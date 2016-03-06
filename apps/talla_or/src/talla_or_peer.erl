%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Onion Router Peer.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         connect/3,
         connect/4,
         close/1,
         incoming_packet/2,
         outgoing_cell/3
        ]).

%% Private API.
-export([lookup/1,
         await/1
        ]).

%% Ranch API.
-export([start_link/4,
         init/4
        ]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-include_lib("public_key/include/public_key.hrl").

-define(DEFAULT_TIMEOUT, 10*1000).

-record(state, {
        socket       = undefined :: ssl:socket() | undefined,
        continuation = <<>>      :: binary(),

        fsm      :: pid(),  %% talla_or_peer_fsm.
        sender   :: pid(),  %% talla_or_peer_send.
        receiver :: pid(),  %% talla_or_peer_recv.

        children :: ordsets:ordset(pid())
    }).

-spec start_link() -> {ok, Peer} | {error, Reason}
    when
        Peer   :: pid(),
        Reason :: term().
start_link() ->
    gen_server:start_link(?MODULE, [], []).

-spec connect(Peer, Address, Port) -> ok
    when
        Peer    :: pid(),
        Address :: inet:ip_address(),
        Port    :: inet:port_number().
connect(Peer, Address, Port) ->
    connect(Peer, Address, Port, ?DEFAULT_TIMEOUT).

-spec connect(Peer, Address, Port, Timeout) -> ok
    when
        Peer    :: pid(),
        Address :: inet:ip_address(),
        Port    :: inet:port_number(),
        Timeout :: timeout().
connect(Peer, Address, Port, Timeout) ->
    gen_server:cast(Peer, {connect, Address, Port, Timeout}).

-spec close(Peer) -> ok
    when
        Peer :: pid().
close(Peer) ->
    gen_server:cast(Peer, close).

-spec incoming_packet(Peer, Packet) -> ok
    when
        Peer   :: pid(),
        Packet :: binary().
incoming_packet(Peer, Packet) ->
    gen_server:cast(Peer, {incoming_packet, Packet}).

-spec outgoing_cell(Peer, Version, Cell) -> ok
    when
        Peer    :: pid(),
        Version :: onion_protocol:version(),
        Cell    :: onion_cell:cell().
outgoing_cell(Peer, Version, Cell) ->
    gen_server:cast(Peer, {outgoing_cell, Version, Cell}).

%% @private
-spec lookup(Socket) -> {ok, Pid} | {error, Reason}
    when
        Socket :: ssl:socket(),
        Pid    :: pid(),
        Reason :: term().
lookup(Socket) ->
    onion_registry:lookup(name(Socket)).

%% @private
-spec await(Socket) -> {ok, Pid} | {error, Reason}
    when
        Socket :: ssl:socket(),
        Pid    :: pid(),
        Reason :: term().
await(Socket) ->
    onion_registry:await(name(Socket)).

%% @private
start_link(Ref, Socket, Transport, Options) ->
    proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Options]).

%% @private
init(Ref, Socket, _Transport, _Options) ->
    ok = proc_lib:init_ack({ok, self()}),
    ok = ranch:accept_ack(Ref),

    register(Socket),

    {ok, FSM}      = talla_or_peer_fsm:start_link(),
    {ok, Sender}   = talla_or_peer_send:start_link(Socket),
    {ok, Receiver} = talla_or_peer_recv:start_link(Socket),

    monitor(process, FSM),
    monitor(process, Sender),
    monitor(process, Receiver),

    {ok, {Address, Port}} = ssl:peername(Socket),

    talla_or_peer_fsm:incoming_connection(FSM, Address, Port),

    gen_server:enter_loop(?MODULE, [], #state {
                                          socket       = Socket,
                                          fsm          = FSM,
                                          sender       = Sender,
                                          receiver     = Receiver,
                                          children     = ordsets:from_list([FSM, Sender, Receiver])
                                        }).

%% @private
init([]) ->
    {ok, #state {}}.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast({connect, Address, Port, Timeout}, #state { socket = undefined, fsm = FSM, children = Children } = State) ->
    talla_or_peer_fsm:connect(FSM, Address, Port),
    case ssl:connect(Address, Port, [{mode, binary}, {packet, 0}, {active, false}], Timeout) of
        {ok, Socket} ->
            register(Socket),

            {ok, FSM}      = talla_or_peer_fsm:start_link(),
            {ok, Sender}   = talla_or_peer_send:start_link(Socket),
            {ok, Receiver} = talla_or_peer_recv:start_link(Socket),

            monitor(process, FSM),
            monitor(process, Sender),
            monitor(process, Receiver),

            talla_or_peer_fsm:outgoing_connection(FSM, Address, Port),

            {noreply, State#state {
                        socket   = Socket,
                        fsm      = FSM,
                        sender   = Sender,
                        receiver = Receiver,
                        children = ordsets:from_list([FSM, Sender, Receiver])
                       }};

        {error, _} = Error ->
            lager:warning("Unable to connect to ~s:~b", [inet:ntoa(Address), Port]),
            {stop, Error, State}
    end;

handle_cast({outgoing_cell, Version, #{ circuit := CircuitID, command := Command } = Cell}, #state { sender = Sender } = State) ->
    log(State, notice, "(v~b) <- ~p (Circuit: ~b)", [Version, Command, CircuitID]),
    talla_or_peer_send:outgoing_cell(Sender, Version, Cell),
    {noreply, State};

handle_cast(close, State) ->
    {stop, normal, State};

handle_cast({incoming_packet, Packet}, State) ->
    case process_stream_chunk(State, Packet) of
        {ok, NewState} ->
            {noreply, NewState};

        {error, _} = Error ->
            {stop, Error, State}
    end;

handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info({'DOWN', _Ref, process, Pid, normal}, #state { children = Children } = State) ->
    true = ordsets:is_element(Pid, Children),

    [Child ! stop || Child <- Children],

    {stop, normal, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

%% @private
process_stream_chunk(#state { continuation = Continuation, fsm = FSM } = State, Packet) ->
    Data = <<Continuation/binary, Packet/binary>>,
    Version = talla_or_peer_fsm:protocol_version(FSM),
    case onion_cell:decode(Version, Data) of
        {ok, Cell, NewData} ->
            log_incoming_cell(State, Version, Cell),
            talla_or_peer_fsm:incoming_cell(FSM, Cell),
            process_stream_chunk(State, NewData);

        {error, insufficient_data} ->
            {ok, State#state { continuation = Data }};

        {error, _} = Error ->
            Error
    end.

%% @private
-spec name(Socket) -> term()
    when
        Socket :: ssl:socket().
name(Socket) ->
    {?MODULE, Socket}.

%% @private
-spec register(Socket) -> term()
    when
        Socket :: ssl:socket().
register(Socket) ->
    onion_registry:register(name(Socket)).

%% @private
log_incoming_cell(State, Version, #{ circuit := CircuitID, command := Command }) ->
    log(State, notice, "(v~b) -> ~p (Circuit: ~b)", [Version, Command, CircuitID]).

%% @private
log(State, Method, Message) ->
    log(State, Method, Message, []).

%% @private
log(#state { socket = Socket }, Method, Message, Arguments) ->
    {ok, {Address, Port}} = ssl:peername(Socket),
    lager:log(Method, [], "~s:~b " ++ Message, [inet:ntoa(Address), Port] ++ Arguments).
