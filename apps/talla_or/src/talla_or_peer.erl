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
         dispatch/3,
         set_protocol/2,
         close/1
        ]).

%% Ranch API.
-export([start_link/4, init/4]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-include_lib("public_key/include/public_key.hrl").

-record(state, {
        socket       :: ssl:socket() | undefined,
        continuation :: binary(),
        protocol     :: onion_cell:version(),
        fsm          :: pid()
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
    gen_server:cast(Peer, {connect, Address, Port}).

-spec dispatch(Peer, Protocol, Cell) -> ok
    when
        Peer     :: pid(),
        Protocol :: onion_protocol:version(),
        Cell     :: onion_cell:cell().
dispatch(Peer, Protocol, Cell) ->
    gen_server:cast(Peer, {dispatch, Protocol, Cell}).

-spec set_protocol(Peer, Protocol) -> ok
    when
        Peer     :: pid(),
        Protocol :: onion_cell:version().
set_protocol(Peer, Protocol) ->
    gen_server:cast(Peer, {set_protocol, Protocol}).

-spec close(Peer) -> ok
    when
        Peer :: pid().
close(Peer) ->
    gen_server:cast(Peer, close).

%% @private
start_link(Ref, Socket, Transport, Options) ->
    proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Options]).

%% @private
init(Ref, Socket, _Transport, _Options) ->
    ok = proc_lib:init_ack({ok, self()}),
    ok = ranch:accept_ack(Ref),
    ok = ack_socket(Socket),

    {ok, FSM} = talla_or_peer_fsm:start_link(),
    {ok, {Address, Port}} = ssl:peername(Socket),

    talla_or_peer_fsm:incoming_connection(FSM, Address, Port),

    gen_server:enter_loop(?MODULE, [], #state {
                                          socket       = Socket,
                                          continuation = <<>>,
                                          protocol     = 3,
                                          fsm          = FSM
                                        }).

%% @private
init([]) ->
    {ok, FSM} = talla_or_peer_fsm:start_link(),
    {ok, #state {
            socket       = undefined,
            continuation = <<>>,
            protocol     = 3,
            fsm          = FSM
           }}.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast({connect, Address, Port}, #state { fsm = FSM, socket = undefined } = State) ->
    case ssl:connect(Address, Port, [binary, {packet, 0}, {active, once}]) of
        {ok, Socket} ->
            {ok, TLSCertificate} = ssl:peercert(Socket),
            {ok, TLSInfo} = ssl:connection_information(Socket),

            talla_or_peer_fsm:outgoing_connection(FSM, Address, Port, TLSCertificate, TLSInfo),

            {noreply, State#state { socket = Socket }};

        {error, _} = Error ->
            lager:warning("Unable to connect to ~s:~b", [inet:ntoa(Address), Port]),
            {stop, Error, State}
    end;

handle_cast({dispatch, Protocol, Cell}, #state { socket = Socket } = State) ->
    case onion_cell:encode(Protocol, Cell) of
        {ok, CellData} ->
            send(Socket, CellData);

        {error, _} ->
            lager:warning("Trying to send bad cell: ~w", [Cell])
    end,
    {noreply, State};

handle_cast({set_protocol, Protocol}, State) ->
    lager:info("Setting peer protocol: ~p", [Protocol]),
    {noreply, State#state { protocol = Protocol }};

handle_cast(close, State) ->
    {stop, normal, State};

handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info({ssl, Socket, Packet}, #state { socket = Socket, protocol = Protocol, fsm = FSM, continuation = Continuation } = State) ->
    ok = ack_socket(Socket),
    Data = <<Continuation/binary, Packet/binary>>,
    case process_stream_chunk(FSM, Protocol, Data) of
        {ok, NewContinuation} ->
            {noreply, State#state { continuation = NewContinuation }};

        {error, _} = Error ->
            {stop, Error, State}
    end;

handle_info({ssl_error, _Socket, Reason}, #state { fsm = FSM } = State) ->
    talla_or_peer_fsm:disconnected(FSM, Reason),
    {stop, normal, State};

handle_info({ssl_closed, _Socket}, #state { fsm = FSM } = State) ->
    talla_or_peer_fsm:disconnected(FSM, closed),
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
-spec ack_socket(Socket :: ssl:socket()) -> ok.
ack_socket(Socket) ->
    ssl:setopts(Socket, [{active, once}]).

%% @private
-spec send(Socket, Data) -> ok | {error, Reason}
    when
        Socket :: ssl:socket(),
        Data   :: iolist(),
        Reason :: term().
send(Socket, Data) ->
    ssl:send(Socket, Data).

%% @private
process_stream_chunk(PeerFSM, Protocol, Data) ->
    case onion_cell:decode(Protocol, Data) of
        {ok, Cell, NewData} ->
            talla_or_peer_fsm:incoming_cell(PeerFSM, Cell),
            process_stream_chunk(PeerFSM, Protocol, NewData);

        {error, insufficient_data} ->
            {ok, Data};

        {error, _} = Error ->
            Error
    end.
