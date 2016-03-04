%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Peer Receiver.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer_recv).
-behaviour(gen_server).

%% API.
-export([start_link/1]).

%% Private API.
-export([lookup/1,
         await/1
        ]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-record(state, {
        socket :: ssl:socket(),
        peer   :: pid(),
        limit  :: pid()
    }).

-spec start_link(Socket) -> {ok, pid()} | {error, Reason}
    when
        Socket :: ssl:socket(),
        Reason :: term().
start_link(Socket) ->
    gen_server:start_link(?MODULE, [Socket], []).

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
init([Socket]) ->
    register(Socket),
    {ok, Peer} = talla_or_peer:await(Socket),
    {ok, #state {
            socket = Socket,
            peer   = Peer,
            limit  = talla_or_limit:recv(1)
        }}.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info({limit, continue}, #state { socket = Socket, peer = Peer } = State) ->
    case recv(Socket) of
        {ok, Packet} ->
            PacketSize = byte_size(Packet),
            NewLimit   = talla_or_limit:recv(PacketSize),

            talla_or_peer:incoming_packet(Peer, Packet),

            {noreply, State#state { limit = NewLimit }};

        {error, _Reason} ->
            {stop, normal, State}
    end;

handle_info(stop, State) ->
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
-spec recv(Socket) -> {ok, Data} | {error, Reason}
    when
        Socket :: ssl:socket(),
        Data   :: iolist(),
        Reason :: term().
recv(Socket) ->
    ssl:recv(Socket, 0).
