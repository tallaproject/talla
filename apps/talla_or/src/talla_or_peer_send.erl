%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Peer Sender.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer_send).
-behaviour(gen_server).

%% API.
-export([start_link/1,
         send/2
        ]).

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
        socket  :: ssl:socket(),
        peer    :: pid(),
        queue   :: queue:queue(),
        limit   :: none | pid()
    }).

-spec start_link(Socket) -> {ok, pid()} | {error, Reason}
    when
        Socket :: ssl:socket(),
        Reason :: term().
start_link(Socket) ->
    gen_server:start_link(?MODULE, [Socket], []).

-spec send(Pid, Packet) -> ok
    when
        Pid    :: pid(),
        Packet :: iolist().
send(Pid, Packet) ->
    gen_server:cast(Pid, {send, Packet}).

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
            queue  = queue:new(),
            limit  = none
        }}.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast({send, Packet}, #state { queue = Queue, limit = Limit } = State) ->
    NewQueue = queue:in(Packet, Queue),
    case Limit of
        none ->
            NewLimit = talla_or_limit:send(1),
            {noreply, State#state { queue = NewQueue, limit = NewLimit }};

        _ ->
            {noreply, State#state { queue = NewQueue }}
    end;

handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info({limit, continue}, #state { peer = Peer, socket = Socket, queue = Queue } = State) ->
    case queue:is_empty(Queue) of
        true ->
            {noreply, State#state { limit = none }};

        false ->
            Packet = queue:head(Queue),
            lager:debug("Sending packet: ~w", [Packet]),

            ssl:send(Socket, Packet),

            Size     = iolist_size(Packet),
            NewQueue = queue:tail(Queue),
            NewLimit = talla_or_limit:send(Size),

            talla_core_bandwidth:bytes_written(Size),

            {noreply, State#state { queue = NewQueue, limit = NewLimit }}
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
