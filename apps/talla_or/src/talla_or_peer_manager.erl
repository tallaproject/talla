%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Peer Manager.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer_manager).
-behaviour(gen_server).

%% API.
-export([start_link/0]).

%% Private API (used by talla_or_peer_fsm).
-export([connecting/0,
         connected/0,
         authenticated/0,
         unauthenticated/0
        ]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).
-define(TABLE, ?MODULE).

-record(state, {
        table = ets:tid()
    }).

-spec start_link() -> {ok, Pid} | {error, Reason}
    when
        Pid    :: pid(),
        Reason :: term().
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec connecting() -> ok.
connecting() ->
    gen_server:cast(?SERVER, {connecting, self()}).

-spec connected() -> ok.
connected() ->
    gen_server:cast(?SERVER, {connected, self()}).

-spec authenticated() -> ok.
authenticated() ->
    gen_server:cast(?SERVER, {authenticated, self()}).

-spec unauthenticated() -> ok.
unauthenticated() ->
    gen_server:cast(?SERVER, {unauthenticated, self()}).

%% @private
init([]) ->
    {ok, #state {
            table = ets:new(?TABLE, [set, named_table, protected, {read_concurrency, true}])
           }}.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast({connecting, Peer}, State) ->
    lager:info("Registering connecting peer: ~p", [Peer]),
    monitor(process, Peer),
    true = ets:insert_new(?TABLE, {Peer, connecting}),
    {noreply, State};

handle_cast({connected, Peer}, State) ->
    ets:insert(?TABLE, {Peer, connected}),
    {noreply, State};

handle_cast({authenticated, Peer}, State) ->
    ets:insert(?TABLE, {Peer, authenticated}),
    {noreply, State};

handle_cast({unauthenticated, Peer}, State) ->
    ets:insert(?TABLE, {Peer, unauthenticated}),
    {noreply, State};

handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info({'DOWN', _Ref, process, Pid, normal}, State) ->
    ets:delete(?TABLE, Pid),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.
