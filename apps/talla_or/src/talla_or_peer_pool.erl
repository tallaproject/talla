%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Peer Pool Supervisor.
%%% @end
%%% -----------------------------------------------------------
-module(talla_or_peer_pool).
-behaviour(supervisor).

%% API.
-export([start_link/0,
         start_peer/0
        ]).

%% Ranch Callbacks.
-export([start_link/4]).

%% Supervisor callbacks.
-export([init/1]).

%% From supervisor.
-type start_link_err() :: {already_started, pid()} | shutdown | term().
-type start_link_ret() :: {ok, pid()} | ignore | {error, start_link_err()}.

-define(CHILD(I, Type), {I, {I, start_link, []}, temporary, 5000, Type, [I]}).
-define(SERVER, ?MODULE).

-spec start_link() -> start_link_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec start_peer() -> {ok, Pid} | {error, Reason}
    when
        Pid    :: pid(),
        Reason :: term().
start_peer() ->
    supervisor:start_child(?SERVER, []).

-spec start_link(ListenerPid :: pid(), Socket :: ssl:socket(), Transport :: term(), Options :: [term()]) -> {ok, pid()} | {error, term()}.
start_link(ListenerPid, Socket, Transport, Options) ->
    supervisor:start_child(?SERVER, [ListenerPid, Socket, Transport, Options]).

%% @private
-spec init([]) -> {ok, {{simple_one_for_one, non_neg_integer(), non_neg_integer()}, []}}.
init([]) ->
    {ok, {{simple_one_for_one, 10, 10}, [
            ?CHILD(talla_or_peer, worker)
        ]}}.
