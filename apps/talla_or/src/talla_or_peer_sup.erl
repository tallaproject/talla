%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Peer Supervisor.
%%% @end
%%% -----------------------------------------------------------
-module(talla_or_peer_sup).
-behaviour(supervisor).

%% API.
-export([start_link/0]).

%% Supervisor callbacks.
-export([init/1]).

%% From supervisor.
-type start_link_err() :: {already_started, pid()} | shutdown | term().
-type start_link_ret() :: {ok, pid()} | ignore | {error, start_link_err()}.

-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

-spec start_link() -> start_link_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @private
init([]) ->
    {ok, {{one_for_all, 10, 10}, [
            ?CHILD(talla_or_peer_manager, worker),
            ?CHILD(talla_or_peer_pool, supervisor),

            %% FIXME(ahf): Should this be moved into a talla_or_circuit_sup?
            ?CHILD(talla_or_circuit_pool, supervisor)
        ]}}.
