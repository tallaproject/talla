%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc The Talla Core Supervisor.
%%% @end
%%% -----------------------------------------------------------
-module(talla_core_sup).
-behaviour(supervisor).

%% API.
-export([start_link/0]).

%% Supervisor callbacks.
-export([init/1]).

%% From supervisor.
-type start_link_err() :: {already_started, pid()} | shutdown | term().
-type start_link_ret() :: {ok, pid()} | ignore | {error, start_link_err()}.

-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 10000, Type, [I]}).

-spec start_link() -> start_link_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @private
init([]) ->
    {ok, {{one_for_one, 10, 10}, [
            ?CHILD(talla_core_uptime_manager, worker),
            ?CHILD(talla_core_bandwidth, worker),
            ?CHILD(talla_core_identity_key, worker),
            ?CHILD(talla_core_onion_key, worker),
            ?CHILD(talla_core_ntor_key, worker),
            ?CHILD(talla_core_ed25519_master_key, worker),
            ?CHILD(talla_core_ed25519_signing_key, worker),
            ?CHILD(talla_core_geoip, worker)
        ]}}.
