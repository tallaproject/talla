%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Talla Directory Config API.
%%% @end
%%% -----------------------------------------------------------
-module(talla_dir_config).

%% API.
-export([enabled/0,
         port/0]).

%% @doc Enable directory cache.
-spec enabled() -> boolean().
enabled() ->
    onion_config:get_boolean(talla_dir, enabled, false).

%% @doc Get the Directory HTTP Port.
-spec port() -> inet:port_number().
port() ->
    case enabled() of
        true ->
            onion_config:get_integer(talla_dir, port, 9080);

        false ->
            0
    end.
