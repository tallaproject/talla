%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc HTTP Utilities.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_dir_http).

%% API.
-export([authorities_url_path/0]).

-spec authorities_url_path() -> string().
authorities_url_path() ->
    Authorities = talla_core_config:authorities(),
    IDs = lists:sort(lists:map(fun (V3Identity) ->
                                   string:substr(V3Identity, 1, 6)
                               end, [V3Identity || #{ v3_identity := V3Identity } <- Authorities])),
    lists:flatten(onion_lists:intersperse($+, IDs)).
