%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc The Talla Core API.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core).

%% API.
-export([name/0,
         version/0,
         platform/0,
         uptime/0
        ]).

-spec name() -> string().
name() ->
    "Talla".

-spec version() -> string().
version() ->
    case application:get_key(talla_core, vsn) of
        {ok, Version} ->
            Version;
        undefined ->
            {ok, Version} = application:get_env(talla_core, vsn),
            Version
    end.

-spec platform() -> string().
platform() ->
    ErlangVersion = erlang:system_info(otp_release),
    ErtsVersion   = erlang:system_info(version),
    lists:flatten(io_lib:format("~s ~s on ~s (Erlang/OTP ~s, Erts ~s)", [name(), version(), onion_os:name(), ErlangVersion, ErtsVersion])).

-spec uptime() -> non_neg_integer().
uptime() ->
    talla_core_uptime_manager:uptime().
