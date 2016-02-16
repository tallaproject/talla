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
    {ok, Version} = application:get_key(talla_core, vsn),
    Version.

-spec platform() -> string().
platform() ->
    ErlangVersion = erlang:system_info(otp_release),
    lists:flatten(io_lib:format("~s ~s on ~s (OTP ~s)", [name(), version(), onion_os:name(), ErlangVersion])).

-spec uptime() -> non_neg_integer().
uptime() ->
    talla_core_uptime_manager:uptime().
