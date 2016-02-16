%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc The Talla Core Application.
%%% @end
%%% -----------------------------------------------------------
-module(talla_core_app).
-behaviour(application).

%% API.
-export([start/2, stop/1]).

-spec start(normal | {takeover, node()} | {failover, node()}, term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    print_info(),
    talla_core_sup:start_link().

-spec stop([]) -> ok.
stop(_State) ->
    ok.

-spec print_info() -> ok.
print_info() ->
    ErlangVersion = erlang:system_info(otp_release),
    [{_, _, CryptoVersion}] = crypto:info_lib(),
    lager:notice(" ______   ____  _      _       ____ "),
    lager:notice("|      | /    || |    | |     /    |"),
    lager:notice("|      ||  o  || |    | |    |  o  |"),
    lager:notice("|_|  |_||     || |___ | |___ |     |    version ~s", [talla_core:version()]),
    lager:notice("  |  |  |  _  ||     ||     ||  _  |    running on ~s (OTP: ~s, ~s)", [onion_os:name(), ErlangVersion, CryptoVersion]),
    lager:notice("  |  |  |  |  ||     ||     ||  |  |"),
    lager:notice("  |__|  |__|__||_____||_____||__|__|"),
    lager:notice(" ").
