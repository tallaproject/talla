%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc The Talla Onion Router Application.
%%% @end
%%% -----------------------------------------------------------
-module(talla_or_app).
-behaviour(application).

%% API.
-export([start/2, stop/1]).

%% Internal API.
-export([start_relay/0]).

-spec start(normal | {takeover, node()} | {failover, node()}, term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    case talla_or_sup:start_link() of
        {ok, _} = Result ->
            ok = maybe_start_relay(),
            ok = talla_or_limit:init(),
            Result;

        {error, _} = Error ->
            Error
    end.

-spec stop([]) -> ok.
stop(_State) ->
    ok.

%% @private
-spec maybe_start_relay() -> ok | {error, Reason}
    when
        Reason :: term().
maybe_start_relay() ->
    case talla_or_config:enabled() of
        true ->
            start_relay();

        false ->
            ok
    end.

%% @private
-spec start_relay() -> ok | {error, Reason}
    when
        Reason :: term().
start_relay() ->
    Port = talla_or_config:port(),
    lager:notice("Starting onion router on port ~b", [Port]),

    {#{ secret := SecretKey }, Certificate} = talla_or_tls_manager:link_certificate(),
    {ok, SecretKeyDER} = onion_rsa:der_encode(SecretKey),

    Options = [
            {port, Port},
            {max_connections, talla_or_config:max_connections()},

            {versions, ['tlsv1.2', 'tlsv1.1', 'tlsv1']},

            {honor_cipher_order, true},
            {reuse_sessions, false},

            {cert, Certificate},
            {key, {'RSAPrivateKey', SecretKeyDER}}
        ],
    case ranch:start_listener(talla_or, 100, talla_or_tls, Options, talla_or_peer_pool, []) of
        {ok, _} ->
            ok;

        {error, Reason} = Error ->
            lager:error("Unable to start onion router: ~p", [Reason]),
            Error
    end.
