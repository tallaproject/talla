%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc The Talla Directory Application.
%%% @end
%%% -----------------------------------------------------------
-module(talla_dir_app).
-behaviour(application).

%% API.
-export([start/2, stop/1, start_dir_cache/0]).

-spec start(normal | {takeover, node()} | {failover, node()}, term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    case talla_dir_sup:start_link() of
        {ok, _} = Result ->
            ok = maybe_start_dir_cache(),
            Result;

        {error, _} = Error ->
            Error
    end.

-spec stop([]) -> ok.
stop(_State) ->
    ok.

%% @private
-spec maybe_start_dir_cache() -> ok | {error, Reason}
    when
        Reason :: term().
maybe_start_dir_cache() ->
    case talla_dir_config:enabled() of
        true ->
            start_dir_cache();

        false ->
            ok
    end.

%% @private
-spec start_dir_cache() -> ok | {error, Reason}
    when
        Reason :: term().
start_dir_cache() ->
    Port = talla_dir_config:port(),
    lager:notice("Starting directory cache on port ~b", [Port]),

    Dispatch = cowboy_router:compile([
            {'_', []}
        ]),
    case cowboy:start_http(talla_dir, 100, [{port, Port}], [
                {env, [{dispatch, Dispatch}]},
                {onrequest, fun talla_dir_cowboy:on_request/1},
                {onresponse, fun talla_dir_cowboy:on_response/4}
            ]) of
        {ok, _} ->
            ok;

        {error, Reason} = Error ->
            lager:error("Unable to start directory cache: ~p", [Reason]),
            Error
    end.
