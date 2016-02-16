%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Cowboy Middleware.
%%% @end
%%% -----------------------------------------------------------
-module(talla_dir_cowboy).

%% API.
-export([on_request/1,
         on_response/4]).

on_request(Request) ->
    {Method, _} = cowboy_req:method(Request),
    {Path, _} = cowboy_req:path(Request),
    {Version, _} = cowboy_req:version(Request),
    lager:info("~s ~s ~s", [Method, Path, Version]),
    Request.

on_response(Status, _Headers, Body, Req) ->
    {{IP, _Port}, Req} = cowboy_req:peer(Req),
    Headers = [{<<"server">>, talla_core:platform()},
               {<<"content-length">>, integer_to_binary(byte_size(Body))},
               {<<"X-Your-Address-Is">>, inet:ntoa(IP)}],
    {ok, Req2} = cowboy_req:reply(Status, Headers, Body, Req),
    Req2.
