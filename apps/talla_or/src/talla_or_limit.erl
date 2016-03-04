%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Rate Limit API.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_limit).

%% API.
-export([init/0,
         send/1,
         recv/1
        ]).

-define(UPLOAD,   talla_or_upload_limit).
-define(DOWNLOAD, talla_or_download_limit).

-spec init() -> ok.
init() ->
    BandwidthRate = talla_or_config:bandwidth_rate(),
    ok = rlimit:new(?UPLOAD, BandwidthRate, 1000),
    ok = rlimit:new(?DOWNLOAD, BandwidthRate, 1000).

-spec send(Bytes) -> pid()
    when
        Bytes :: non_neg_integer().
send(Bytes) ->
    rlimit:atake(Bytes, {limit, continue}, ?UPLOAD).

-spec recv(Bytes) -> pid()
    when
        Bytes :: non_neg_integer().
recv(Bytes) ->
    rlimit:atake(Bytes, {limit, continue}, ?DOWNLOAD).
