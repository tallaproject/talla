%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @private
%%% ----------------------------------------------------------------------------
-module(talla_or_ssl_hack).

%% API.
-export([master_secret/1,
         client_random/1,
         server_random/1
        ]).

-include_lib("ssl/src/ssl_record.hrl").
-include_lib("ssl/src/ssl_connection.hrl").

-spec master_secret(Socket) -> binary()
    when
        Socket :: ssl:sslsocket().
master_secret(Socket) ->
    #security_parameters {
            master_secret = MasterSecret
        } = lookup(Socket),
    MasterSecret.

-spec client_random(Socket) -> binary()
    when
        Socket :: ssl:sslsocket().
client_random(Socket) ->
    #security_parameters {
            client_random = ClientRandom
        } = lookup(Socket),
    ClientRandom.

-spec server_random(Socket) -> binary()
    when
        Socket :: ssl:sslsocket().
server_random(Socket) ->
    #security_parameters {
            server_random = ServerRandom
        } = lookup(Socket),
    ServerRandom.

%% @private
-spec lookup(Socket) -> term()
    when
        Socket :: ssl:sslsocket().
lookup({sslsocket, _, Connection}) ->
    {_, #state {
            connection_states = CS
        }} = sys:get_state(Connection),
    #connection_state {
            security_parameters = Params
        } = ssl_record:current_connection_state(CS, read),
    Params.
