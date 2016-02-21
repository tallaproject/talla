%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Talla Core Descriptor API.
%%% @end
%%% -----------------------------------------------------------
-module(talla_core_descriptor).

%% API.
-export([create/0]).

-spec create() -> iolist().
create() ->
    Nickname = talla_core_config:nickname(),
    Address = inet:ntoa(talla_core_config:onion_address()),
    Port = talla_core_config:onion_port(),
    Contact = talla_core_config:contact(),

    PublicIDKey = talla_core_identity_key:public_key(),
    PublicIDKeyDer = talla_crypto_rsa:der_encode(PublicIDKey),
    PublicIDKeyFingerprint = onion_binary:fingerprint(sha, PublicIDKeyDer),

    PublicOnionKey = talla_core_onion_key:public_key(),

    PublicNTOROnionKey = talla_core_ntor_key:public_key(),

    Timestamp = timestamp(),
    Data = iolist_to_binary([
            io_lib:format("router ~s ~s ~b 0 0~n", [Nickname, Address, Port]),
            io_lib:format("platform ~s~n", [talla_core:platform()]),
            io_lib:format("contact ~s~n", [Contact]),
            io_lib:format("published ~s~n", [Timestamp]),
            io_lib:format("fingerprint ~s~n", [PublicIDKeyFingerprint]),
            io_lib:format("uptime ~b~n", [talla_core:uptime()]),
            io_lib:format("bandwidth 1073741824 1073741824 65536~n", []),

            io_lib:format("onion-key~n", []),
            talla_crypto_rsa:pem_encode(PublicOnionKey),

            io_lib:format("signing-key~n", []),
            talla_crypto_rsa:pem_encode(PublicIDKey),

            io_lib:format("ntor-onion-key ~s~n", [base64:encode(PublicNTOROnionKey)]),

            io_lib:format("reject *:*~n", []),

            io_lib:format("router-signature~n", [])
        ]),
    Signature = talla_core_identity_key:sign(Data),
    iolist_to_binary([Data,
                      <<"-----BEGIN SIGNATURE-----\n">>,
                      base64encode_and_split(Signature),
                      <<"\n-----END SIGNATURE-----\n">>
                     ]).

%% @private
-spec timestamp() -> string().
timestamp() ->
    {{Year, Month, Day}, {Hour, Minute, Second}} = calendar:now_to_datetime(os:timestamp()),
    io_lib:format("~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b", [Year, Month, Day, Hour, Minute, Second]).

base64encode_and_split(Bin) ->
    split_lines(base64:encode(Bin)).

split_lines(<<Text:64/binary>>) ->
    [Text];
split_lines(<<Text:64/binary, Rest/binary>>) ->
    [Text, $\n | split_lines(Rest)];
split_lines(Bin) ->
    [Bin].
