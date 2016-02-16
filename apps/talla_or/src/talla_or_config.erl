%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Talla Onion Router Config API.
%%% @end
%%% -----------------------------------------------------------
-module(talla_or_config).

%% API.
-export([enabled/0,
         nickname/0,
         contact/0,
         address/0,
         port/0,
         exit_policy/0,
         max_connections/0
        ]).

%% @doc Enable the relay or not.
-spec enabled() -> boolean().
enabled() ->
    onion_config:get_boolean(talla_or, enabled, false).

%% @doc Get relay nickname.
-spec nickname() -> string().
nickname() ->
    onion_config:get_string(talla_or, nickname, "").

%% @doc Get contact information.
-spec contact() -> string().
contact() ->
    onion_config:get_string(talla_or, contact, "").

%% @doc Get address.
-spec address() -> inet:ip_address().
address() ->
    case onion_config:get_string(talla_or, address) of
        not_found ->
            not_found;

        Address ->
            case inet:parse_address(Address) of
                {ok, IP} ->
                    IP;

                {error, Reason} ->
                    error({invalid_address, Reason})
            end
    end.

%% @doc Get port.
-spec port() -> inet:port_number().
port() ->
    case enabled() of
        true ->
            onion_config:get_integer(talla_or, port, 9000);

        false ->
            0
    end.

%% @doc Get the exit policy.
-spec exit_policy() -> onion_descriptor:exit_policy().
exit_policy() ->
    onion_config:get_value(talla_or, exit_policy, [{reject, "*:*"}]).

%% @doc Get the maximum number of incoming connections.
-spec max_connections() -> non_neg_integer().
max_connections() ->
    onion_config:get_integer(talla_or, max_connections, 1024).
