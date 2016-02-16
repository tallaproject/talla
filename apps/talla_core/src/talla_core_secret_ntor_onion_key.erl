%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Secret NTOR Onion Key server
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core_secret_ntor_onion_key).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         public_key/0
        ]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-record(state, {
        secret_key :: binary(),
        public_key :: binary()
    }).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec public_key() -> binary().
public_key() ->
    gen_server:call(?SERVER, public_key).

%% @private
init(_Args) ->
    Filename = filename:join([talla_core_config:data_dir(), "keys", "secret_onion_key_ntor"]),
    Mode = 8#00600,
    case file:read_file(Filename) of
        {ok, <<"== c25519v1: onion ==", SecretKey:32/bytes, PublicKey:32/bytes>>} ->
            lager:notice("Loading ~s", [Filename]),
            {ok, #state { secret_key = SecretKey, public_key = PublicKey }};

        {ok, _} ->
            lager:error("Invalid ntor onion key found in ~s", [Filename]),
            {error, invalid_ntor_key};

        {error, enoent} ->
            lager:notice("Creating ~s", [Filename]),
            #{ secret := SecretKey, public := PublicKey } = enacl_ext:curve25519_keypair(),
            ok = onion_file:touch(Filename, Mode),
            ok = file:write_file(Filename, <<"== c25519v1: onion ==", SecretKey/bytes, PublicKey/bytes>>),
            {ok, #state { secret_key = SecretKey, public_key = PublicKey }};

        {error, Reason} ->
            lager:error("Error: Unable to load ~s: ~p", [Filename, Reason]),
            {error, Reason}
    end.

%% @private
handle_call(public_key, _From, #state { public_key = PublicKey } = State) ->
    {reply, PublicKey, State};

handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info(Info, State) ->
    lager:warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.
