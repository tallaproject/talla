%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Ed25519 Signing Key server
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core_ed25519_signing_key).
-behaviour(gen_server).

-export([start_link/0,

         public_key/0,

         sign/1,
         verify/2
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
          secret_key :: onion_ed25519:secret_key(),
          public_key :: onion_ed25519:public_key()
         }).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec public_key() -> onion_ed25519:public_key().
public_key() ->
    gen_server:call(?SERVER, public_key).

-spec sign(Message) -> Signature
    when
        Message   :: binary(),
        Signature :: binary().
sign(Message) ->
    onion_ed25519:sign(Message, secret_key()).

-spec verify(Signature, Message) -> boolean()
    when
        Signature :: binary(),
        Message   :: binary().
verify(Signature, Message) ->
    onion_ed25519:open(Signature, Message, public_key()).

%% @private
init(_Args) ->
    Filename = filename:join([talla_core_config:data_dir(), "keys", "ed25519_signing_key"]),
    case file:read_file(Filename) of
        {ok, <<SecretKey:64/binary, PublicKey:32/binary>>} ->
            lager:notice("Loaded ~s", [Filename]),
            {ok, #state { secret_key = SecretKey,
                          public_key = PublicKey }};

        {error, enoent} ->
            lager:notice("Creating ~s", [Filename]),

            #{ secret := SecretKey,
               public := PublicKey } = onion_ed25519:keypair(),

            ok = filelib:ensure_dir(Filename),
            ok = onion_file:touch(Filename, 8#00600),

            ok = file:write_file(Filename, <<SecretKey:64/binary, PublicKey:32/binary>>),

            {ok, #state { secret_key = SecretKey,
                          public_key = PublicKey }};

        {error, Reason} = Error ->
            lager:error("Error: Unable to load ~s: ~p", [Filename, Reason]),
            Error
    end.

%% @private
handle_call(public_key, _From, #state { public_key = PublicKey } = State) ->
    {reply, PublicKey, State};

handle_call(secret_key, _From, #state { secret_key = SecretKey } = State) ->
    {reply, SecretKey, State};

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

%% @private
secret_key() ->
    gen_server:call(?SERVER, secret_key).
