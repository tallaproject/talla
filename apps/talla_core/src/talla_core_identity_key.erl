%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Secret ID Key server
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core_identity_key).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         public_key/0,

         fingerprint/0,
         fingerprint/1,

         sign/1,
         sign_certificate/1,
         sign_document/1
        ]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-include_lib("public_key/include/public_key.hrl").

-define(SERVER, ?MODULE).

-record(state, {
        key :: onion_rsa:keypair()
    }).

-spec public_key() -> onion_rsa:public_key().
public_key() ->
    gen_server:call(?SERVER, public_key).

-spec fingerprint() -> binary().
fingerprint() ->
    fingerprint(sha).

-spec fingerprint(Hash) -> binary()
    when
        Hash :: atom().
fingerprint(Hash) ->
    {ok, PublicKey} = onion_rsa:der_encode(public_key()),
    crypto:hash(Hash, PublicKey).

-spec sign(Data :: binary()) -> binary().
sign(Data) when is_binary(Data) ->
    gen_server:call(?SERVER, {sign, Data}).

-spec sign_certificate(Certificate) -> CertificateDer
    when
        Certificate    :: #'OTPTBSCertificate'{},
        CertificateDer :: public_key:der_encoded().
sign_certificate(Certificate) ->
    gen_server:call(?SERVER, {sign_certificate, Certificate}).

-spec sign_document(Document) -> SignedDocument
    when
        Document       :: iolist(),
        SignedDocument :: iolist().
sign_document(Document) ->
    gen_server:call(?SERVER, {sign_document, Document}).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @private
init(_Args) ->
    Filename = filename:join([talla_core_config:data_dir(), "keys", "secret_id_key"]),
    Mode = 8#00600,
    case file:read_file(Filename) of
        {ok, FileContent} ->
            lager:notice("Loading ~s", [Filename]),
            {ok, SecretKey} = onion_rsa:pem_decode(FileContent),
            {ok, #state { key = #{ secret => SecretKey,
                                   public => onion_rsa:secret_key_to_public_key(SecretKey) }}};

        {error, enoent} ->
            lager:notice("Creating ~s", [Filename]),
            {ok, #{ secret := SecretKey } = Key} = onion_rsa:keypair(1024),
            {ok, SecretKeyPem} = onion_rsa:pem_encode(SecretKey),
            ok = filelib:ensure_dir(Filename),
            ok = onion_file:touch(Filename, Mode),
            ok = file:write_file(Filename, SecretKeyPem),
            {ok, #state { key = Key }};

        {error, Reason} ->
            lager:error("Error: Unable to load ~s: ~p", [Filename, Reason]),
            {error, Reason}
    end.

%% @private
handle_call(public_key, _From, #state { key = #{ public := PublicKey } } = State) ->
    {reply, PublicKey, State};

handle_call({sign, Data}, _From, #state { key = #{ secret := SecretKey } } = State) ->
    {reply, onion_rsa:private_encrypt(crypto:hash(sha, Data), SecretKey), State};

handle_call({sign_document, Document}, _From, #state { key = #{ secret := SecretKey } } = State) ->
    Signature = onion_rsa:private_encrypt(crypto:hash(sha, Document), SecretKey),
    {reply, [Document, onion_pem:encode("SIGNATURE", Signature)], State};

handle_call({sign_certificate, Certificate}, _From, #state { key = #{ secret := SecretKey } } = State) ->
    {reply, onion_x509:sign(Certificate, SecretKey), State};

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
