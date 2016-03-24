%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc TLS Manager.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_tls_manager).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         link_certificate/0,
         id_certificate/0,
         auth_certificate/0
        ]).

%% Generic Server Behaviour.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-define(ID_CERTIFICATE_LIFETIME,   (365 * 24 * 60 * 60)).

%% Types.
-record(state, {
        certificates :: map()
    }).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec link_certificate() -> {KeyPair, Certificate}
    when
        KeyPair     :: onion_rsa:keypair(),
        Certificate :: public_key:der_encoded().
link_certificate() ->
    gen_server:call(?SERVER, {get_certificate, link_certificate}).

-spec id_certificate() -> {KeyPair, Certificate}
    when
        KeyPair     :: onion_rsa:keypair(),
        Certificate :: public_key:der_encoded().
id_certificate() ->
    gen_server:call(?SERVER, {get_certificate, id_certificate}).

-spec auth_certificate() -> {KeyPair, Certificate}
    when
        KeyPair     :: onion_rsa:keypair(),
        Certificate :: public_key:der_encoded().
auth_certificate() ->
    gen_server:call(?SERVER, {get_certificate, auth_certificate}).

%% @private
init([]) ->
    Certificates = new_certificates(),
    log_certificates(Certificates),
    {ok, #state { certificates = Certificates }}.

%% @private
handle_call({get_certificate, Certificate}, _From, #state { certificates = Certificates } = State) ->
    {reply, maps:get(Certificate, Certificates, not_found), State};

handle_call(Request, From, State) ->
    lager:warning("Unhandled call '~p' from ~p (State: ~p)", [Request, From, State]),
    {reply, ok, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast '~p' (State: ~p)", [Message, State]),
    {noreply, State}.

%% @private
handle_info(Info, State) ->
    lager:warning("Unhandled info '~p' (State: ~p)", [Info, State]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

%% @private
-spec certificate_lifetime() -> non_neg_integer().
certificate_lifetime() ->
    FiveDays = 5 * 24 * 60 * 60,
    OneYear  = 365 * 24 * 60 * 60,
    Lifetime = onion_random:time_range(FiveDays, OneYear),

    %% See Tor ticket: #8443.
    case onion_random:coin_toss() of
        head ->
            Lifetime rem (24 * 60 * 60);

        tail ->
            (Lifetime rem (24 * 60 * 60)) - 1
    end.

%% @private
new_certificates() ->
    Lifetime = certificate_lifetime(),

    Nickname1 = onion_random:hostname(8, 20, "www.", ".net"),
    Nickname2 = onion_random:hostname(8, 20, "www.", ".com"),

    IDPublicKey = talla_core_identity_key:public_key(),

    {ok, #{ public := LinkPublicKey } = LinkKeyPair } = onion_rsa:keypair(1024),
    {ok, #{ public := AuthPublicKey } = AuthKeyPair } = onion_rsa:keypair(1024),

    {ok, LinkCertificate} = new_certificate(LinkPublicKey, Nickname1, Nickname2, Lifetime),
    {ok, IDCertificate}   = new_certificate(IDPublicKey, Nickname2, Nickname2, ?ID_CERTIFICATE_LIFETIME),
    {ok, AuthCertificate} = new_certificate(AuthPublicKey, Nickname1, Nickname2, Lifetime),

    #{ link_certificate => {LinkKeyPair, talla_core_identity_key:sign_certificate(LinkCertificate)},
       id_certificate   => {#{ public => IDPublicKey }, talla_core_identity_key:sign_certificate(IDCertificate)},
       auth_certificate => {AuthKeyPair, talla_core_identity_key:sign_certificate(AuthCertificate)} }.

%% @private
-spec new_certificate(PublicKey, Nickname1, Nickname2, Lifetime) -> {ok, Certificate} | {error, Reason}
    when
        PublicKey   :: onion_rsa:public_key(),
        Nickname1   :: string(),
        Nickname2   :: string(),
        Lifetime    :: pos_integer(),
        Certificate :: term(),
        Reason      :: term().
new_certificate(PublicKey, Nickname1, Nickname2, Lifetime) ->
    Now = onion_time:epoch(),
    StartTimeSecond = onion_random:time_range(Now - Lifetime, Now) + 2 * 24 * 60 * 60,

    StartTime = StartTimeSecond - (StartTimeSecond rem (24 * 60 * 60)),
    EndTime   = StartTime + Lifetime,

    onion_x509:create_certificate(#{
        public_key => PublicKey,
        valid_from => onion_time:from_epoch(StartTime),
        valid_to   => onion_time:from_epoch(EndTime),
        subject    => [{name, Nickname1}],
        issuer     => [{name, Nickname2}]
    }).

%% @private
-spec log_certificates(map()) -> ok.
log_certificates(Certificates) ->
    lists:foreach(fun log_certificate/1, maps:to_list(Certificates)).

%% @private
-spec log_certificate(term()) -> ok.
log_certificate({Type, {_KeyPair, Certificate}}) ->
    Hash = onion_binary:fingerprint(sha, Certificate),
    case Type of
        link_certificate ->
            lager:notice("Link certificate: ~s", [Hash]);
        id_certificate ->
            lager:notice("ID certificate: ~s", [Hash]);
        auth_certificate ->
            lager:notice("Auth certificate: ~s", [Hash])
    end.
