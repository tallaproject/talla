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
         link_certificate/0
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
-define(LINK_CERTIFICATE_LIFETIME, (3 * 60 * 60)).

%% Types.
-record(state, {
            secret_key  :: public_key:der_encoded(),
            certificate :: public_key:der_encoded(),
            timer_ref   :: reference()
         }).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec link_certificate() -> {SecretKey, Certificate}
    when
        SecretKey   :: public_key:der_encoded(),
        Certificate :: public_key:der_encoded().
link_certificate() ->
    gen_server:call(?SERVER, link_certificate).

%% @private
init([]) ->
    {SecretKey, Certificate} = new_link_certificate(),
    lager:notice("Link certificate: ~s", [onion_binary:fingerprint(sha, Certificate)]),
    TimerRef = start_timer(),
    {ok, #state {
            secret_key  = SecretKey,
            certificate = Certificate,
            timer_ref   = TimerRef
           }}.

%% @private
handle_call(link_certificate, _From, #state { secret_key = SecretKey, certificate = Certificate } = State) ->
    {reply, {SecretKey, Certificate}, State};

handle_call(Request, From, State) ->
    lager:warning("Unhandled call '~p' from ~p (State: ~p)", [Request, From, State]),
    {reply, ok, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast '~p' (State: ~p)", [Message, State]),
    {noreply, State}.

%% @private
handle_info({timeout, TimerRef, rotate}, #state { timer_ref = TimerRef } = State) ->
    {SecretKey, Certificate} = new_link_certificate(),
    lager:notice("Rotating link certificate: ~s", [onion_binary:fingerprint(sha, Certificate)]),
    NewTimerRef = start_timer(),
    {noreply, State#state {
                secret_key  = SecretKey,
                certificate = Certificate,
                timer_ref   = NewTimerRef
              }};

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
-spec new_link_certificate() -> {public_key:der_encoded(), public_key:der_encoded()}.
new_link_certificate() ->
    Lifetime = certificate_lifetime(),
    Now = onion_time:unix_epoch(),
    StartTimeSecond = onion_random:time_range(Now - Lifetime, Now) + 2 * 24 * 60 * 60,
    StartTime = StartTimeSecond - (StartTimeSecond rem (24 * 60 * 60)),
    EndTime   = StartTime + Lifetime,
    {ok, #{ secret := SecretKey, public := PublicKey }} = onion_rsa:keypair(1024),
    {ok, SecretKeyDer} = onion_rsa:der_encode(SecretKey),
    {ok, Certificate} = onion_x509:create_certificate(#{
                                public_key => PublicKey,
                                valid_from => onion_time:from_unix_epoch(StartTime),
                                valid_to   => onion_time:from_unix_epoch(EndTime),
                                subject    => [{name, onion_random:hostname(8, 20, "www.", ".net")}],
                                issuer     => [{name, onion_random:hostname(8, 20, "www.", ".com")}]
                            }),
    {SecretKeyDer, talla_core_secret_id_key:sign_certificate(Certificate)}.

%% @private
-spec start_timer() -> reference().
start_timer() ->
    erlang:start_timer(timer:seconds(?LINK_CERTIFICATE_LIFETIME), self(), rotate).
