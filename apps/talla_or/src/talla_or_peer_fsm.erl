%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Onion Router Peer FSM.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer_fsm).
-behaviour(gen_fsm).

%% API.
-export([start_link/0,

         dispatch/2,

         incoming_connection/3,

         disconnected/2
        ]).

%% States.
-export([idle/2,
         version_handshake/2,
         authenticate/2,
         catch_all/2
        ]).

%% Generic FSM Callbacks.
-export([init/1,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4
        ]).

-record(state, {
        type     :: incoming | outgoing,

        peer     :: pid(),
        protocol :: onion_cell:version(),

        address  :: inet:ip_address(),
        port     :: inet:port_number(),

        authenticated  :: boolean(),

        certs          :: [map()],
        authenticate   :: map(),
        auth_challenge :: binary(),

        circuits :: map()
    }).

-spec start_link() -> {ok, Pid} | {error, Reason}
    when
        Pid    :: pid(),
        Reason :: term().
start_link() ->
    gen_fsm:start_link(?MODULE, [self()], []).

dispatch(Peer, Cell) ->
    gen_fsm:send_event(Peer, {dispatch, Cell}).

incoming_connection(Peer, Address, Port) ->
    gen_fsm:send_event(Peer, {incoming_connection, Address, Port}).

disconnected(Peer, Reason) ->
    gen_fsm:send_all_state_event(Peer, {disconnected, Reason}).

%% @private
idle({incoming_connection, Address, Port}, State) ->
    NewState = State#state { type = incoming, address = Address, port = Port },
    log(NewState, notice, "Incoming connection from ~s:~b", [inet:ntoa(Address), Port]),
    {next_state, version_handshake, NewState}.

%idle({outgoing_connection, Address, Port, TLSCertificate, TLSInfo}, State) ->
%    NewState = State#state { type = outgoing, address = Address, port = Port, tls_info = TLSInfo, tls_cert = TLSCertificate },
%    TLSCipherSuite = proplists:get_value(cipher_suite, TLSInfo),
%    TLSProtocol = proplists:get_value(protocol, TLSInfo),
%    log(NewState, notice, "Connected using ~s (~p) ", [TLSProtocol, TLSCipherSuite]),
%    dispatch_cell(NewState, onion_cell:versions()),
%    {next_state, version_handshake, NewState}.

%% @private
version_handshake({dispatch, #{ command := versions, payload := Versions } = Cell}, #state { type = incoming, address = Address, peer = Peer } = State) ->
    log_incoming_cell(State, Cell),
    dispatch_cell(State, onion_cell:versions()),
    case onion_protocol:shared_protocol(Versions) of
        {ok, NewProtocol} ->
            log(State, notice, "Negotiated protocol: ~b", [NewProtocol]),
            talla_or_peer:set_protocol(Peer, NewProtocol),

            NewState = State#state { protocol = NewProtocol },

            %% certs
            {_, LinkCertDER} = talla_or_tls_manager:link_certificate(),
            LinkCert = #{ type => 1, cert => LinkCertDER },

            {_, IDCertDER} = talla_or_tls_manager:id_certificate(),
            IDCert   = #{ type => 2, cert => IDCertDER },
            dispatch_cell(NewState, onion_cell:certs([LinkCert, IDCert])),

            %% auth_challenge
            Challenge = onion_random:bytes(32),
            dispatch_cell(NewState, onion_cell:auth_challenge(Challenge, [{rsa, sha256, tls_secret}])),

            %% netinfo
            dispatch_cell(NewState, onion_cell:netinfo(Address, [talla_or_config:address()])),

            {next_state, authenticate, NewState#state { auth_challenge = Challenge }};

        {error, Reason} ->
            talla_or_peer:close(Peer),
            {stop, normal, State}
    end.

authenticate({dispatch, #{ command := certs, payload := Certs } = Cell}, #state { type = incoming } = State) ->
    log_incoming_cell(State, Cell),
    {next_state, authenticate, State#state { certs = Certs }};

authenticate({dispatch, #{ command := authenticate, payload := Authenticate } = Cell}, #state { type = incoming } = State) ->
    log_incoming_cell(State, Cell),
    {next_state, authenticate, State#state { authenticate = Authenticate }};

authenticate({dispatch, #{ command := netinfo, payload := _Netinfo } = Cell}, #state { type = incoming, authenticate = Auth, certs = Certs } = State) ->
    log_incoming_cell(State, Cell),
    case {Auth, Certs} of
        {undefined, undefined} ->
            {next_state, catch_all, State#state { authenticate  = undefined,
                                                  certs         = undefined,
                                                  authenticated = false }};

        {_, _} ->
            %% FIXME(ahf): Authenticate this peer.
            {next_state, catch_all, State#state { authenticate  = undefined,
                                                  certs         = undefined,
                                                  authenticated = true }}
    end.

catch_all({dispatch, #{ command := create2, circuit := CID, payload := #{ type := ntor, data := <<Fingerprint:20/binary, NTorPublicKey:32/binary, PublicKey:32/binary>> }, circuit := CircuitID} = Cell}, #state { type = incoming, circuits = Circuits } = State) ->
    log_incoming_cell(State, Cell),
    {ok, ServerPublicKey}     = onion_rsa:der_encode(talla_core_secret_id_key:public_key()),
    ServerNTorPublicKey = talla_core_secret_ntor_onion_key:public_key(),
    OurFingerprint = crypto:hash(sha, ServerPublicKey),

    case {Fingerprint, NTorPublicKey} of
        {OurFingerprint, ServerNTorPublicKey} ->
            {Response, KeySeed} = talla_core_secret_ntor_onion_key:server_handshake(PublicKey),
            dispatch_cell(State, onion_cell:created2(CID, Response)),
            {next_state, catch_all, State#state { circuits = maps:put(CID, KeySeed, Circuits) }};

        {_, _} ->
            lager:warning("No match!"),
            {next_state, catch_all, State}
    end;

catch_all({dispatch, #{ command := create2, payload := #{ type := ntap }} = Cell}, #state { type = incoming, peer = Peer } = State) ->
    log_incoming_cell(State, Cell),
    %% FIXME(ahf): implement ...
    lager:warning("Not implemented: ntap"),
    talla_or_peer:close(Peer),
    {stop, normal, State};

catch_all({dispatch, #{ command := relay_early, payload := Payload } = Cell}, #state { type = incoming } = State) ->
    log_incoming_cell(State, Cell),
    {next_state, catch_all, State};

catch_all({dispatch, Cell}, #state { type = incoming } = State) ->
    log_incoming_cell(State, Cell),
    {next_state, catch_all, State}.

%% @private
init([Peer]) ->
    {ok, idle, #state { peer          = Peer,
                        protocol      = 3,
                        authenticated = false,
                        circuits      = maps:new() }}.

%% @private
handle_event({disconnected, Reason}, _StateName, State) ->
    log(State, notice, "Disconnected: ~p", [Reason]),
    {stop, normal, State};

handle_event(Request, StateName, State) ->
    log(State, warning, "Unhandled event: ~p", [Request]),
    {next_state, StateName, State}.

%% @private
handle_sync_event(Request, _From, StateName, State) ->
    log(State, warning, "Unhandled sync event: ~p", [Request]),
    {next_state, StateName, State}.

%% @private
handle_info(Info, StateName, State) ->
    log(State, warning, "Unhandled info: ~p", [Info]),
    {next_state, StateName, State}.

%% @private
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% @private
terminate(_Reason, _StateName, _State) ->
    ok.

%% @private
dispatch_cell(#state { peer = Peer } = State, #{ circuit := CircuitID, command := Command } = Cell) ->
    log(State, notice, "-> ~p (Circuit: ~b)", [Command, CircuitID]),
    talla_or_peer:dispatch(Peer, Cell).

%% @private
log_incoming_cell(State, #{ circuit := CircuitID, command := Command }) ->
    log(State, notice, "<- ~p (Circuit: ~b)", [Command, CircuitID]).

%% @private
log(State, Method, Message) ->
    log(State, Method, Message, []).

%% @private
log(#state { address = Address, port = Port, protocol = Protocol }, Method, Message, Arguments) ->
    lager:log(Method, [{address, Address}, {port, Port}, {protocol, Protocol}], "~s:~b (v~b) " ++ Message, [inet:ntoa(Address), Port, Protocol] ++ Arguments).
