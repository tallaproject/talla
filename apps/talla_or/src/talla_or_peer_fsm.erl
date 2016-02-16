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

         incoming_connection/4,
         outgoing_connection/5,

         disconnected/2
        ]).

%% States.
-export([idle/2,

         version_handshake/3,
         certs/3,
         auth_challenge/3,
         netinfo/3,

         catch_all/3
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

        tls_info :: proplists:proplist(),
        tls_cert :: public_key:der_encoded(),

        certs    :: [map()]
    }).

-spec start_link() -> {ok, Pid} | {error, Reason}
    when
        Pid    :: pid(),
        Reason :: term().
start_link() ->
    gen_fsm:start_link(?MODULE, [self()], []).

dispatch(Peer, Cell) ->
    gen_fsm:sync_send_event(Peer, {dispatch, Cell}).

incoming_connection(Peer, Address, Port, TLSInfo) ->
    gen_fsm:send_event(Peer, {incoming_connection, Address, Port, TLSInfo}).

outgoing_connection(Peer, Address, Port, TLSCertificate, TLSInfo) ->
    gen_fsm:send_event(Peer, {outgoing_connection, Address, Port, TLSCertificate, TLSInfo}).

disconnected(Peer, Reason) ->
    gen_fsm:send_all_state_event(Peer, {disconnected, Reason}).

%% @private
idle({incoming_connection, Address, Port, TLSInfo}, State) ->
    log(State, notice, "Incoming connection"),
    {next_state, idle, State#state { type = incoming, address = Address, port = Port, tls_info = TLSInfo } };

idle({outgoing_connection, Address, Port, TLSCertificate, TLSInfo}, State) ->
    NewState = State#state { type = outgoing, address = Address, port = Port, tls_info = TLSInfo, tls_cert = TLSCertificate },
    TLSCipherSuite = proplists:get_value(cipher_suite, TLSInfo),
    TLSProtocol = proplists:get_value(protocol, TLSInfo),
    log(NewState, notice, "Connected using ~s (~p) ", [TLSProtocol, TLSCipherSuite]),
    dispatch_cell(NewState, onion_cell:versions()),
    {next_state, version_handshake, NewState}.

%% @private
version_handshake({dispatch, #{ command := versions, payload := Versions } = Cell}, From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    case onion_protocol:shared_protocol(Versions) of
        {ok, NewProtocol} ->
            log(State, notice, "Negotiated protocol: ~b", [NewProtocol]),
            gen_fsm:reply(From, {upgrade, NewProtocol}),
            {next_state, certs, State#state { protocol = NewProtocol }};

        {error, Reason} ->
            gen_fsm:reply(From, {close, Reason}),
            {stop, normal, State}
    end;

version_handshake({dispatch, #{ command := authorize } = Cell}, _From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    {reply, ok, version_handshake, State};

version_handshake({dispatch, #{ command := vpadding } = Cell}, _From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    {reply, ok, version_handshake, State};

version_handshake({dispatch, #{ command := padding } = Cell}, _From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    {reply, ok, version_handshake, State};

version_handshake({dispatch, #{command := Command } = Cell}, From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    log(State, error, "Received invalid cell ~p during version handshake", [Command]),
    gen_fsm:reply(From, {close, invalid_command, Command}),
    {stop, normal, State}.

certs({dispatch, #{ command := certs, payload := Certs } = Cell}, _From, #state { tls_cert = TLSCertificate, type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    {ok, PublicKey} = onion_x509:public_key(TLSCertificate),
    case onion_certs_cell:validate_server(Certs, PublicKey) of
        true ->
            {reply, ok, auth_challenge, State#state { certs = Certs }};

        false ->
            {reply, {close, invalid_certs}, normal, State}
    end;

certs({dispatch, #{command := Command } = Cell}, From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    log(State, error, "Invalid Cell: ~w (~p)", [Cell, certs]),
    gen_fsm:reply(From, {close, invalid_command, Command}),
    {stop, normal, State}.

auth_challenge({dispatch, #{ command := auth_challenge } = Cell}, _From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
%%    dispatch_cell(Peer, onion_cell:certs()),
%%    dispatch_cell(Peer, onion_cell:authenticate()),
    {reply, ok, netinfo, State};

auth_challenge({dispatch, #{command := Command } = Cell}, From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    log(State, error, "Invalid Cell: ~w (~p)", [Cell, auth_challenge]),
    gen_fsm:reply(From, {close, invalid_command, Command}),
    {stop, normal, State}.

netinfo({dispatch, #{ command := netinfo } = Cell}, _From, #state { address = Address, type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    dispatch_cell(State, onion_cell:netinfo(Address, [talla_or_config:address()])),
    {reply, ok, missing, State};

netinfo({dispatch, #{ command := Command } = Cell}, From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    log(State, error, "Invalid Cell: ~w (~p)", [Cell, netinfo]),
    gen_fsm:reply(From, {close, invalid_command, Command}),
    {stop, normal, State}.

catch_all({dispatch, Cell}, _From, #state { type = outgoing } = State) ->
    log_incoming_cell(State, Cell),
    {reply, ok, catch_all, State}.

%connect(Peer, Address, Port) ->
%    gen_fsm:send_event(Peer, {connecting, Address, Port}).

%connected(Peer, ProtocolVersion, KeyExchange, Cipher, Hash) ->
%    gen_fsm:send_event(Peer, {connected, ProtocolVersion, KeyExchange, Cipher, Hash}).

%% @private
%% @private
%%await_versions_cell({dispatch, #{ command := versions, payload := Versions } = Cell}, _From, #state { peer = _Peer } = State) ->
%%    lager:notice("Cell: <- ~w", [Cell]),
%%    OurVersions = ordsets:from_list(onion_cell:supported_cell_versions()),
%%    TheirVersions = ordsets:from_list(Versions),
%%    case ordsets:union(OurVersions, TheirVersions) of
%%        [] ->
%%            {reply, {close, protocol_mismatch}, await_cell, State};
%%
%%        VersionUnion ->
%%            NewProtocol = lists:last(VersionUnion),
%%            lager:notice("Negotiated protocol version: ~b", [NewProtocol]),
%%            {reply, {upgrade, NewProtocol}, await_cell, State#state { protocol = NewProtocol }}
%%    end.

%% @private
%%await_cell({dispatch, Cell}, _From, State) ->
%%    lager:notice("Cell: <- ~w", [Cell]),
%%    {reply, ok, await_cell, State}.

%% @private
init([Peer]) ->
    {ok, idle, #state { peer = Peer, protocol = 3 }}.

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
dispatch_cell(#state { peer = Peer } = State, #{ circuit := CircuitID, command := Command, payload := Payload } = Cell) ->
    log(State, notice, "-> ~p (Circuit: ~b): ~p", [Command, CircuitID, Payload]),
    talla_or_peer:dispatch(Peer, Cell).

%% @private
log_incoming_cell(State, #{ circuit := CircuitID, command := Command, payload := Payload }) ->
    log(State, notice, "<- ~p (Circuit: ~b): ~p", [Command, CircuitID, Payload]).

%% @private
log(State, Method, Message) ->
    log(State, Method, Message, []).

%% @private
log(#state { address = Address, port = Port, protocol = Protocol }, Method, Message, Arguments) ->
    lager:log(Method, [{address, Address}, {port, Port}, {protocol, Protocol}], "~s:~b (v~b) " ++ Message, [inet:ntoa(Address), Port, Protocol] ++ Arguments).
