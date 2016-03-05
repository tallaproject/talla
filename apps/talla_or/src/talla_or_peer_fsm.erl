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

         incoming_cell/2,
         outgoing_cell/2,

         incoming_connection/3,
         outgoing_connection/3,

         protocol_version/1
        ]).

%% States.
-export([idle/2,

         handshaking/2,

         authenticating/2,

         authenticated/2,
         unauthenticated/2
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

        certs          :: [map()],
        authenticate   :: map(),
        auth_challenge :: binary(),

        circuits :: map()
    }).

-define(CELL(Cell), {incoming_cell, Cell}).

-define(CELL(CircuitID, Command), ?CELL(#{ circuit := CircuitID,
                                           command := Command } = Cell)).
-define(CELL(CircuitID, Command, Payload), ?CELL(#{ circuit := CircuitID,
                                                    command := Command,
                                                    payload := Payload } = Cell)).

-spec start_link() -> {ok, Pid} | {error, Reason}
    when
        Pid    :: pid(),
        Reason :: term().
start_link() ->
    gen_fsm:start_link(?MODULE, [self()], []).

incoming_cell(Peer, Cell) ->
    gen_fsm:send_event(Peer, {incoming_cell, Cell}).

outgoing_cell(Peer, Cell) ->
    gen_fsm:send_event(Peer, {outgoing_cell, Cell}).

incoming_connection(Peer, Address, Port) ->
    gen_fsm:send_event(Peer, {incoming_connection, Address, Port}).

outgoing_connection(Peer, Address, Port) ->
    gen_fsm:send_event(Peer, {outgoing_connection, Address, Port}).

protocol_version(Peer) ->
    gen_fsm:sync_send_all_state_event(Peer, protocol_version).

%% @private
idle({incoming_connection, Address, Port}, State) ->
    NewState = State#state { type = incoming, address = Address, port = Port },
    log(NewState, notice, "Incoming connection from ~s:~b", [inet:ntoa(Address), Port]),
    {next_state, handshaking, NewState};

idle({outgoing_connection, Address, Port}, State) ->
    NewState = State#state { type = outgoing, address = Address, port = Port },
    log(NewState, notice, "Outgoing connection to ~s:~b", [inet:ntoa(Address), Port]),
    forward_outgoing_cell(NewState, onion_cell:versions()),
    {next_state, handshaking, NewState}.

%% @private
handshaking(?CELL(0, versions, Versions), #state { type = incoming, address = Address, peer = Peer } = State) ->
    forward_outgoing_cell(State, onion_cell:versions()),
    case onion_protocol:shared_protocol(Versions) of
        {ok, NewProtocol} ->
            log(State, notice, "Negotiated protocol: ~b", [NewProtocol]),
            NewState = State#state { protocol = NewProtocol },

            %% certs
            {_, LinkCertDER} = talla_or_tls_manager:link_certificate(),
            LinkCert = #{ type => 1, cert => LinkCertDER },

            {_, IDCertDER} = talla_or_tls_manager:id_certificate(),
            IDCert   = #{ type => 2, cert => IDCertDER },
            forward_outgoing_cell(NewState, onion_cell:certs([LinkCert, IDCert])),

            %% auth_challenge
            Challenge = onion_random:bytes(32),
            forward_outgoing_cell(NewState, onion_cell:auth_challenge(Challenge, [{rsa, sha256, tls_secret}])),

            %% netinfo
            forward_outgoing_cell(NewState, onion_cell:netinfo(Address, [talla_or_config:address()])),

            {next_state, authenticating, NewState#state { auth_challenge = Challenge }};

        {error, Reason} ->
            {stop, normal, State}
    end;

handshaking(?CELL(0, versions, Versions), #state { type = outgoing, address = Address, peer = Peer } = State) ->
    case onion_protocol:shared_protocol(Versions) of
        {ok, NewProtocol} ->
            log(State, notice, "Negotiated protocol: ~b", [NewProtocol]),

            NewState = State#state { protocol = NewProtocol },

            {next_state, handshaking, NewState};

        {error, _} = Error ->
            {stop, Error, State}
    end;

handshaking(?CELL(Cell), #state { type = outgoing } = State) ->
    {next_state, handshaking, State}.

authenticating(?CELL(0, certs, Certs), #state { type = incoming } = State) ->
    {next_state, authenticating, State#state { certs = Certs }};

authenticating(?CELL(0, authenticate, Authenticate), #state { type = incoming } = State) ->
    {next_state, authenticating, State#state { authenticate = Authenticate }};

authenticating(?CELL(0, netinfo, _Netinfo), #state { type         = incoming,
                                                     authenticate = Auth,
                                                     certs        = Certs } = State) ->
    case {Auth, Certs} of
        {undefined, undefined} ->
            {next_state, unauthenticated, State#state { authenticate = undefined,
                                                        certs        = undefined }};

        {_, _} ->
            %% FIXME(ahf): Authenticate this peer.
            {next_state, authenticated, State#state { authenticate = undefined,
                                                      certs        = undefined }}
    end.

authenticated(?CELL(CircuitID, create2), #state { type = incoming } = State) when CircuitID =/= 0 ->
    {next_state, authenticated, forward_circuit_cell(State, Cell)};

authenticated(?CELL(CircuitID, destroy), #state { type = incoming } = State) when CircuitID =/= 0 ->
    {next_state, authenticated, forward_circuit_cell(State, Cell)};

authenticated(?CELL(CircuitID, relay_early), #state { type = incoming } = State) when CircuitID =/= 0 ->
    {next_state, authenticated, forward_circuit_cell(State, Cell)};

authenticated(?CELL(CircuitID, relay), #state { type = incoming } = State) when CircuitID =/= 0 ->
    {next_state, authenticated, forward_circuit_cell(State, Cell)};

authenticated(?CELL(Cell), #state { type = incoming } = State) ->
    {next_state, authenticated, State};

authenticated({outgoing_cell, Cell}, #state { type = incoming } = State) ->
    forward_outgoing_cell(State, Cell),
    {next_state, authenticated, State}.

unauthenticated(?CELL(Cell), #state { type = incoming } = State) ->
    {next_state, authenticated, State}.

%% @private
init([Peer]) ->
    {ok, idle, #state { peer     = Peer,
                        protocol = 3,
                        circuits = maps:new() }}.

%% @private
handle_event(Request, StateName, State) ->
    log(State, warning, "Unhandled event: ~p", [Request]),
    {next_state, StateName, State}.

%% @private
handle_sync_event(protocol_version, From, StateName, #state { protocol = ProtocolVersion } = State) ->
    gen_fsm:reply(From, ProtocolVersion),
    {next_state, StateName, State};

handle_sync_event(Request, From, StateName, State) ->
    log(State, warning, "Unhandled sync event: ~p", [Request]),
    gen_fsm:reply(From, unhandled),
    {next_state, StateName, State}.

%% @private
handle_info(stop, _StateName, State) ->
    log(State, notice, "Disconnected", []),
    {stop, normal, State};

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
forward_outgoing_cell(#state { peer = Peer, protocol = Protocol } = State, #{ circuit := CircuitID, command := Command } = Cell) ->
    talla_or_peer:outgoing_cell(Peer, Protocol, Cell).

%% @private
forward_circuit_cell(#state { circuits = Circuits } = State, #{ circuit := CircuitID, command := Command } = Cell) ->
    log(State, notice, "=> ~p (Circuit: ~b)", [Command, CircuitID]),
    case maps:get(CircuitID, Circuits, not_found) of
        not_found ->
            {ok, Pid} = talla_or_circuit_sup:start_circuit(CircuitID, self()),
            talla_or_circuit:incoming_cell(Pid, Cell),
            State#state { circuits = maps:put(CircuitID, Pid, Circuits) };

        Pid ->
            talla_or_circuit:incoming_cell(Pid, Cell),
            State
    end.

%% @private
log(State, Method, Message) ->
    log(State, Method, Message, []).

%% @private
log(#state { address = Address, port = Port, protocol = Protocol }, Method, Message, Arguments) ->
    lager:log(Method, [{address, Address}, {port, Port}, {protocol, Protocol}], "~s:~b (v~b) " ++ Message, [inet:ntoa(Address), Port, Protocol] ++ Arguments).
