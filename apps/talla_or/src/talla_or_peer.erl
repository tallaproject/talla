%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Onion Router Peer.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer).
-behaviour(gen_statem).

%% API.
-export([start_link/0,
         stop/1,
         send/2,
         connect/3,
         create_circuit/1
        ]).

%% States.
-export([normal/3,
         await_connect/3,
         outbound_handshake/3,
         inbound_handshake/3
        ]).

%% Generic State Machine Callbacks.
-export([init/1,
         code_change/4,
         terminate/3,
         callback_mode/0
        ]).

%% Ranch Callbacks.
-export([start_link/4,
         init/4
        ]).

%% Types.
-export_type([t/0]).

-type t() :: pid().

-record(state, {
            %% The socket of our peer.
            socket :: ssl:sslsocket(),

            %% Continuation of packets used by the cell decoder.
            continuation = <<>> :: binary(),

            %% Sender process.
            send_process :: talla_or_peer_send:t(),

            %% TLS session information
            session_info :: onion_ssl_session:t(),

            %% Used by the rlimit application to notify our peer that it should
            %% (re)activate its socket and allow incoming data. This is used
            %% for TCP rate-limiting.
            receive_limit :: pid(),

            %% Contexts used for authentication.
            receive_context :: binary(),
            send_context    :: binary(),

            %% Protocol version used by the cell decoder.
            protocol_version = 3 :: onion_cell:version(),

            %% Certs cell.
            certs_payload :: [map()],

            %% Circuit ID to circuit handler mapping.
            circuits = #{} :: #{ non_neg_integer() => talla_or_circuit:t() },

            %% Last received cell timestamp.
            last_cell_received :: integer(),

            %% Last received cell timer.
            last_cell_timer :: reference(),

            %% The direction of the connection.
            direction :: inbound | outbound
    }).

-type state() :: #state {}.

-type der_encoded() :: public_key:der_encoded().

-type cert() :: #{ type => 1..3,
                   cert => der_encoded()}.


%% How long to keep the connection alive without having been able to decode a
%% cell.
-define(CELL_TIMEOUT, timer:minutes(5)).

%% Connect timeout to external OR's.
-define(CONNECT_TIMEOUT, timer:seconds(30)).

%% Max tries when generating a new Circuit ID before giving up.
-define(CIRCUIT_ID_CREATION_ATTEMPTS, 100).

%% ----------------------------------------------------------------------------
%% API.
%% ----------------------------------------------------------------------------

%% @doc Start a new, linked, Peer process.
%%
%% This function spawns and starts a new Peer process that is linked to the
%% callers process.
%%
%% @end
-spec start_link() -> {ok, Peer} | {error, Reason}
    when
        Peer   :: t(),
        Reason :: term().
start_link() ->
    gen_statem:start_link(?MODULE, [], []).

%% @doc Stop a Peer process.
%%
%% This function stops a given Peer process.
%%
%% @end
-spec stop(Peer) -> ok
    when
        Peer :: t().
stop(Peer) ->
    gen_statem:stop(Peer).

%% @doc Send a Cell to the given Peer.
%%
%% This function will queue and send a given cell to the given peer.
%%
%% @end
-spec send(Peer, Cell) -> ok
    when
        Peer :: t(),
        Cell :: onion_cell:t().
send(Peer, Cell) ->
    gen_statem:cast(Peer, {send, Cell}).

%% @doc Connect to an onion router.
-spec connect(Peer, Address, Port) -> ok
    when
        Peer    :: t(),
        Address :: inet:ip_address(),
        Port    :: inet:port_number().
connect(Peer, Address, Port) ->
    gen_statem:cast(Peer, {connect, Address, Port}).

%% @doc Create a new circuit.
-spec create_circuit(Peer) -> {ok, Circuit} | {error, Reason}
    when
        Peer    :: t(),
        Circuit :: talla_or_circuit:t(),
        Reason  :: term().
create_circuit(Peer) ->
    gen_statem:call(Peer, create_circuit).

%% ----------------------------------------------------------------------------
%% Protocol States.
%% ----------------------------------------------------------------------------

%% @private
-spec normal(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
normal(internal, {cell, #{ command := create2,
                           circuit := CircuitID } = Cell}, #state { circuits = Circuits } = StateData) when CircuitID =/= 0 ->
    case maps:get(CircuitID, Circuits, not_found) of
        not_found ->
            %% FIXME(ahf): Generate new CircuitID here.
            {ok, Pid} = start_circuit(CircuitID),

            %% Update our state.
            NewStateData = StateData#state {
                circuits = maps:put(CircuitID, Pid, Circuits)
            },

            %% Forward the create2 cell to the circuit.
            talla_or_circuit:dispatch(Pid, Cell),

            {keep_state, NewStateData};

        Pid when is_pid(Pid) ->
            lager:warning("Received create2 cell on known circuit: ~p", [Cell]),
            {keep_state, StateData}
    end;

normal(internal, {cell, #{ command := destroy,
                           circuit := CircuitID } = Cell}, #state { circuits = Circuits } = StateData) when CircuitID =/= 0 ->
    case maps:get(CircuitID, Circuits, not_found) of
        not_found ->
            lager:warning("Received destroy cell on unknown circuit: ~p", [Cell]),
            {keep_state, StateData};

        Pid when is_pid(Pid) ->
            talla_or_circuit:dispatch(Pid, Cell),

            %% Update our state.
            NewStateData = StateData#state {
                circuits = maps:remove(CircuitID, Circuits)
            },

            {keep_state, NewStateData}
    end;

normal(internal, {cell, #{ circuit := CircuitID } = Cell}, #state { circuits = Circuits } = StateData) when CircuitID =/= 0 ->
    case maps:get(CircuitID, Circuits, not_found) of
        not_found ->
            lager:warning("Received cell on unknown circuit: ~p", [Cell]),
            {keep_state, StateData};

        Pid when is_pid(Pid) ->
            talla_or_circuit:dispatch(Pid, Cell),
            {keep_state, StateData}
    end;

normal(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

-spec await_connect(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
await_connect(cast, {connect, Address, Port}, undefined) ->
    %% We have been asked to connect to a remote OR.
    lager:info("Connecting to onion router at ~s:~b", [inet:ntoa(Address), Port]),

    %% Try to connect to the OR.
    case ssl:connect(Address, Port, [{mode, binary}, {packet, raw}, {active, false}, {nodelay, true}], ?CONNECT_TIMEOUT) of
        {ok, Socket} ->
            %% We successfully managed to connect to the OR.
            lager:info("Connected to onion router at ~s:~b", [inet:ntoa(Address), Port]),

            %% Add connection metadata to lager for tracing.
            lager:md([
                {ip_address,  ip_address(Socket)},
                {port_number, port_number(Socket)}
            ]),

            %% Our State.
            StateData = state(Socket),

            %% Update our state data.
            NewStateData = StateData#state {
                session_info = onion_ssl_session:from_client_socket(Socket),
                direction    = outbound
            },

            %% Send a version cell to the remote OR.
            SendContext = send_internal(onion_cell:versions(), NewStateData),

            {next_state, outbound_handshake, NewStateData#state{ send_context = SendContext }};

        {error, Reason} ->
            lager:info("Unable to connect to onion router at ~s:~b: ~p", [inet:ntoa(Address), Port, Reason]),

            %% FIXME(ahf): Consider a:
            %% talla_or_peer_manager:peer_error(Reason).
            talla_or_peer_manager:timeout(),

            {stop, normal, undefined}
    end;

await_connect(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

-spec outbound_handshake(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
outbound_handshake(internal, {cell, #{ command := versions,
                                       circuit := 0,
                                       payload := Versions }}, StateData) ->
    case onion_protocol:shared_protocol(Versions) of
        {ok, ProtocolVersion} ->
            lager:info("Negotiated protocol version: ~b", [ProtocolVersion]),

            %% Update our state.
            NewStateData = StateData#state {
                protocol_version = ProtocolVersion
            },

            {keep_state, NewStateData}; %%% FIXME

        {error, _} ->
            lager:warning("Unable to negotiate versions with peer. They support: ~p", [Versions]),
            {stop, normal, StateData}
    end;

outbound_handshake(internal, {cell, #{ command := certs,
                                       circuit := 0,
                                       payload := Certs }}, #state { session_info = #{ certificate := SSLCert } } = StateData) ->

    %% Validate certificates according to tor-spec 4.2
    ok = outbound_cert_validation(Certs, SSLCert),

    NewStateData = StateData#state {
        certs_payload = Certs
    },

    {keep_state, NewStateData};

outbound_handshake(internal, {cell, #{ command := auth_challenge,
                                       circuit := 0,
                                       payload := #{ methods := [{rsa, sha256, tls_secret}] } }}, #state { receive_context    = ReceiveContext,
                                                                                                           socket             = Socket,
                                                                                                           certs_payload      = Certs,
                                                                                                           session_info       = SessionInformation} = StateData) ->
    %% Get the authentication certificate and store the secret key we
    %% use for later verification.
    {#{ secret := AuthenticationSecretKey }, AuthenticationCertificate} = talla_or_tls_manager:auth_certificate(),

    %% Send certs cell.
    CertsCell = onion_cell:certs([#{ type => 3, cert => AuthenticationCertificate },
                                  #{ type => 2, cert => identity_certificate() }]),
    NewSendContext = send_internal(CertsCell, StateData),

    %% Update our state (since we do not need contexts etc. anymore).
    NewStateData = StateData#state {
        certs_payload      = undefined,
        receive_context    = undefined,
        send_context       = undefined
    },

    %% Create and send authenticate cell
    [#{ cert := ServerIdentityCertificate }] = lists:filter(fun (#{ type := Type}) ->
                                                                Type =:= 2
                                                            end, Certs),
    {ok, ServerIdentityPublicKey} = onion_x509:public_key(ServerIdentityCertificate),

    AuthenticateCell = onion_authenticate_cell:create(#{
            client_identity_public_key => talla_core_identity_key:public_key(),
            server_identity_public_key => ServerIdentityPublicKey,

            client_log => crypto:hash_final(NewSendContext),
            server_log => crypto:hash_final(ReceiveContext),

            server_certificate => onion_ssl_session:certificate(SessionInformation),
            ssl_session        => SessionInformation,

            authentication_secret_key => AuthenticationSecretKey
        }),
    send_internal(AuthenticateCell, NewStateData),

    %% Create and send netinfo cell
    NetinfoCell = onion_cell:netinfo(ip_address(Socket), [talla_or_config:address()]),
    send_internal(NetinfoCell, NewStateData),

    talla_or_peer_manager:connected(),

    {next_state, normal, NewStateData};

outbound_handshake(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

-spec inbound_handshake(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
inbound_handshake(internal, {cell, #{ command := versions,
                                      circuit := 0,
                                      payload := Versions }}, #state { socket = Socket } =  StateData) ->
    case onion_protocol:shared_protocol(Versions) of
        {ok, ProtocolVersion} ->
            %% We receive an versions cell on circuit 0 - we send our versions cell,
            %% handshake information, and update our state.
            NewSendContext1 = send_internal(onion_cell:versions(), StateData),

            lager:info("Negotiated protocol version: ~b", [ProtocolVersion]),

            NewStateData = StateData#state { protocol_version = ProtocolVersion },

            %% Send certs cell.
            CertsCell = onion_cell:certs([#{ type => 1, cert => link_certificate() },
                                          #{ type => 2, cert => identity_certificate() }]),
            NewSendContext2 = send_internal(CertsCell, NewStateData#state { send_context = NewSendContext1 }),

            %% We hash the random bytes to avoid exposing "pure" randomness.
            Challenge = crypto:hash(sha256, onion_random:bytes(32)),

            %% Send Auth Challenge.
            AuthChallengeCell = onion_cell:auth_challenge(Challenge, [{rsa, sha256, tls_secret}]),
            NewSendContext3 = send_internal(AuthChallengeCell, NewStateData#state { send_context = NewSendContext2 }),

            %% Send Netinfo.
            NetinfoCell = onion_cell:netinfo(ip_address(Socket), [talla_or_config:address()]),
            send_internal(NetinfoCell, NewStateData),

            %% Update our send context.
            FinalStateData = NewStateData#state { send_context = NewSendContext3 },

            %% Await incoming certs, authenticate & netinfo cells
            {keep_state, FinalStateData};

        {error, _} ->
            lager:warning("Unable to negotiate versions with peer. They support: ~p", [Versions]),
            {stop, normal, StateData}
    end;

inbound_handshake(internal, {cell, #{ command := certs,
                                      circuit := 0,
                                      payload := Certs }}, #state { receive_context = ReceiveContext,
                                                                    send_context    = SendContext} = StateData) ->
    %% Validate certs (according to tor-spec 4.2), store them, stop context updating and wait for authenticate cell.
    %% FIXME(ahf): Check if we have already received a certs cell.
    ok = inbound_cert_validation(Certs),
    NewStateData = StateData#state {
        certs_payload   = Certs,
        receive_context = {final, crypto:hash_final(ReceiveContext)},
        send_context    = {final, crypto:hash_final(SendContext)}
    },

    %% Continue.
    {keep_state, NewStateData};

inbound_handshake(internal, {cell, #{ command := authenticate,
                                      circuit := 0,
                                      payload := #{ auth_type := AuthType, auth := Authenticate } }}, StateData) ->
    %% Received authenticate cell. Validate the contents and continue.
    %% FIXME(ahf): Check if we have already received an authenticate cell.
    case AuthType of
        1 ->
            ok = validate_authenticate_cell(Authenticate, StateData);
        _ ->
            throw({error, unknown_auth_type})
    end,

    %% Continue.
    {keep_state, StateData};

inbound_handshake(internal, {cell, #{ command := netinfo,
                                      circuit := 0 }}, StateData) ->
    %% We received a netinfo cell and is now able to determine if the remote
    %% peer wants to authenticate with us (they are a relay) or they want to
    %% continue as an unauthenticated peer (they are a client).

    %% Update our state and remove all the information that is no longer
    %% needed for us.
    NewStateData = StateData#state {
        certs_payload            = undefined,

        %% No longer needed and we want to avoid running a SHA-256 update on
        %% every incoming packet.
        receive_context = undefined,
        send_context    = undefined
    },
    {next_state, normal, NewStateData};

inbound_handshake(internal, {cell, #{ command := Command }}, StateData) ->
    lager:warning("Protocol violation during handshake: Received ~s", [Command]),

    {stop, normal, StateData};

inbound_handshake(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

%% ----------------------------------------------------------------------------
%% Generic State Machine Callbacks.
%% ----------------------------------------------------------------------------

%% @private
%% This function is used to initialize our state machine.
init([]) ->
    %% We want to trap exit signals.
    process_flag(trap_exit, true),

    {ok, await_connect, undefined}.

%% @private
%% Call when we are doing a code change (live upgrade/downgrade).
-spec code_change(Version, StateName, StateData, Extra) -> {ok, NewStateName, NewStateData}
    when
        Version         :: {down, term()} | term(),
        StateName       :: atom(),
        StateData       :: state(),
        Extra           :: term(),
        NewStateName    :: StateName,
        NewStateData    :: StateData.
code_change(_Version, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

%% @private
%% Called before our process is terminated.
-spec terminate(Reason, StateName, StateData) -> ok
    when
        Reason    :: term(),
        StateName :: atom(),
        StateData :: state().
terminate(Reason, StateName, _StateData) ->
    lager:notice("Shutting down peer: ~p (~s)", [Reason, StateName]),

    %% Remember that in this function that StateData might be undefined and not
    %% state() in case the call to ssl:connect/4 fails in await_connect/3.

    ok.

%% ----------------------------------------------------------------------------
%% Ranch Callbacks.
%% ----------------------------------------------------------------------------

%% @private
%% This function is called by Ranch when it's accepting an incoming connection
%% to our Onion Router port.
-spec start_link(Ref, Socket, Transport, Options) -> {ok, Peer} | {error, Reason}
    when
        Ref       :: term(),
        Socket    :: ssl:socket(),
        Transport :: term(),
        Options   :: [term()],
        Peer      :: t(),
        Reason    :: term().
start_link(Ref, Socket, Transport, Options) ->
    proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Options]).

%% @private
%% Do initialization for incoming connections and enter our gen_statem event
%% loop.
-spec init(Ref, Socket, Transport, Options) -> no_return()
    when
        Ref       :: term(),
        Socket    :: ssl:sslsocket(),
        Transport :: term(),
        Options   :: [term()].
init(Ref, Socket, _Transport, _Options) ->
    %% Accept our connection from Ranch.
    ok = proc_lib:init_ack({ok, self()}),
    ok = ranch:accept_ack(Ref),

    %% We want to trap exit signals.
    process_flag(trap_exit, true),

    %% Add connection metadata to lager for tracing.
    lager:md([
        {ip_address,  ip_address(Socket)},
        {port_number, port_number(Socket)}
    ]),

    %% Log the incoming connection.
    lager:info("Accepted incoming onion connection from ~s:~b", [inet:ntoa(ip_address(Socket)),
                                                                   port_number(Socket)]),

    %% Initialize our state.
    StateData = state(Socket),

    %% Get the DER encoded certificate that was served to our client. We have
    %% to get this from talla_or_tls as a message since it might get rotated
    %% between the client was accepted and that we are ready to ask the
    %% talla_tls_manager which certificate that is (currently) in use.
    {ok, Certificate} = server_certificate(),

    %% Our initial state.
    NewStateData = StateData#state {
        session_info = onion_ssl_session:from_server_socket(Socket, Certificate),
        direction    = inbound
    },

    %% Enter the Generic State Machine loop.
    gen_statem:enter_loop(?MODULE, [], inbound_handshake, NewStateData).

%% ----------------------------------------------------------------------------
%% Generic State Handler.
%% ----------------------------------------------------------------------------

%% @private
%% Handle events that are generic for all states. All state functions should
%% have a catch all function clause that dispatches onto this function.
%%
%% This function should never have a reason to return something other than
%% {keep_state, StateData} or {stop, Reason, StateData}.
-spec handle_event(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
handle_event(cast, {send, Cell}, StateData) ->
    SendContext = send_internal(Cell, StateData),
    {keep_state, StateData#state { send_context = SendContext }};

handle_event(internal, {cell, _Cell}, StateData) ->
    %% We have received a cell and none of our state handlers handled the
    %% event. We ignore it and continue as is.
    {keep_state, StateData};

handle_event(info, {limit, continue}, #state { socket = Socket } = StateData) ->
    %% Our peer is allowed to receive data again from the rate-limit system.
    %% Continue with the current state that we are in.
    activate_socket(Socket),
    {keep_state, StateData};

handle_event(info, {ssl, Socket, Packet}, #state { socket = Socket, continuation = Continuation } = StateData) ->
    %% Our peer have received a data packet.
    Size = byte_size(Packet),
    lager:debug("Received packet: ~w (~b)", [Packet, Size]),

    %% Notify the bandwidth measuring system of the size of our packet.
    talla_core_bandwidth:bytes_read(Size),

    %% Notify the rate-limiting system of the size of the packet.
    NewReceiveLimit = talla_or_limit:recv(Size),

    %% Update our StateData.
    NewStateData = StateData#state {
        receive_limit = NewReceiveLimit,
        continuation  = <<Continuation/binary, Packet/binary>>
    },

    %% Ask our state machine to try to decode packets as its next event.
    {keep_state, NewStateData, [{next_event, internal, decode_packet}]};

handle_event(info, {ssl_closed, Socket}, #state { socket = Socket } = StateData) ->
    %% Our peer's socket was closed. Stop our peer process.
    lager:notice("Connection closed"),

    {stop, normal, StateData};

handle_event(info, {ssl_error, Socket, Reason}, #state { socket = Socket } = StateData) ->
    %% Our peer's socket was moved to an erroneous state. Stop our peer
    %% process.
    lager:warning("Connection closed with an error: ~p", [Reason]),

    {stop, {ssl_error, Reason}, StateData};

handle_event(internal, decode_packet, #state { continuation     = Continuation,
                                               protocol_version = ProtocolVersion,
                                               receive_context  = ReceiveContext,
                                               last_cell_timer  = LastCellTimer } = StateData) ->

    %% Our peer have received data that needs to be decoded by the cell decoder.
    case onion_cell:decode(ProtocolVersion, Continuation) of
        {ok, #{ command := Command,
                circuit := CircuitID,
                packet  := Packet } = Cell, NewContinuation} ->
            %% We succesfully decoded a cell. We inject an event containing the
            %% decoded cell as {internal, {cell, Cell}} and asks the state
            %% machine to call our current state function with it as an
            %% argument.
            %%
            %% Since we only decoded one cell here, we have to also inject
            %% another {internal, decode_packet} to be executed *after* our
            %% state function have handled the succesfully decoded cell. This
            %% is done to ensure that if the remote peer send multiple frames
            %% after each other that we will decode them in order without
            %% having to wait for next time we receive a packet.
            %%
            %% We could avoid this by having each state function return
            %% [{next_event, internal, decode_packet}], but it seems nicer for
            %% the protocol handling code this way.
            lager:info("(v~b) -> ~p (CircuitID: ~b)", [ProtocolVersion, Command, CircuitID]),

            %% Update our StateData.
            NewStateData = StateData#state {
                continuation       = NewContinuation,
                receive_context    = update_context(ReceiveContext, Packet),
                last_cell_received = erlang:system_time(),
                last_cell_timer    = restart_cell_timer(LastCellTimer)
            },

            %% Inject our cell and decode_packet event.
            {keep_state, NewStateData, [{next_event, internal, {cell, Cell}},
                                        {next_event, internal, decode_packet}]};

        {error, insufficient_data} ->
            %% We don't have enough data to decode a cell, continue as is.
            %%
            %% FIXME(ahf): Handle too large continuation and/or a timeout of
            %%             last-succesfully-decoded-cell?
            {keep_state, StateData};

        {error, _} = Error ->
            %% We received an error from the cell decoder. Stop our peer.
            {stop, Error, StateData}
    end;

handle_event(info, {'EXIT', Pid, normal}, #state { receive_limit = Pid } = StateData) ->
    %% We trapped an exit from our receive_limit process from the
    %% rate-limiting system. This can safely be ignored.
    {keep_state, StateData};

handle_event(info, cell_timeout, StateData) ->
    %% Handle that we haven't received a cell in a certain period of time.
    %% FIXME(ahf): Implement.
    {keep_state, StateData};

handle_event({call, From}, create_circuit, #state { circuits = Circuits } = StateData) ->
    case create_circuit_id(StateData) of
        {ok, CircuitID} ->
            {ok, Circuit} = start_circuit(CircuitID),

            lager:notice("Creating new circuit: ~p (~p)", [CircuitID, Circuit]),

            %% Update our state.
            NewStateData = StateData#state {
                circuits = maps:put(CircuitID, Circuit, Circuits)
            },

            %% Reply with a reference to the newly created circuit process.
            gen_statem:reply(From, {ok, Circuit}),

            {keep_state, NewStateData};

        {error, _} = Error ->
            lager:warning("Unable to create new circuit: currently allocated circuits: ~b", [maps:size(Circuits)]),

            gen_statem:reply(From, Error),

            {keep_state, StateData}
    end;

handle_event(EventType, EventContent, StateData) ->
    %% Looks like none of the above handlers was able to handle this message.
    %% Continue with the current state and hope for the best, but emit a
    %% warning before continuing.
    lager:warning("Unhandled peer event: ~p (Type: ~p)", [EventContent, EventType]),
    {keep_state, StateData}.

%% ----------------------------------------------------------------------------
%% Utility Functions.
%% ----------------------------------------------------------------------------

%% This function returns the callback method used by gen_statem. Look at
%% gen_statem's documentation for further information.
-spec callback_mode() -> gen_statem:callback_mode().
callback_mode() ->
    state_functions.

%% @private
%% Notify the Erlang runtime that we are ready to receive more data on a given
%% socket.
-spec activate_socket(Socket) -> ok
    when
        Socket :: ssl:sslsocket().
activate_socket(Socket) ->
    ssl:setopts(Socket, [{active, once}]).

%% @private
%% Erlang doesn't have an API to get the certificate served by our listening
%% TLS socket, to one of our incoming clients, once the client have connected.
%% As a solution to this, we have made talla_or_tls send a {certificate, Cert}
%% message to us with the information needed.
-spec server_certificate() -> {ok, Certificate} | {error, Reason}
    when
        Certificate :: public_key:der_encoded(),
        Reason      :: term().
server_certificate() ->
    receive
        {certificate, Certificate} ->
            {ok, Certificate}
    after 5000 ->
            {error, timeout}
    end.

%% @private
%% Update the send or receive context (if it is still needed to be updated).
-spec update_context(Context, Packet) -> NewContext
    when
        Context    :: binary() | {final, binary()} | undefined,
        Packet     :: binary(),
        NewContext :: Context.
update_context(undefined, _Packet) ->
    undefined;

update_context({final, Context}, _Packet) ->
    {final, Context};

update_context(Context, Packet) ->
    case Context of
        {sha256, _} = Context ->
            crypto:hash_update(Context, Packet);

        % pre-OTP 19.2 behaviour
        Context when is_binary(Context) ->
            crypto:hash_update(Context, Packet);

        _ ->
            Context
    end.

%% @private
%% Internal helper function to send a message from within our peer.
-spec send_internal(Cell, StateData) -> NewSendContext
    when
        Cell           :: onion_cell:t(),
        StateData      :: state(),
        NewSendContext :: binary().
send_internal(#{ command := Command,
                 circuit := CircuitID } = Cell, #state { send_process     = SendProcess,
                                                         send_context     = SendContext,
                                                         protocol_version = ProtocolVersion}) ->
    %% Encode the cell to a binary packet and enqueue it to our send process.
    {ok, Packet} = onion_cell:encode(ProtocolVersion, Cell),

    %% Log cell information.
    lager:info("(v~b) <- ~p (CircuitID: ~b)", [ProtocolVersion, Command, CircuitID]),

    %% Enqueue packet.
    talla_or_peer_send:enqueue(SendProcess, Packet),

    %% Update our StateData's send_context if necessary.
    update_context(SendContext, Packet).

%% @private
%% Get the IP address of a peer as a string.
-spec ip_address(Socket) -> inet:ip_address()
    when
        Socket :: ssl:sslsocket().
ip_address(Socket) ->
    {ok, {Address, _Port}} = ssl:peername(Socket),
    Address.

%% @private
%% Get the Port of a peer as an integer.
-spec port_number(Socket) -> inet:port_number()
    when
        Socket :: ssl:sslsocket().
port_number(Socket) ->
    {ok, {_Address, Port}} = ssl:peername(Socket),
    Port.

%% @private
%% Get link certificate.
-spec link_certificate() -> public_key:der_encoded().
link_certificate() ->
    {_, Certificate} = talla_or_tls_manager:link_certificate(),
    Certificate.

%% @private
%% Get ID certificate.
-spec identity_certificate() -> public_key:der_encoded().
identity_certificate() ->
    {_, Certificate} = talla_or_tls_manager:id_certificate(),
    Certificate.

%% @private
%% Start the cell timer.
-spec start_cell_timer() -> reference().
start_cell_timer() ->
    erlang:send_after(?CELL_TIMEOUT, self(), cell_timeout).

%% @private
%% Stop the cell timer.
-spec stop_cell_timer(Timer) -> non_neg_integer() | false
    when
        Timer :: reference().
stop_cell_timer(Timer) ->
    erlang:cancel_timer(Timer).

%% @private
%% Restart the cell timer.
-spec restart_cell_timer(OldTimer) -> NewTimer
    when
        OldTimer :: reference(),
        NewTimer :: reference().
restart_cell_timer(OldTimer) ->
    stop_cell_timer(OldTimer),
    start_cell_timer().

%% @private
%% Initialize our state.
-spec state(Socket) -> state()
    when
        Socket :: ssl:sslsocket().
state(Socket) ->
    %% Start our sending process. Our sending process is needed because calling
    %% ssl:send/2 might block and we want this server to be as unblocking as
    %% possible.
    {ok, SendProcess} = talla_or_peer_send:start_link(Socket),

    %% Our initial state.
    #state {
        socket             = Socket,
        receive_limit      = talla_or_limit:recv(1),
        send_process       = SendProcess,
        send_context       = crypto:hash_init(sha256),
        receive_context    = crypto:hash_init(sha256),
        last_cell_received = erlang:system_time(),
        last_cell_timer    = start_cell_timer()
    }.

%% @private
%% Generate a CircuitID.
-spec create_circuit_id(State) -> {ok, CircuitID} | {error, Reason}
    when
        State     :: state(),
        CircuitID :: non_neg_integer(),
        Reason    :: Reason.
create_circuit_id(#state { protocol_version = 4,
                           direction        = Direction,
                           circuits         = Circuits }) ->
    create_circuit_id(4, Direction =:= outbound, Circuits, ?CIRCUIT_ID_CREATION_ATTEMPTS).

%% @private
create_circuit_id(_, _, _, 0) ->
    {error, not_found};

create_circuit_id(ProtocolVersion, MSB, Circuits, Tries) ->
    {ok, CircuitID} = onion_circuit:id(ProtocolVersion, MSB),
    case maps:get(CircuitID, Circuits, not_found) of
        not_found ->
            {ok, CircuitID};

        _ ->
            create_circuit_id(ProtocolVersion, MSB, Circuits, Tries - 1)
    end.

%% @private
-spec start_circuit(CircuitID) -> {ok, Circuit} | {error, Reason}
    when
        CircuitID :: onion_circuit:id(),
        Circuit   :: talla_or_circuit:t(),
        Reason    :: term().
start_circuit(CircuitID) ->
    case talla_or_circuit_pool:start_circuit(self(), CircuitID) of
        {ok, Circuit} = Result ->
            erlang:monitor(process, Circuit),
            Result;

        {error, _} = Error ->
            Error
    end.

%% @private
-spec inbound_cert_validation(Certs) -> ok
    when
        Certs :: [cert()].
inbound_cert_validation(Certs) ->
    %% Check that the correct certs are in the payload
    [{2, IdCert}, {3, AuthCert}] = sort_certs(Certs),

    % Certificate validation performed on both inbound and outbound handshakes
    base_validation(IdCert, AuthCert),

    % Check that key in the auth cert have the correct format
    {ok, AuthKey} = onion_x509:public_key(AuthCert),
    true = (1024 =:= onion_rsa:key_size(AuthKey)),
    ok.

%% @private
-spec outbound_cert_validation(Certs, SSLCert) -> ok
      when
          Certs :: [cert()],
          SSLCert :: der_encoded().
outbound_cert_validation(Certs, SSLCert) ->
    %% Check that the correct certs are in the payload
    [{1, LinkCert}, {2, IdCert}] = sort_certs(Certs),

    % Certificate validation performed on both inbound and outbound handshakes
    base_validation(IdCert, LinkCert),

    % Check that pubkey from the TLS certificate is equal to the pubkey of the Link certificate
    true = equal_keys(SSLCert, LinkCert),
    ok.

%% @private
-spec sort_certs(Certs) -> Certs
    when
        Certs :: [cert()].
sort_certs([#{ type := Type1, cert := Cert1 }, #{ type := Type2, cert := Cert2 }]) ->
    lists:keysort(1, [{Type1, Cert1}, {Type2, Cert2}]).

%% @private
-spec base_validation(IdCert, OtherCert) -> ok
    when
        IdCert :: der_encoded(),
        OtherCert :: IdCert.
base_validation(IdCert, OtherCert) ->
    % Check that key in the ID certificate have the correct format
    {ok, IdKey} = onion_x509:public_key(IdCert),
    true = (1024 =:= onion_rsa:key_size(IdKey)),

    % Verify signatures
    true = onion_x509:verify(OtherCert, IdKey),
    true = onion_x509:verify(IdCert, IdKey),
    true = onion_x509:is_self_signed(IdCert),

    % Validate validUntil and validAfter for both certificates
    true = validate_timestamps(IdCert),
    true = validate_timestamps(OtherCert),
    ok.

%% @private
-spec equal_keys(Cert1, Cert2) -> true | false
    when
        Cert1 :: der_encoded(),
        Cert2 :: Cert1.
equal_keys(Cert1, Cert2) ->
    {ok, Key1} = onion_x509:public_key(Cert1),
    {ok, Key2} = onion_x509:public_key(Cert2),
    Key1 =:= Key2.

%% @private
-spec validate_timestamps(Cert) -> true | false
    when
        Cert :: der_encoded().
validate_timestamps(Cert) ->
    Now = onion_time:epoch(),
    ValidAfter = onion_time:to_epoch(onion_x509:not_before(Cert)),
    ValidUntil = onion_time:to_epoch(onion_x509:not_after(Cert)),
    (ValidAfter < Now) and (Now < ValidUntil).

%% @private
-spec validate_authenticate_cell(Authenticate, StateData) -> ok
    when
        Authenticate :: onion_cell:auth(),
        StateData    :: state().
validate_authenticate_cell(#{ client_id_key_digest := ClientKeyDigest,
                              server_id_key_digest := ServerKeyDigest,

                              server_log           := ServerLog,
                              client_log           := ClientLog,

                              tls_cert_digest      := TLSCertDigest,
                              tls_secrets_digest   := TLSSecretsDigest,
                              random_bytes         := RandomBytes,
                              signature            := Signature}, #state { send_context    = {final, SendContext},
                                                                           receive_context = {final, ReceiveContext},
                                                                           certs_payload   = Certs,
                                                                           session_info    = SessionInformation}) ->
    % Create Auth payload from our own data
    [{2, IdCert}, {3, AuthCert}] = sort_certs(Certs),
    {ok, ClientAuthPublicKey} = onion_x509:public_key(AuthCert),
    {ok, ClientIdentityPublicKey} = onion_x509:public_key(IdCert),

    OurAuthPayload = onion_authenticate_cell:create_payload(#{
            client_identity_public_key => ClientIdentityPublicKey,
            server_identity_public_key => talla_core_identity_key:public_key(),

            client_log => ReceiveContext,
            server_log => SendContext,

            server_certificate => onion_ssl_session:certificate(SessionInformation),
            ssl_session        => SessionInformation
        }, RandomBytes),

    %% Assemble auth payload that we've received from the peer
    PeerAuthPayload = <<"AUTH0001",
                        ClientKeyDigest/binary,
                        ServerKeyDigest/binary,
                        ServerLog/binary,
                        ClientLog/binary,
                        TLSCertDigest/binary,
                        TLSSecretsDigest/binary,
                        RandomBytes/binary>>,

    %% Compare the two payloads and verify they are equal
    OurAuthPayloadHash = crypto:hash(sha256, OurAuthPayload),
    PeerAuthPayloadHash = crypto:hash(sha256, PeerAuthPayload),
    true = PeerAuthPayloadHash =:= OurAuthPayloadHash,

    %% Verify Peers signature of auth payload
    true = PeerAuthPayloadHash =:= onion_rsa:public_decrypt(Signature, ClientAuthPublicKey, rsa_pkcs1_padding),
    ok.
