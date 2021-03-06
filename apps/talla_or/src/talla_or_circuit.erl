%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Onion Router Circuit.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_circuit).
-behaviour(gen_statem).

%% API.
-export([start_link/2,
         stop/1,

         dispatch/2
        ]).

%% States.
-export([create/3,
         relay/3
        ]).

%% Generic State Machine Callbacks.
-export([init/1,
         code_change/4,
         terminate/3,
         callback_mode/0
        ]).

%% Types.
-export_type([t/0]).

-type t() :: pid().

-record(state, {
        parent  :: talla_or_peer:t(),
        sibling :: t(),

        %% The ID of our circuit.
        circuit :: non_neg_integer(),

        %% Key material used by this circuit.
        forward_hash    :: binary(),
        forward_aes_key :: term(),

        backward_hash    :: binary(),
        backward_aes_key :: term(),

        %% The number of relay_early cell's that have passed through
        %% this circuit.
        relay_early_count = 0 :: non_neg_integer(),

        extend_data :: binary()
    }).

-type state() :: #state {}.

%% ----------------------------------------------------------------------------
%% API.
%% ----------------------------------------------------------------------------

-spec start_link(Peer, CircuitID) -> {ok, Circuit} | {error, Reason}
    when
        Peer      :: talla_or_peer:t(),
        CircuitID :: onion_circuit:id(),
        Circuit   :: t(),
        Reason    :: term().
start_link(Peer, CircuitID) ->
    gen_statem:start_link(?MODULE, [Peer, CircuitID], []).

-spec stop(Circuit) -> ok
    when
        Circuit :: t().
stop(Circuit) ->
    gen_statem:stop(Circuit).

-spec dispatch(Circuit, Cell) -> ok
    when
        Circuit :: t(),
        Cell    :: onion_cell:t().
dispatch(Circuit, Cell) ->
    gen_statem:cast(Circuit, {dispatch, self(), Cell}).

%% ----------------------------------------------------------------------------
%% Protocol States.
%% ----------------------------------------------------------------------------

%% @private
-spec create(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
create(internal, {cell, #{ command := create2,
                           circuit := Circuit,
                           payload := #{ data := <<Fingerprint:20/binary,
                                                   NTorPublicKey:32/binary,
                                                   PublicKey:32/binary>>
                                        }}}, StateData) ->
    %% We received a create2 cell and haven't already gotten a Circuit ID.
    %% Update our state and reply to the create request.
    lager:notice("Creating new relay: ~b", [Circuit]),

    %% Reply.
    case ntor_handshake(Fingerprint, NTorPublicKey, PublicKey) of
        {ok, HandshakeState} ->
            %% Send created2 response.
            send(onion_cell:created2(Circuit, maps:get(response, HandshakeState))),

            %% Update our state.
            NewStateData = StateData#state {
                circuit          = Circuit,
                forward_aes_key  = maps:get(forward_aes_key, HandshakeState),
                backward_aes_key = maps:get(backward_aes_key, HandshakeState),
                forward_hash     = maps:get(forward_hash, HandshakeState),
                backward_hash    = maps:get(backward_hash, HandshakeState)
            },

            %% Continue to the normal loop.
            {next_state, relay, NewStateData};

        {error, _} = Error ->
            {stop, Error, StateData}
    end;

create(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

-spec relay(EventType, EventContent, StateData) -> gen_statem:handle_event_result()
    when
        EventType    :: gen_statem:event_type(),
        EventContent :: term(),
        StateData    :: state().
relay(internal, {cell, #{ command := destroy,
                          circuit := CircuitID }}, StateData) ->
    lager:warning("Tearing down circuit: ~p", [CircuitID]),
    {keep_state, StateData};

relay(internal, {cell, #{ command := relay_early,
                          circuit := Circuit,
                          payload := #{ data := Payload } }}, #state { circuit           = Circuit,
                                                                       forward_aes_key   = FAESKey,
                                                                       forward_hash      = FHash,
                                                                       relay_early_count = RelayEarlyCount } = StateData) ->
    case decrypt(FAESKey, FHash, Payload) of
        {recognized, NewAESKey, #{ command := relay_extend2,
                                   stream  := 0,
                                   payload := #{ data  := Data,
                                                 type  := ntor,
                                                 links := [#{ type    := tls_over_ipv4,
                                                              payload := {Address, Port} } | _] }}} ->
            talla_or_peer_manager:connect(Address, Port),

            %% Update our state.
            NewStateData = StateData#state {
                relay_early_count = RelayEarlyCount + 1,

                %% FIXME(ahf): Better name.
                extend_data = Data
            },

            {keep_state, NewStateData};

        relay ->
            lager:warning("Relay"),
            {keep_state, StateData};

        NoMatch ->
            lager:warning("No match: ~p", [NoMatch]),
            {keep_state, StateData}
    end;

relay(info, {peer_connected, _, Peer}, #state { circuit     = CircuitID,
                                                extend_data = ExtendData } = StateData) ->
    lager:warning("Peer connected: ~p", [Peer]),

    %% Update our state.
    case talla_or_peer:create_circuit(Peer) of
        {ok, Circuit} ->
            lager:warning("Sibling: ~p", [Circuit]),

            %% Update our state.
            NewStateData = StateData#state {
                sibling = Circuit
            },

            {keep_state, NewStateData};

        {error, Reason} ->
            lager:warning("Unable to create circuit"),

            %% FIXME(ahf): terminate ourself.

            {keep_state, StateData}
    end;

relay(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

await_peer_connect(EventType, EventContent, StateData) ->
    {keep_state, StateData, [postpone]}.

%% ----------------------------------------------------------------------------
%% Generic State Machine Callbacks.
%% ----------------------------------------------------------------------------

%% @private
%% This function is used to initialize our state machine.
init([Peer, CircuitID]) ->
    %% We want to trap exit signals.
    process_flag(trap_exit, true),

    %% Our initial state.
    StateData = #state {
        circuit = CircuitID,
        parent  = Peer
    },

    %% We start in the create state.
    {ok, create, StateData}.

%% @private
%% Call when we are doing a code change (live upgrade/downgrade).
-spec code_change(Version, StateName, StateData, Extra) -> {NewCallbackMode, NewStateName, NewStateData}
    when
        Version         :: {down, term()} | term(),
        StateName       :: atom(),
        StateData       :: state(),
        Extra           :: term(),
        NewCallbackMode :: atom(),
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
terminate(_Reason, _StateName, _StateData) ->
    ok.

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
handle_event(internal, {cell_sent, _Cell}, StateData) ->
    %% Ignore this.
    {keep_state, StateData};

handle_event(cast, {dispatch, Source, #{ command := Command,
                                         circuit := Circuit } = Cell}, #state { circuit = Circuit,
                                                                                parent  = Parent,
                                                                                sibling = Sibling } = StateData) ->
    case Source of
        Parent ->
            lager:notice("Relay from parent: ~p (Circuit: ~b)", [Command, Circuit]),
            ok;

        Sibling ->
            lager:notice("Relay from sibling: ~p (Circuit: ~b)", [Command, Circuit]),
            ok;

        _ ->
            lager:warning("Relay from unknown (~p): ~p (Circuit: ~b)", [Source, Command, Circuit]),
            ok
    end,
    {keep_state, StateData, [{next_event, internal, {cell, Cell}}]};

handle_event(cast, {send, #{ command := Command,
                             circuit := Circuit } = Cell}, #state { parent = Parent } = StateData) ->
    lager:notice("Relay Response: ~p (Circuit: ~b)", [Command, Circuit]),
    talla_or_peer:send(Parent, Cell),
    {keep_state, StateData, [{next_event, internal, {cell_sent, Cell}}]};

handle_event(EventType, EventContent, StateData) ->
    %% Looks like none of the above handlers was able to handle this message.
    %% Continue with the current state and hope for the best, but emit a
    %% warning before continuing.
    lager:warning("Unhandled circuit event: ~p (Type: ~p)", [EventContent, EventType]),
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
%% Update the send or receive context (if it is still needed to be updated).
-spec update_context(Context, Packet) -> NewContext
    when
        Context    :: binary(),
        Packet     :: binary(),
        NewContext :: Context.
update_context(Context, Packet) ->
    case Context of
        Context when is_binary(Context) ->
            crypto:hash_update(Context, Packet);

        _ ->
            Context
    end.

%% @private
-spec send(Circuit, Cell) -> ok
    when
        Circuit :: t(),
        Cell    :: onion_cell:t().
send(Circuit, Cell) ->
    gen_statem:cast(Circuit, {send, Cell}).

%% @private
-spec send(Cell) -> ok
    when
        Cell :: onion_cell:t().
send(Cell) ->
    send(self(), Cell).

%% @private
%% Check if a given set of keys matches ours.
ntor_handshake(Fingerprint, PublicKey, ClientPublicKey) ->
    OurFingerprint = talla_core_identity_key:fingerprint(),
    OurPublicKey   = talla_core_ntor_key:public_key(),
    case Fingerprint =:= OurFingerprint andalso PublicKey =:= OurPublicKey of
        true ->
            {Response, <<FHash:20/binary, BHash:20/binary,
                         FKey:16/binary, BKey:16/binary>>} = talla_core_ntor_key:server_handshake(ClientPublicKey, 72),

            {ok, #{ response => Response,

                    forward_hash  => crypto:hash_update(crypto:hash_init(sha), FHash),
                    backward_hash => crypto:hash_update(crypto:hash_init(sha), BHash),

                    forward_aes_key  => onion_aes:init(FKey),
                    backward_aes_key => onion_aes:init(BKey) }};

        false ->
            {error, key_mismatch}
    end.

%% @private
digest(Context, Data) ->
    <<Start:5/binary, _:32/integer, Rest/binary>> = Data,
    <<Result:4/binary, _/binary>> = crypto:hash_final(crypto:hash_update(Context, <<Start/binary, 0:32/integer, Rest/binary>>)),
    Result.

%% @private
decrypt(AESKey, Context, Payload) ->
    {NewAESKey, Message} = onion_aes:decrypt(AESKey, Payload),
    MessageDigest = digest(Context, Message),
    case Message of
        <<Command:8/integer, 0:16/integer, StreamID:16/integer, MessageDigest:4/binary, Length:16/integer, Packet:Length/binary, _/binary>> ->
            {recognized, NewAESKey, #{ command => decode_command(Command),
                                       stream  => StreamID,
                                       payload => decode_relay_packet(Command, Packet) } };

        _ ->
            relay
    end.

%% @private
decode_relay_packet(14, Payload) ->
    %% RELAY_EXTEND2
    decode_extend2_cell(Payload);

decode_relay_packet(_, _) ->
    unknown.

decode_htype(0) ->
    tap;
decode_htype(2) ->
    ntor;
decode_htype(_) ->
    unknown.

decode_link_type(0) ->
    tls_over_ipv4;
decode_link_type(1) ->
    tls_over_ipv6;
decode_link_type(2) ->
    legacy_identity;
decode_link_type(_) ->
    unknown.

decode_command(1) ->
    relay_begin;
decode_command(2) ->
    relay_data;
decode_command(3) ->
    relay_end;
decode_command(4) ->
    relay_connected;
decode_command(5) ->
    relay_sendme;
decode_command(6) ->
    relay_extend;
decode_command(7) ->
    relay_extended;
decode_command(8) ->
    relay_truncate;
decode_command(9) ->
    relay_truncated;
decode_command(10) ->
    relay_drop;
decode_command(11) ->
    relay_resolve;
decode_command(12) ->
    relay_resolved;
decode_command(13) ->
    relay_begin_dir;
decode_command(14) ->
    relay_extend2;
decode_command(15) ->
    relay_extended2;
decode_command(X) ->
    {unknown_command, X}.

decode_extend2_cell(<<NSpec:8/integer, Rest/binary>>) ->
    {Links, <<HType:16/integer, HLen:16/integer, HData:HLen/bytes, _/binary>>} = decode_extend2_link_specifiers(Rest, [], NSpec),
    #{ type => decode_htype(HType), data => HData, links => Links }.

decode_extend2_link_specifiers(Rest, Result, 0) ->
    {lists:reverse(Result), Rest};

decode_extend2_link_specifiers(<<LSType:8/integer, LSLen:8/integer, LSpec:LSLen/binary, Rest/binary>>, Result, NSpec) ->
    decode_extend2_link_specifiers(Rest, [#{ type => decode_link_type(LSType), payload => decode_extend2_link_specifier(LSType, LSpec) } | Result], NSpec - 1).

decode_extend2_link_specifier(0, <<A:8/integer, B:8/integer, C:8/integer, D:8/integer, Port:16/integer>>) ->
    {{A, B, C, D}, Port};

decode_extend2_link_specifier(1, <<A:16/integer, B:16/integer, C:16/integer, D:16/integer, E:16/integer, F:16/integer, G:16/integer, H:16/integer, Port:16/integer>>) ->
    {{A, B, C, D, E, F, G, H}, Port};

decode_extend2_link_specifier(2, <<Fingerprint:20/binary, _/binary>>) ->
    Fingerprint.
