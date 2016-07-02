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
-export([start_link/0,
         stop/1,
         controlling_process/2,
         dispatch/2
        ]).

%% States.
-export([create/3,
         relay/3
        ]).

%% Generic State Machine Callbacks.
-export([init/1,
         code_change/4,
         terminate/3
        ]).

%% Types.
-export_type([t/0]).

-type t() :: pid().

-record(state, {
        %% Control Process.
        control_process :: pid(),

        %% The ID of our circuit.
        %% FIXME(ahf): Should be something like onion_circuit:id().
        circuit :: non_neg_integer(),

        %% Key material used by this circuit.
        forward_hash    :: binary(),
        forward_aes_key :: term(),

        backward_hash    :: binary(),
        backward_aes_key :: term(),

        %% The number of relay_early cell's that have passed through
        %% this circuit.
        relay_early_count = 0 :: non_neg_integer()
    }).

-type state() :: #state {}.

%% ----------------------------------------------------------------------------
%% API.
%% ----------------------------------------------------------------------------

-spec start_link() -> {ok, Circuit} | {error, Reason}
    when
        Circuit :: t(),
        Reason  :: term().
start_link() ->
    gen_statem:start_link(?MODULE, [], []).

-spec stop(Circuit) -> ok
    when
        Circuit :: t().
stop(Circuit) ->
    gen_statem:stop(Circuit).

%% FIXME(ahf): controlling_peer?
-spec controlling_process(Circuit, Peer) -> ok
    when
        Circuit :: t(),
        Peer    :: talla_or_peer:t().
controlling_process(Circuit, Pid) ->
    gen_statem:cast(Circuit, {controlling_process, Pid}).

-spec dispatch(Circuit, Cell) -> ok
    when
        Circuit :: t(),
        Cell    :: onion_cell:t().
dispatch(Circuit, Cell) ->
    gen_statem:cast(Circuit, {dispatch, Cell}).

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
                                        }}}, #state { circuit = undefined } = StateData) ->
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
                circuit = Circuit
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
relay(EventType, EventContent, StateData) ->
    handle_event(EventType, EventContent, StateData).

%% ----------------------------------------------------------------------------
%% Generic State Machine Callbacks.
%% ----------------------------------------------------------------------------

%% @private
%% This function is used to initialize our state machine.
init([]) ->
    %% We want to trap exit signals.
    process_flag(trap_exit, true),

    %% Our initial state.
    StateData = #state {
        forward_hash  = crypto:hash_init(sha),
        backward_hash = crypto:hash_init(sha)
    },

    %% We start in the create state.
    {callback_method(), create, StateData}.

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
    {callback_method(), StateName, StateData}.

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

handle_event(cast, {dispatch, #{ command := Command,
                                 circuit := Circuit } = Cell}, StateData) ->
    lager:notice("Relay: ~p (Circuit: ~b)", [Command, Circuit]),
    {keep_state, StateData, [{next_event, internal, {cell, Cell}}]};

handle_event(cast, {send, #{ command := Command,
                             circuit := Circuit } = Cell}, #state { control_process = ControlProcess } = StateData) ->
    lager:notice("Relay Response: ~p (Circuit: ~b)", [Command, Circuit]),
    talla_or_peer:send(ControlProcess, Cell),
    {keep_state, StateData, [{next_event, internal, {cell_sent, Cell}}]};

handle_event(cast, {controlling_process, Pid}, StateData) ->
    %% Set our control process.

    NewStateData = StateData#state {
        control_process = Pid
    },

    {keep_state, NewStateData};

handle_event(EventType, EventContent, StateData) ->
    %% Looks like none of the above handlers was able to handle this message.
    %% Continue with the current state and hope for the best, but emit a
    %% warning before continuing.
    lager:warning("Unhandled event: ~p (Type: ~p)", [EventContent, EventType]),
    {keep_state, StateData}.

%% ----------------------------------------------------------------------------
%% Utility Functions.
%% ----------------------------------------------------------------------------

%% @private
%% This function returns the callback method used by gen_statem. Look at
%% gen_statem's documentation for further information.
-spec callback_method() -> gen_statem:callback_mode().
callback_method() ->
    state_functions.

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

                    forward_hash  => FHash,
                    backward_hash => BHash,

                    forward_aes_key  => onion_aes:init(FKey),
                    backward_aes_key => onion_aes:init(BKey) }};

        false ->
            {error, key_mismatch}
    end.
