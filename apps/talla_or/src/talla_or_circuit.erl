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
-behaviour(gen_fsm).

%% API.
-export([start_link/2,
         incoming_cell/2
        ]).

%% States.
-export([create/2,
         created/2
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
        %% The CircuitID given from the Peer.
        circuit_id    :: non_neg_integer(),

        %% The Peer.
        peer          :: pid(),

        %% Forward AES state and rolling hash.
        forward_key   :: term(),
        forward_hash  :: term(),

        %% Backward AES state and rolling hash.
        backward_key  :: term(),
        backward_hash :: term(),

        %% RELAY_EARLY count.
        relay_early_count :: non_neg_integer()
    }).

-define(CELL(Cell), {incoming_cell, Cell}).

-define(CELL(CircuitID, Command), ?CELL(#{ circuit := CircuitID,
                                           command := Command } = Cell)).
-define(CELL(CircuitID, Command, Payload), ?CELL(#{ circuit := CircuitID,
                                                    command := Command,
                                                    payload := Payload } = Cell)).

-spec start_link(CircuitID, Peer) -> {ok, Pid} | {error, Reason}
    when
        CircuitID :: non_neg_integer(),
        Peer      :: pid(),
        Pid       :: pid(),
        Reason    :: term().
start_link(CircuitID, Peer) when is_integer(CircuitID) ->
    gen_fsm:start_link(?MODULE, [CircuitID, Peer], []).

-spec incoming_cell(Pid, Cell) -> ok
    when
        Pid  :: pid(),
        Cell :: term().
incoming_cell(Pid, Cell) ->
    gen_fsm:send_event(Pid, {incoming_cell, Cell}).

%% @private
%% FIXME(ahf): Move data parsing to onion_cell.
create(?CELL(CircuitID, create2, #{ type := ntor, data := <<Fingerprint:20/binary, NTorPublicKey:32/binary, ClientPublicKey:32/binary>> }), #state { circuit_id = CircuitID, peer = Peer } = State) ->
    RouterFingerprint   = talla_core_identity_key:fingerprint(),
    RouterNTorPublicKey = talla_core_ntor_key:public_key(),
    case {Fingerprint, NTorPublicKey} of
        {RouterFingerprint, RouterNTorPublicKey} ->
            {Response, KeyMaterial} = talla_core_ntor_key:server_handshake(ClientPublicKey, 72),
            talla_or_peer_fsm:outgoing_cell(Peer, onion_cell:created2(CircuitID, Response)),
            <<ForwardHash:20/binary, BackwardHash:20/binary, ForwardKey:16/binary, BackwardKey:16/binary>> = KeyMaterial,
            {next_state, created, State#state { forward_hash  = crypto:hash_update(crypto:hash_init(sha), ForwardHash),
                                                forward_key   = onion_aes:init(ForwardKey),
                                                backward_hash = crypto:hash_update(crypto:hash_init(sha), BackwardHash),
                                                backward_key  = onion_aes:init(BackwardKey) }};
        {_, _} ->
            lager:warning("Unknown create2"),
            erlang:error(eek)
    end.

created(?CELL(CircuitID, relay_early, #{ data := Payload }), #state { relay_early_count = RelayEarlyCount,
                                                                      forward_key       = ForwardKey,
                                                                      forward_hash      = ForwardHash } = State) when RelayEarlyCount =< 8 ->
    {NewForwardKey, Data} = onion_aes:decrypt(ForwardKey, Payload),
    PayloadDigest = digest(Data, ForwardHash),
    case Data of
        <<Command:8/integer, Recognized:16/integer, StreamID:16/integer, Digest:4/binary, Length:16/integer, Packet:Length/binary, _/binary>> when Recognized =:= 0 ->
            case PayloadDigest of
                <<Digest:4/binary, _/binary>> ->
                    lager:warning("Relay: ~p -> ~p -> ~p", [Command, StreamID, Packet]),
                    {next_state, created, State#state{ relay_early_count = RelayEarlyCount + 1,
                                                       forward_key       = NewForwardKey,
                                                       forward_hash      = crypto:hash_update(ForwardHash, PayloadDigest) }};
                _ ->
                    lager:warning("Failed Digest: ~w vs ~w", [PayloadDigest, Digest]),
                    {next_state, created, State#state{ relay_early_count = RelayEarlyCount + 1,
                                                       forward_key       = NewForwardKey }}
            end;

        _ ->
            lager:warning("Failed decoding decrypted relay_early cell"),
            {next_state, created, State#state{ relay_early_count = RelayEarlyCount + 1,
                                               forward_key       = NewForwardKey }}
    end;

created(?CELL(Cell), State) ->
    lager:warning("Created: ~p", [Cell]),
    {next_state, created, State}.

%% @private
init([CircuitID, Peer]) ->
    {ok, create, #state {
            circuit_id        = CircuitID,
            peer              = Peer,
            relay_early_count = 0
        }}.

%% @private
handle_event(Request, StateName, State) ->
    lager:warning("Unhandled event: ~p", [Request]),
    {next_state, StateName, State}.

%% @private
handle_sync_event(Request, _From, StateName, State) ->
    lager:warning("Unhandled sync event: ~p", [Request]),
    {next_state, StateName, State}.

%% @private
handle_info(Info, StateName, State) ->
    lager:warning("Unhandled info: ~p", [Info]),
    {next_state, StateName, State}.

%% @private
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% @private
terminate(_Reason, _StateName, _State) ->
    ok.

%% @private
digest(Data, Context) ->
    <<A:5/binary, _:32/integer, Rest/binary>> = Data,
    crypto:hash_final(crypto:hash_update(Context, <<A/binary, 0:32/integer, Rest/binary>>)).
