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
-behaviour(gen_server).

%% API.
-export([start_link/1]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-record(state, {
        %% The CircuitID given from the Peer.
        circuit_id    :: non_neg_integer(),

        %% Forward AES state and rolling hash.
        forward_key   :: term(),
        forward_hash  :: term(),

        %% Backward AES state and rolling hash.
        backward_key  :: term(),
        backward_hash :: term(),

        %% RELAY_EARLY count.
        relay_early_count :: non_neg_integer()
    }).

-spec start_link(CircuitID) -> {ok, Pid} | {error, Reason}
    when
        CircuitID :: non_neg_integer(),
        Pid       :: pid(),
        Reason    :: term().
start_link(CircuitID) when is_integer(CircuitID) ->
    gen_server:start_link(?MODULE, [CircuitID], []).

%% @private
init([CircuitID]) ->
    {ok, #state {
            circuit_id        = CircuitID,
            relay_early_count = 0
        }}.

%% @private
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
