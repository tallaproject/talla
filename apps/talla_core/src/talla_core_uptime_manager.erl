%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Server for keeping uptime information.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core_uptime_manager).

%% Behaviour.
-behaviour(gen_server).

%% API.
-export([start_link/0, start_timestamp/0, uptime/0]).

%% Generic Server Behaviour.
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Types.
-record(state, {
          system_start_timestamp :: erlang:timestamp()
         }).

-define(SERVER, ?MODULE).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec start_timestamp() -> non_neg_integer().
start_timestamp() ->
    gen_server:call(?SERVER, start_timestamp).

-spec uptime() -> non_neg_integer().
uptime() ->
    gen_server:call(?SERVER, uptime).

%% @private
init([]) ->
    {ok, #state {
            system_start_timestamp = onion_time:epoch()
           }}.

%% @private
handle_call(uptime, _From, #state { system_start_timestamp = Timestamp } = State) ->
    Now = onion_time:epoch(),
    {reply, Now - Timestamp, State};

handle_call(start_timestamp, _From, #state { system_start_timestamp = Timestamp } = State) ->
    {reply, Timestamp, State};

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
