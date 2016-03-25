%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Bandwidth statistics.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core_bandwidth).

%% API.
-export([start_link/0,

         bytes_read/1,
         bytes_written/1
        ]).

%% Generic Server Callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-define(TABLE, ?MODULE).

%% How long is a period?
-define(PERIOD, (15 * 60)). %% 900.

%% How long should we store data?
-define(HISTORY, (24 * 60 * 60)). %% 86400 (one day)

-define(DELETE_MATCH_SPEC(T), [{{{'$1', '$2'}, '$3'},
                                [{'=/=', '$1', meta}],
                                [{'<', '$2', T - ?HISTORY}]}]).

-record(state, {}).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec bytes_read(Bytes) -> ok
    when
        Bytes :: non_neg_integer().
bytes_read(Bytes) when is_integer(Bytes), Bytes >= 0 ->
    T = current_period(),
    ets:update_counter(?TABLE, {bytes_read, T}, Bytes, {{bytes_read, T}, 0}),
    ok.

-spec bytes_written(Bytes) -> ok
    when
        Bytes :: non_neg_integer().
bytes_written(Bytes) when is_integer(Bytes), Bytes >= 0 ->
    T = current_period(),
    ets:update_counter(?TABLE, {bytes_written, T}, Bytes, {{bytes_written, T}, 0}),
    ok.

%% @private
init(_Args) ->
    ets:new(?TABLE, [ordered_set, public, named_table, {read_concurrency, true}, {write_concurrency, true}]),
    bump_period(),
    collect_garbage(),
    {ok, #state {}}.

%% @private
handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast: ~p", [Message]),
    {noreply, State}.

%% @private
handle_info(bump_period, State) ->
    bump_period(),
    {noreply, State};

handle_info(collect_garbage, State) ->
    collect_garbage(),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

%% @private
-spec bump_period() -> ok.
bump_period() ->
    T = onion_time:epoch(),
    ets:insert(?TABLE, [{{meta, current_period}, T}]),
    erlang:send_after(timer:seconds(?PERIOD), self(), bump_period).

%% @private
-spec collect_garbage() -> ok.
collect_garbage() ->
    T = onion_time:epoch(),
    DeleteCount = ets:select_delete(?TABLE, ?DELETE_MATCH_SPEC(T)),
    case DeleteCount of
        0 ->
            ok;

        DeleteCount ->
            lager:debug("Garbage collected ~b bandwidth counters", [DeleteCount])
    end,
    erlang:send_after(timer:seconds(?HISTORY), self(), collect_garbage).

%% @private
-spec current_period() -> non_neg_integer().
current_period() ->
    [{_, T}] = ets:lookup(?TABLE, {meta, current_period}),
    T.
