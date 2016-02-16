%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Consensus Fetcher.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_dir_consensus_fetcher).
-behaviour(gen_server).

%% API.
-export([start_link/0]).

%% Generic Server Behaviour.
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Types.
-record(state, {
            timer_ref    :: reference(),
            http_ref     :: reference(),
            continuation :: binary()
        }).

-define(SERVER, ?MODULE).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @private
init([]) ->
    {ok, #state { timer_ref = start_timer(2) }}.

%% @private
handle_call(Request, From, State) ->
    lager:warning("Unhandled call '~p' from ~p (State: ~p)", [Request, From, State]),
    {reply, ok, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast '~p' (State: ~p)", [Message, State]),
    {noreply, State}.

%% @private
handle_info({timeout, Timer, fetch}, #state { timer_ref = Timer } = State) ->
    Authorities = talla_core_config:authorities(),
    #{ address := Address, dir_port := DirPort } = onion_random:pick(Authorities),
    URL = onion_string:format("http://~s:~b/tor/status-vote/current/consensus/~s.z", [inet:ntoa(Address), DirPort, talla_dir_http:authorities_url_path()]),
    lager:notice("Downloading consensus from ~s", [URL]),
    {ok, Ref} = hackney:get(URL, [], <<>>, [async]),
    {noreply, State#state { http_ref = Ref, continuation = <<>> }};

handle_info({hackney_response, HttpRef, {status, Status, Reason}}, #state { http_ref = HttpRef } = State) ->
    lager:info("Consensus download status: ~s (~b)", [Reason, Status]),
    {noreply, State};

handle_info({hackney_response, HttpRef, {headers, Headers}}, #state { http_ref = HttpRef } = State) ->
    lager:info("Consensus download headers: ~p", [Headers]),
    {noreply, State};

handle_info({hackney_response, HttpRef, done}, #state { http_ref = HttpRef, continuation = Continuation } = State) ->
    lager:info("Consensus download finished"),

    Z = zlib:open(),
    zlib:inflateInit(Z),
    Data = iolist_to_binary(zlib:inflate(Z, Continuation)),
    zlib:close(Z),

    {ok, Items} = onion_document:decode(Data),
    lists:foreach(fun (Item) -> lager:notice("Item: ~p", [Item]) end, Items),
    {noreply, State#state { timer_ref = start_timer(10000) }};

handle_info({hackney_response, HttpRef, Packet}, #state { http_ref = HttpRef, continuation = Continuation } = State) when is_binary(Packet) ->
    lager:info("Consensus download chunk: ~b", [byte_size(Packet)]),
    {noreply, State#state { continuation = <<Continuation/binary, Packet/binary>> }};

handle_info(Info, State) ->
    lager:warning("Unhandled info '~p' (State: ~p)", [Info, State]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

%% @private
-spec start_timer(Time) -> reference()
    when
        Time :: integer().
start_timer(Time) ->
    erlang:start_timer(Time, self(), fetch, []).
