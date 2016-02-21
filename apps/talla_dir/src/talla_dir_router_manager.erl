%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Router Manager
%%%
%%% This server is responsible for announcing our onion router to the authority
%%% servers in the network.
%%%
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_dir_router_manager).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         announce/0
        ]).

%% Generic Server Behaviour.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

%% Types.
-record(state, {}).

-define(SERVER, ?MODULE).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec announce() -> ok.
announce() ->
    gen_server:cast(?SERVER, announce).

%% @private
init([]) ->
    {ok, #state {}}.

%% @private
handle_call(Request, From, State) ->
    lager:warning("Unhandled call '~p' from ~p (State: ~p)", [Request, From, State]),
    {reply, ok, State}.

%% @private
handle_cast(announce, State) ->
    {ok, SigningKey} = onion_rsa:der_encode(talla_core_identity_key:public_key()),
    {ok, OnionKey}   = onion_rsa:der_encode(talla_core_onion_key:public_key()),
    case talla_or_config:enabled() of
        true ->
            Document = onion_server_descriptor:encode(#{
                    published => calendar:now_to_universal_time(erlang:timestamp()),

                    address  => talla_or_config:address(),
                    or_port  => talla_or_config:port(),

                    bandwidth_average  => 1024,
                    bandwidth_burst    => 1024,
                    bandwidth_observed => 1024,

                    nickname => talla_or_config:nickname(),
                    contact  => talla_or_config:contact(),

                    platform => talla_core:platform(),
                    uptime   => talla_core:uptime(),

                    signing_key    => SigningKey,
                    onion_key      => OnionKey,
                    ntor_onion_key => talla_core_ntor_key:public_key()
                }),
            SignedDocument = talla_core_identity_key:sign_document(Document),
            Authorities    = talla_core_config:authorities(),
            lists:foreach(fun (#{ address := Address, dir_port := Port } = Authority) ->
                              lager:notice("Publishing server descriptor to ~s:~b", [inet:ntoa(Address), Port]),
                              talla_dir_http_client:post(Address, Port, "", SignedDocument, Authority)
                          end, Authorities);

        false ->
            lager:warning("Trying to announce onion router, but the onion router is disabled in the config.")
    end,
    {noreply, State};

handle_cast(Message, State) ->
    lager:warning("Unhandled cast '~p' (State: ~p)", [Message, State]),
    {noreply, State}.

%% @private
handle_info({http_client_response, Status, _Headers, #{ address := Address, dir_port := DirPort }, _Response}, State) ->
    lager:notice("Got ~b from authority: ~s:~b", [Status, inet:ntoa(Address), DirPort]),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info '~p' (State: ~p)", [Info, State]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVersion, State, _Extra) ->
    {ok, State}.
