%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Certificate Manager.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_dir_certificate_manager).
-behaviour(gen_server).

%% API.
-export([start_link/0]).

%% Generic Server Behaviour.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% Types.
-record(state, {}).

-define(SERVER, ?MODULE).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @private
init([]) ->
    lists:foreach(fun download/1, talla_core_config:authorities()),
    {ok, #state {}}.

%% @private
handle_call(Request, From, State) ->
    lager:warning("Unhandled call '~p' from ~p (State: ~p)", [Request, From, State]),
    {reply, ok, State}.

%% @private
handle_cast(Message, State) ->
    lager:warning("Unhandled cast '~p' (State: ~p)", [Message, State]),
    {noreply, State}.

%% @private
handle_info({http_client_response, 200, _Headers, #{ nickname := Nickname, fingerprint := Fingerprint } = Authority, {document, Document}}, State) ->
    lager:notice("Got certificate document from ~s (~s)", [Nickname, Fingerprint]),
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

%% @private
download(#{ nickname := Nickname, address := Address, dir_port := Port, fingerprint := Fingerprint } = Authority) ->
    lager:notice("Downloading certificate document for ~s (~s)", [Nickname, Fingerprint]),
    talla_dir_http_client:get(Address, Port, "keys/authority.z", Authority).

%% @private
validate_document(_Authority, Document) ->
    try
        [<<"3">> | _]     = onion_document:get_item("dir-key-certificate-version", Document),
        [_Fingerprint | _] = onion_document:get_item("fingerprint", Document),

        {ok, _IDPublicKey}               = decode_key("dir-identity-key", Document),
        {ok, _DirectorySigningPublicKey} = decode_key("dir-signing-key", Document),

%%        [PublishedDate, PublishedTime | _] = onion_document:get_item("dir-key-published", Document),
%%        [ExpiresDate, ExpiresTime | _]     = onion_document:get_item("dir-key-expires", Document),

        true
    catch _:_ ->
        false
    end.

decode_key(Keyword, Document) ->
    {_, KeyPEM} = onion_document:get_item(Keyword, Document),
    onion_rsa:pem_decode(KeyPEM).
