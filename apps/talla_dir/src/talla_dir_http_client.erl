%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc HTTP Client.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_dir_http_client).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         get/3,
         get/4,
         post/4,
         post/5]).

%% Generic Server Behaviour.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

get(Address, Port, Resource) ->
    get(Address, Port, Resource, []).

get(Address, Port, Resource, Extra) ->
    gen_server:cast(?SERVER, {get, Address, Port, Resource, Extra, self()}).

post(Address, Port, Resource, Body) ->
    post(Address, Port, Resource, Body, []).

post(Address, Port, Resource, Body, Extra) ->
    gen_server:cast(?SERVER, {post, Address, Port, Resource, Body, Extra, self()}).

%% @private
init([]) ->
    {ok, maps:new()}.

%% @private
handle_call(Request, From, State) ->
    lager:warning("Unhandled call '~p' from ~p (State: ~p)", [Request, From, State]),
    {reply, ok, State}.

%% @private
handle_cast({get, Address, Port, Resource, Extra, Pid}, State) ->
    URL = onion_string:format("http://~s:~b/tor/~s", [inet:ntoa(Address), Port, Resource]),
    lager:info("GET ~s", [URL]),
    case hackney:get(URL, [{<<"User-Agent">>, talla_core:platform()}], <<>>, [async]) of
        {ok, Ref} ->
            {noreply, maps:put(Ref, #{ owner => Pid, extra => Extra }, State)};

        {error, Reason} ->
            Pid ! {http_client_error, Reason},
            {noreply, State}
    end;

handle_cast({post, Address, Port, Resource, Body, Extra, Pid}, State) ->
    URL = onion_string:format("http://~s:~b/tor/~s", [inet:ntoa(Address), Port, Resource]),
    lager:info("POST ~s", [URL]),
    case hackney:post(URL, [{<<"User-Agent">>, talla_core:platform()}], Body, [async]) of
        {ok, Ref} ->
            {noreply, maps:put(Ref, #{ owner => Pid, extra => Extra }, State)};

        {error, Reason} ->
            Pid ! {http_client_error, Reason},
            {noreply, State}
    end;

handle_cast(Message, State) ->
    lager:warning("Unhandled cast '~p' (State: ~p)", [Message, State]),
    {noreply, State}.

%% @private
handle_info({hackney_response, Ref, Message}, State) ->
    lager:info("Response for ~p: ~p (State: ~p)", [Ref, Message, State]),

    %%% FIXME(ahf): For some reason we cannot match in the function body.
    #{ Ref := RequestState } = State,

    case Message of
        {status, StatusCode, _StatusMessage} ->
            {noreply, maps:put(Ref, RequestState#{ status => StatusCode }, State)};

        {headers, Headers} ->
            {noreply, maps:put(Ref, RequestState#{ headers => maps:from_list(Headers) }, State)};

        done ->
            Owner    = maps:get(owner, RequestState),
            Status   = maps:get(status, RequestState),
            Headers  = maps:get(headers, RequestState),
            Data     = decode_data(Headers, lists:reverse(maps:get(data, RequestState, []))),
            Extra    = maps:get(extra, RequestState),
            Response = case onion_document:decode(Data) of
                           {ok, Document} ->
                               {document, Document};

                           {error, _} ->
                               lager:warning("Unable to decode document: ~p", [Data]),
                               {unknown, Data}
                       end,

            Owner ! {http_client_response, Status, Headers, Extra, Response},

            {noreply, maps:remove(Ref, State)};

        Packet when is_binary(Packet) ->
            Data = maps:get(data, RequestState, []),
            {noreply, maps:put(Ref, RequestState#{ data => [Packet | Data] }, State)};

        _ ->
            lager:warning("Unhandled response '~p' (State: ~p)", [Message, State]),
            {noreply, State}
    end;

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
decode_data(Headers, Data) ->
    case maps:get(<<"Content-Encoding">>, Headers, none) of
        <<"deflate">> ->
            deflate(Data);

        none ->
            iolist_to_binary(Data);

        Unknown ->
            lager:warning("Unknown Content-Encoding: ~s", [Unknown]),
            iolist_to_binary(Data)
    end.

%% @private
deflate(Data) ->
    Z = zlib:open(),
    zlib:inflateInit(Z),
    InflatedData = zlib:inflate(Z, Data),
    zlib:close(Z),
    iolist_to_binary(InflatedData).
