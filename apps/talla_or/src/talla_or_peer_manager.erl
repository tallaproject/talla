%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Peer Manager.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_peer_manager).
-behaviour(gen_server).

%% API.
-export([start_link/0,
         connect/2,

         connected/0, %% From talla_or_peer.
         timeout/0    %% From talla_or_peer.
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

-record(state, {
          peers :: ets:tid(),
          subscriptions :: ets:tid()
    }).

-spec start_link() -> {ok, Pid} | {error, Reason}
    when
        Pid    :: pid(),
        Reason :: term().
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec connect(Address, Port) -> reference()
    when
        Address :: inet:ip_address(),
        Port    :: inet:port_number().
connect(Address, Port) ->
    gen_server:call(?SERVER, {connect, Address, Port, self()}).

-spec connected() -> ok.
connected() ->
    gen_server:cast(?SERVER, {connected, self()}).

-spec timeout() -> ok.
timeout() ->
    gen_server:cast(?SERVER, {timeout, self()}).

%% @private
init([]) ->
    {ok, #state {
            peers = ets:new(peers_table, [set, protected]),
            subscriptions = ets:new(subscriptions_table, [duplicate_bag, protected])
           }}.

%% @private
handle_call({connect, Address, Port, Process}, _From, #state { peers = PeerTable, subscriptions = SubscriptionsTable } = State) ->
    Reference = make_ref(),
    case ets:lookup(PeerTable, {Address, Port}) of
        [] ->
            {ok, Peer} = talla_or_peer_pool:start_peer(),
            talla_or_peer:connect(Peer, Address, Port),
            true = ets:insert_new(PeerTable, [{{Address, Port}, Peer}]),
            ets:insert(SubscriptionsTable, [{Peer, {Process, Reference}}]);

        [{{Address, Port}, Peer}] ->
            notify_connected(Process, Reference, Peer)
    end,
    {reply, Reference, State};

handle_call(Request, _From, State) ->
    lager:warning("Unhandled call: ~p", [Request]),
    {reply, unhandled, State}.

%% @private
handle_cast({connected, Peer}, #state { subscriptions = SubscriptionsTable } = State) ->
    Subscribers = ets:take(SubscriptionsTable, Peer),
    lists:foreach(fun ({_, {Process, Reference}}) ->
                    notify_connected(Process, Reference, Peer)
                  end, Subscribers),
    {noreply, State};

handle_cast({timeout, Peer}, #state { subscriptions = SubscriptionsTable } = State) ->
    Subscribers = ets:take(SubscriptionsTable, Peer),
    lists:foreach(fun ({_, {Process, Reference}}) ->
                    notify_timeout(Process, Reference)
                  end, Subscribers),
    {noreply, State};

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

%% @private
notify_connected(Process, Reference, Peer) ->
    Process ! {peer_connected, Reference, Peer}.

%% @private
notify_timeout(Process, Reference) ->
    Process ! {peer_timeout, Reference}.
