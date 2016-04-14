%%%
%%% Copyright (c) 2016 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc GeoIP API.
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_core_geoip).

%% API.
-export([start_link/0,

         country_from_ipv4/1,
         country_from_ipv6/1,

         digest_ipv4/0,
         digest_ipv6/0
        ]).

%% Generic Server Callbacks.
-export([init/0,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-define(IPV4_TABLE, talla_core_geoip_ipv4).
-define(IPV6_TABLE, talla_core_geoip_ipv6).

-define(MATCH_SPEC(V), [{{{'$1', '$2'}, '$3'}, [{'=<', '$1', {V}},
                                                {'>=', '$2', {V}}], ['$3']}]).

-record(state, {
          digest_ipv4 :: binary(),
          digest_ipv6 :: binary()
         }).

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    proc_lib:start_link(?MODULE, init, []).

-spec country_from_ipv4(IP) -> binary()
    when
        IP :: inet:ip4_address().
country_from_ipv4({_, _, _, _} = IP) ->
    case ets:select(?IPV4_TABLE, ?MATCH_SPEC(IP)) of
        [] ->
            <<"??">>;

        [Country] ->
            Country;

        List ->
            lager:warning("Bug: Found multiple results for IP ~s: ~w", [inet:ntoa(IP), List]),
            hd(List)
    end.

-spec country_from_ipv6(IP) -> binary()
    when
        IP :: inet:ip6_address().
country_from_ipv6({_, _, _, _, _, _, _, _} = IP) ->
    case ets:select(?IPV6_TABLE, ?MATCH_SPEC(IP)) of
        [] ->
            <<"??">>;

        [Country] ->
            Country;

        List ->
            lager:warning("Bug: Found multiple results for IP ~s: ~w", [inet:ntoa(IP), List]),
            hd(List)
    end.

-spec digest_ipv4() -> binary().
digest_ipv4() ->
    gen_server:call(?SERVER, digest_ipv4).

-spec digest_ipv6() -> binary().
digest_ipv6() ->
    gen_server:call(?SERVER, digest_ipv6).

%% @private
init() ->
    new_table(?IPV4_TABLE),
    new_table(?IPV6_TABLE),

    ok = proc_lib:init_ack({ok, self()}),
    register(?MODULE, self()),

    IPv4Digest = load_ipv4_table(),
    lager:notice("Using GeoIP IPv4 Database: ~s", [onion_base16:encode(IPv4Digest)]),

    IPv6Digest = load_ipv6_table(),
    lager:notice("Using GeoIP IPv6 Database: ~s", [onion_base16:encode(IPv6Digest)]),

    gen_server:enter_loop(?MODULE, [], #state {
                                          digest_ipv4 = IPv4Digest,
                                          digest_ipv6 = IPv6Digest
                                         }).

%% @private
handle_call(digest_ipv4, _From, #state { digest_ipv4 = Digest } = State) ->
    {reply, Digest, State};

handle_call(digest_ipv6, _From, #state { digest_ipv6 = Digest } = State) ->
    {reply, Digest, State};

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

%% @private
-spec load_ipv4_table() -> binary().
load_ipv4_table() ->
    {ok, IPs, Digest} = onion_geoip:parse_ipv4_file(file("geoip")),
    true = ets:insert_new(?IPV4_TABLE, IPs),
    Digest.

%% @private
-spec load_ipv6_table() -> binary().
load_ipv6_table() ->
    {ok, IPs, Digest} = onion_geoip:parse_ipv6_file(file("geoip6")),
    true = ets:insert_new(?IPV6_TABLE, IPs),
    Digest.

%% @private
-spec new_table(Name) -> ets:tid()
    when
        Name :: atom().
new_table(Name) ->
    ets:new(Name, [ordered_set, protected, named_table, {read_concurrency, true}]).

%% @private
-spec file(Filename) -> Path
    when
        Filename :: file:filename(),
        Path     :: file:filename().
file(Filename) ->
    filename:join([code:priv_dir(talla_core), "geoip", Filename]).
