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
-export([init/1,
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
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

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
init(_Args) ->
    {ok, #state {}, 0}.

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
handle_info(timeout, State) ->
    IPv4Digest = compute_digest(file("geoip")),
    lager:notice("Using GeoIP IPv4 Database: ~s", [onion_base16:encode(IPv4Digest)]),

    IPv6Digest = compute_digest(file("geoip6")),
    lager:notice("Using GeoIP IPv6 Database: ~s", [onion_base16:encode(IPv6Digest)]),

    new_ipv4_table(),
    new_ipv6_table(),

    {noreply, State#state {
                    digest_ipv4 = IPv4Digest,
                    digest_ipv6 = IPv6Digest
                }};

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
-spec new_ipv4_table() -> ok.
new_ipv4_table() ->
    Table = ets:new(?IPV4_TABLE, [ordered_set, protected, named_table, {read_concurrency, true}]),
    {ok, IPs} = onion_geoip:parse_ipv4_file(file("geoip")),
    true = ets:insert_new(Table, IPs),
    ok.

%% @private
-spec new_ipv6_table() -> ok.
new_ipv6_table() ->
    Table = ets:new(?IPV6_TABLE, [ordered_set, protected, named_table, {read_concurrency, true}]),
    {ok, IPs} = onion_geoip:parse_ipv6_file(file("geoip6")),
    true = ets:insert_new(Table, IPs),
    ok.

%% @private
-spec file(Filename) -> Path
    when
        Filename :: file:filename(),
        Path     :: file:filename().
file(Filename) ->
    filename:join([code:priv_dir(talla_core), "geoip", Filename]).

%% @private
-spec compute_digest(Filename) -> binary()
    when
        Filename :: file:filename().
compute_digest(Filename) ->
    {ok, Content} = file:read_file(Filename),
    crypto:hash(sha, Content).
