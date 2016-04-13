%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% ----------------------------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Tor TLS Transport Wrapper for Ranch.
%%%
%%% This module wraps calls to ranch_ssl, but we need to be able to
%%% periodically rotate the keys without having to restart our Ranch listener,
%%% which requires access to the accept_ack/2 directly.
%%%
%%% @end
%%% ----------------------------------------------------------------------------
-module(talla_or_tls).
-behaviour(ranch_transport).

%% Ranch API.
-export([name/0,
         secure/0,
         messages/0,
         listen/1,
         accept/2,
         accept_ack/2,
         connect/3,
         connect/4,
         recv/3,
         send/2,
         sendfile/2,
         sendfile/4,
         sendfile/5,
         setopts/2,
         controlling_process/2,
         peername/1,
         sockname/1,
         shutdown/2,
         close/1]).

-spec name() -> atom().
name() ->
    ranch_ssl:name().

-spec secure() -> boolean().
secure() ->
    ranch_ssl:secure().

-spec messages() -> [atom()].
messages() ->
    ranch_ssl:messages().

-spec listen(proplists:proplist()) -> {ok, ssl:sslsocket()} | {error, atom()}.
listen(Opts) ->
    ranch_ssl:listen(Opts).

-spec accept(ssl:sslsocket(), timeout()) -> {ok, ssl:sslsocket()} | {error, closed | timeout | atom()}.
accept(LSocket, Timeout) ->
    ranch_ssl:accept(LSocket, Timeout).

-spec accept_ack(ssl:sslsocket(), timeout()) -> ok.
accept_ack(CSocket, Timeout) ->
    {#{ secret := SecretKey}, Certificate} = talla_or_tls_manager:link_certificate(),
    {ok, SecretKeyDER} = onion_rsa:der_encode(SecretKey),

    %% FIXME(ahf): I was unable to get this information using ssl:getopts/2 -
    %% if you have a better way of doing this, please fix onion_ssl_session,
    %% the handle_info({certificate, ...}, ...) function in talla_or_peer, and
    %% this line.
    self() ! {certificate, Certificate},

    case ssl:ssl_accept(CSocket, [{key, {'RSAPrivateKey', SecretKeyDER}},
                                  {cert, Certificate}], Timeout) of
        ok ->
            ok;

        %% Garbage was most likely sent to the socket, don't error out.
        {error, {tls_alert, _}} ->
            ok = close(CSocket),
            exit(normal);

        %% Socket most likely stopped responding, don't error out.
        {error, timeout} ->
            ok = close(CSocket),
            exit(normal);

        {error, Reason} ->
            ok = close(CSocket),
            error(Reason)
    end.

-spec connect(inet:ip_address() | inet:hostname(), inet:port_number(), any()) -> {ok, inet:socket()} | {error, atom()}.
connect(Host, Port, Opts) when is_integer(Port) ->
    ranch_ssl:connect(Host, Port, Opts).

-spec connect(inet:ip_address() | inet:hostname(), inet:port_number(), any(), timeout()) -> {ok, inet:socket()} | {error, atom()}.
connect(Host, Port, Opts, Timeout) when is_integer(Port) ->
    ranch_ssl:connect(Host, Port, Opts, Timeout).

-spec recv(ssl:sslsocket(), non_neg_integer(), timeout()) -> {ok, any()} | {error, closed | atom()}.
recv(Socket, Length, Timeout) ->
    ranch_ssl:recv(Socket, Length, Timeout).

-spec send(ssl:sslsocket(), iodata()) -> ok | {error, atom()}.
send(Socket, Packet) ->
    ranch_ssl:send(Socket, Packet).

-spec sendfile(ssl:sslsocket(), file:name_all() | file:fd()) -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Socket, Filename) ->
    ranch_ssl:sendfile(Socket, Filename).

-spec sendfile(ssl:sslsocket(), file:name_all() | file:fd(), non_neg_integer(), non_neg_integer()) -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Socket, File, Offset, Bytes) ->
    ranch_ssl:sendfile(Socket, File, Offset, Bytes).

-spec sendfile(ssl:sslsocket(), file:name_all() | file:fd(), non_neg_integer(), non_neg_integer(), ranch_transport:sendfile_opts()) -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Socket, File, Offset, Bytes, Opts) ->
    ranch_ssl:sendfile(Socket, File, Offset, Bytes, Opts).

-spec setopts(ssl:sslsocket(), list()) -> ok | {error, atom()}.
setopts(Socket, Opts) ->
    ranch_ssl:setopts(Socket, Opts).

-spec controlling_process(ssl:sslsocket(), pid()) -> ok | {error, closed | not_owner | atom()}.
controlling_process(Socket, Pid) ->
    ranch_ssl:controlling_process(Socket, Pid).

-spec peername(ssl:sslsocket()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
peername(Socket) ->
    ranch_ssl:peername(Socket).

-spec sockname(ssl:sslsocket()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
sockname(Socket) ->
    ranch_ssl:sockname(Socket).

-spec shutdown(ssl:sslsocket(), read | write | read_write) -> ok | {error, atom()}.
shutdown(Socket, How) ->
    ranch_ssl:shutdown(Socket, How).

-spec close(ssl:sslsocket()) -> ok.
close(Socket) ->
    ranch_ssl:close(Socket).
