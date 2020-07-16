%% @copyright 2010 Mochi Media, Inc.

%% @doc MochiWeb socket - wrapper for plain and ssl sockets.

-module(mochiweb_socket).

-export([listen/4, accept/1, transport_accept/1, finish_accept/1, recv/3, send/2, close/1, port/1, peername/1,
         setopts/2, type/1]).

-define(ACCEPT_TIMEOUT, 2000).
-define(SSL_TIMEOUT, 10000).
-define(SSL_HANDSHAKE_TIMEOUT, 20000).


listen(Ssl, Port, Opts, SslOpts) ->
    case Ssl of
        true ->
            Opts1 = add_unbroken_ciphers_default(Opts ++ SslOpts),
            Opts2 = add_safe_protocol_versions(Opts1),
            case ssl:listen(Port, Opts2) of
                {ok, ListenSocket} ->
                    {ok, {ssl, ListenSocket}};
                {error, _} = Err ->
                    Err
            end;
        false ->
            gen_tcp:listen(Port, Opts)
    end.

-ifdef(ssl_filter_broken).
add_unbroken_ciphers_default(Opts) ->
    Default = sort_cipher_suites(filter_unsecure_cipher_suites(default_ciphers())),
    Ciphers = proplists:get_value(ciphers, Opts, Default),

    % io:fwrite(standard_error, "Ciphers: ~p~n", [[suite_definition(S) || S <- Ciphers]]),

    [{ciphers, Ciphers} | proplists:delete(ciphers, Opts)].

% Sort the cipher suite in more preferred secure order to less.
sort_cipher_suites(Suites) ->
    lists:reverse(lists:sort(fun(A, B) ->
                                     suite_sort_info(A) =< suite_definition(B)
                             end, Suites)). 
    
suite_sort_info(Suite) ->
  SuiteInfo = suite_definition(Suite),
  {has_ec_key_exchange(SuiteInfo),
   has_aead(SuiteInfo),
   has_ecdsa(SuiteInfo),
   effective_key_bits(SuiteInfo),
   hash_size(SuiteInfo)}.


has_ec_key_exchange({KeyExchange, _, _}) -> has_ec_key_exchange(KeyExchange);
has_ec_key_exchange({KeyExchange, _, _, _}) -> has_ec_key_exchange(KeyExchange);
has_ec_key_exchange(Suite) when is_map(Suite) ->
    has_ec_key_exchange(maps:get(key_exchange, Suite));
has_ec_key_exchange(KeyExchange) when is_atom(KeyExchange) ->
    case atom_to_list(KeyExchange) of
        "ecdhe"++_ -> true;
        _ -> false
    end.

has_aead(SuiteInfo) when is_map(SuiteInfo) -> has_aead(maps:get(mac, SuiteInfo));
has_aead({_, _, Mac}) -> has_aead(Mac);
has_aead({_, _, Mac, _}) -> has_aead(Mac);
has_aead(aead) -> true;
has_aead(_) -> false.

has_ecdsa(SuiteInfo) when is_map(SuiteInfo) -> has_ecdsa(maps:get(key_exchange, SuiteInfo));
has_ecdsa({KeyExchange, _, _}) -> has_ecdsa(KeyExchange);
has_ecdsa({KeyExchange, _, _, _}) -> has_ecdsa(KeyExchange);
has_ecdsa(ecdhe_ecdsa) -> true;
has_ecdsa(ecdh_ecdsa) -> true;
has_ecdsa(_) -> false.

effective_key_bits(Suite) when is_map(Suite)  -> effective_key_bits(maps:get(cipher, Suite));
effective_key_bits({_, Cipher, _}) -> effective_key_bits(Cipher);
effective_key_bits({_, Cipher, _, _}) -> effective_key_bits(Cipher);

effective_key_bits(null) -> 0;
effective_key_bits(des_cbc) -> 56;
effective_key_bits(rc4_128) -> 128;
effective_key_bits(aes_128_cbc) -> 128;
effective_key_bits(aes_128_gcm) -> 128;
effective_key_bits('3des_ede_cbc') -> 168;
effective_key_bits('aes_256_cbc') -> 256;
effective_key_bits('aes_256_gcm') -> 256.

hash_size(SuiteInfo) when is_map(SuiteInfo) -> hash_size(maps:get(mac, SuiteInfo));
hash_size({_, _, Mac}) -> hash_size(Mac);
hash_size({_, _, Mac, _}) -> hash_size(Mac);
hash_size(null) -> 0;
hash_size(aead) -> 0;
hash_size(md5) -> 16;
hash_size(sha) -> 20;
hash_size(sha256) -> 32;
hash_size(sha384) -> 48.


filter_unsecure_cipher_suites(Ciphers) ->
    lists:filter(fun is_secure/1, Ciphers).

% Return true if the cipher spec is secure.
is_secure(Suite) when is_binary(Suite) ->
    is_secure(suite_definition(Suite));
is_secure({KeyExchange, Cipher, MacHash}) ->
    is_secure_key_exchange(KeyExchange) andalso is_secure_cipher(Cipher) andalso is_secure_mac(MacHash);
is_secure({KeyExchange, Cipher, MacHash, _PrfHash}) ->
    is_secure_key_exchange(KeyExchange) andalso is_secure_cipher(Cipher) andalso is_secure_mac(MacHash);
is_secure(Suite) when is_map(Suite) ->
    is_secure_key_exchange(maps:get(key_exchange, Suite)) andalso is_secure_cipher(maps:get(cipher, Suite)) andalso is_secure_mac(maps:get(mac, Suite)).

-ifdef(ssl_cipher_old).
suite_definition(Suite) ->
    ssl_cipher:suite_definition(Suite).
-else.
% OTP-21
suite_definition(Suite) ->
    ssl_cipher_format:suite_definition(Suite).
-endif.

% Return true if the key_exchange algorithm is secure
is_secure_key_exchange(rsa) -> false; 
is_secure_key_exchange(Alg) -> 
    true.
    %case atom_to_list(Alg) of
    %    "ecdh_" ++ _ -> false;
    %    _ -> true
    %end.

% Return true if the cipher algorithm is secure.
is_secure_cipher(des_cbc) -> false;
is_secure_cipher(rc4_128) -> false;
is_secure_cipher('3des_ede_cbc') -> false;
is_secure_cipher(_) -> true.

% Return true if the mac algorithm is secure.
is_secure_mac(md5) -> false;
is_secure_mac(_) -> true.

% Get a list of default ciphers.
%
% Note: ssl:cipher_suites/0 does not return a usable set of ciphers. It returns
% only ciphers usable by the highest protocol version. The problem is that it
% doesn't return default_prf as prf algorithm, but a fixed one usable by tls 1.2
% only.
default_ciphers() ->
    HighestProtocolVersion = tls_record:highest_protocol_version([]),
    AllSuites = ssl_cipher:suites(HighestProtocolVersion),
    ssl_cipher:filter_suites(AllSuites).


-else.
% OTP-22 and upwards are ok. 
%
% The default cipher suite is not sorted into more secure to less in this case.
add_unbroken_ciphers_default(Opts) ->
    Opts.
-endif.


add_safe_protocol_versions(Opts) ->
    case proplists:is_defined(versions, Opts) of
        true ->
            Opts;
        false ->
            Versions = filter_unsafe_protcol_versions(proplists:get_value(available, ssl:versions())),
            [{versions, Versions} | Opts]
    end.

filter_unsafe_protcol_versions(Versions) ->
    lists:filter(fun
                    (sslv3) -> false;
                    (tlsv1) -> false;
                    ('tlsv1.1') -> false;
                    (_) -> true
                 end,
                 Versions).

accept({ssl, ListenSocket}) ->
    % There's a bug in ssl:transport_accept/2 at the moment, which is the
    % reason for the try...catch block. Should be fixed in OTP R14.
    try ssl:transport_accept(ListenSocket, ?SSL_TIMEOUT) of
        {ok, Socket} ->
            finish_accept(Socket);
        {error, _} = Err ->
            Err
    catch
        error:{badmatch, {error, Reason}} ->
            {error, Reason}
    end;
accept(ListenSocket) ->
    gen_tcp:accept(ListenSocket, ?ACCEPT_TIMEOUT).

transport_accept({ssl, ListenSocket}) ->
    case ssl:transport_accept(ListenSocket, ?SSL_TIMEOUT) of
        {ok, Socket} ->
            {ok, {ssl, Socket}};
        {error, _} = Err ->
            Err
    end;
transport_accept(ListenSocket) ->
    gen_tcp:accept(ListenSocket, ?ACCEPT_TIMEOUT).

-ifdef(ssl_handshake_unavailable).
finish_accept({ssl, Socket} = S) ->
    case ssl:ssl_accept(Socket, ?SSL_HANDSHAKE_TIMEOUT) of
        ok ->
            {ok, {ssl, Socket}};
        %% Garbage was most likely sent to the socket, don't error out.
        {error, {tls_alert, _}} ->
            mochiweb_socket:close(S),
            exit(normal);
        %% Socket most likely stopped responding, don't error out.
        {error, Reason} when Reason =:= timeout orelse Reason =:= closed ->
            mochiweb_socket:close(S),
            exit(normal);
        {error, _} = Err ->
            mochiweb_socket:close(S),
            exit(Err)
    end;
finish_accept(Socket) ->
    {ok, Socket}.
-else.
finish_accept({ssl, Socket} = S) ->
    case ssl:handshake(Socket, ?SSL_HANDSHAKE_TIMEOUT) of
        {ok, SslSocket} ->
            {ok, {ssl, SslSocket}};
        %% Garbage was most likely sent to the socket, don't error out.
        {error, {tls_alert, _}} ->
            mochiweb_socket:close(S),
            exit(normal);
        %% Socket most likely stopped responding, don't error out.
        {error, Reason} when Reason =:= timeout orelse Reason =:= closed ->
            mochiweb_socket:close(S),
            exit(normal);
        {error, _} = Err ->
            mochiweb_socket:close(S),
            exit(Err)
    end;
finish_accept(Socket) ->
    {ok, Socket}.
-endif.


recv({ssl, Socket}, Length, Timeout) ->
    ssl:recv(Socket, Length, Timeout);
recv(Socket, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout).

send({ssl, Socket}, Data) ->
    ssl:send(Socket, Data);
send(Socket, Data) ->
    gen_tcp:send(Socket, Data).

close({ssl, Socket}) ->
    ssl:close(Socket);
close(Socket) ->
    gen_tcp:close(Socket).

port({ssl, Socket}) ->
    case ssl:sockname(Socket) of
        {ok, {_, Port}} ->
            {ok, Port};
        {error, _} = Err ->
            Err
    end;
port(Socket) ->
    inet:port(Socket).

peername({ssl, Socket}) ->
    ssl:peername(Socket);
peername(Socket) ->
    inet:peername(Socket).

setopts({ssl, Socket}, Opts) ->
    ssl:setopts(Socket, Opts);
setopts(Socket, Opts) ->
    inet:setopts(Socket, Opts).

type({ssl, _}) ->
    ssl;
type(_) ->
    plain.

%%
%% Tests
%%
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-ifdef(ssl_filter_broken).
default_cipher_test() ->
    %% Make sure there are default ciphers.
    ?assert(length(default_ciphers()) > 0),
    ok.
-endif.


-endif.
