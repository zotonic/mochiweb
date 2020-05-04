%% @author Bob Ippolito <bob@mochimedia.com>
%% @copyright 2010 Mochi Media, Inc.

%% @doc MochiWeb acceptor.

-module(mochiweb_acceptor).
-author('bob@mochimedia.com').

-include("internal.hrl").

-export([start_link/3]).

% exported for looping with a fully qualified module name.
-export([init/3, call_loop/2]).

start_link(Server, Listen, Loop) ->
    proc_lib:spawn_link(?MODULE, init, [Server, Listen, Loop]).

init(Server, Listen, Loop) ->
    T1 = os:timestamp(),
    case catch mochiweb_socket:transport_accept(Listen) of
        {ok, Socket} ->
            %% Accept this connection, and let the socket server start a new acceptor
            gen_server:cast(Server, {accepted, self(), timer:now_diff(os:timestamp(), T1)}),

            %% Perform a ssl handshake if needed.
            {ok, Socket1} = mochiweb_socket:finish_accept(Socket),

            ?MODULE:call_loop(Loop, Socket1);
        {error, timeout} ->
            ?MODULE:init(Server, Listen, Loop);
        {error, econnaborted} ->
            ?MODULE:init(Server, Listen, Loop);
        {error, closed} ->
            exit(normal);
        {error, Other} ->
            exit({error, Other})
    end.

call_loop({M, F}, Socket) when is_atom(M) ->
    M:F(Socket);
call_loop({M, F, [A1]}, Socket) when is_atom(M) ->
    M:F(Socket, A1);
call_loop({M, F, A}, Socket) when is_atom(M) ->
    erlang:apply(M, F, [Socket | A]);
call_loop(Loop, Socket) ->
    Loop(Socket).

%%
%% Tests
%%
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
