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
    case catch mochiweb_socket:accept(Listen) of
        {ok, Socket} ->
            gen_server:cast(Server, {accepted, self(), timer:now_diff(os:timestamp(), T1)}),
            ?MODULE:call_loop(Loop, Socket);
        {error, timeout} ->
            ?MODULE:init(Server, Listen, Loop);
        {error, econnaborted} ->
            ?MODULE:init(Server, Listen, Loop);
        {error, {tls_alert, _}} ->
            ?MODULE:init(Server, Listen, Loop);
        {error, closed} ->
            exit(normal);
        {error, Other} ->
            exit({error, Other})
    end.

call_loop({M, F}, Socket) ->
    M:F(Socket);
call_loop({M, F, [A1]}, Socket) ->
    M:F(Socket, A1);
call_loop({M, F, A}, Socket) ->
    erlang:apply(M, F, [Socket | A]);
call_loop(Loop, Socket) ->
    Loop(Socket).

%%
%% Tests
%%
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
