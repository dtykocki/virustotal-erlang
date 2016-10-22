%%%-------------------------------------------------------------------
%% @author Doug Tykocki <tykockda@gmail.com>
%% @doc virustotal top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(virustotal_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_child/2, stop_child/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(CACHE_NAME, virustotal).

%%====================================================================
%% API
%%====================================================================

start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_child(Name, ApiKey) ->
  supervisor:start_child(?SERVER, poolboy:child_spec(
    Name,
    [{name, {local, Name}},
      {worker_module, virustotal},
      {size, 5}, {max_overflow, 10}],
    [ApiKey])).

stop_child(Name) ->
  supervisor:terminate_child(?SERVER, Name),
  supervisor:delete_child(?SERVER, Name).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
  SupFlags = #{strategy => one_for_one,
               intensity => 5,
               period => 10},
  ChildSpecs = [],
  ets:new(?CACHE_NAME, [set, named_table, public]),
  {ok, {SupFlags, ChildSpecs}}.
