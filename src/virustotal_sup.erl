%%%-------------------------------------------------------------------
%% @author Doug Tykocki <tykockda@gmail.com>
%% @doc virustotal top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(virustotal_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_child/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API
%%====================================================================

start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_child(Name, ApiKey) ->
  supervisor:start_child(?MODULE, [Name, ApiKey]).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
  SupFlags = #{strategy => simple_one_for_one,
               intensity => 5,
               period => 10},
  ChildSpecs = [#{id => virustotal,
                 start => {virustotal, start_link, []},
                 restart => transient,
                 shutdown => 5000,
                 type => worker,
                 modules => [virustotal]}],
  {ok, {SupFlags, ChildSpecs}}.
