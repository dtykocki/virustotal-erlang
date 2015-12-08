%%%-------------------------------------------------------------------
%% @author Doug Tykocki <tykockda@gmail.com>
%% @doc virustotal application module
%% @end
%%%-------------------------------------------------------------------

-module(virustotal_app).

-behaviour(application).

%% Application callbacks
-export([start/2 ,stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
  virustotal_sup:start_link().

stop(_State) ->
  ok.
