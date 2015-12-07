%%%-------------------------------------------------------------------
%% @doc virustotal public API and gen_server
%% @end
%%%-------------------------------------------------------------------

-module(virustotal).

-behaviour(gen_server).

%% API
-export([start/2, start_link/2, url_scan/2, url_report/2]).

%% GenServer callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {key}).

%%%===================================================================
%%% API
%%%===================================================================

start(Name, Key) ->
  virustotal_sup:start_child(Name, Key).

start_link(Name, Key) ->
  gen_server:start_link({local, Name}, ?MODULE, [Key], []).

url_scan(Name, Resource) ->
  gen_server:call(Name, {url_scan, Resource}).

url_report(Name, Resource) ->
  gen_server:call(Name, {url_report, Resource}).

%%%===================================================================
%%% GenServer callbacks
%%%===================================================================

init([Key]) ->
  {ok, #state{key = Key}}.

handle_call({url_scan, Resource}, _From, #state{key=Key} = State) ->
  Reply = virustotal_client:url_scan(Key, Resource),
  {reply, Reply, State};
handle_call({url_report, Resource}, _From, #state{key=Key} = State) ->
  Reply = virustotal_client:url_report(Key, Resource),
  {reply, Reply, State}.

handle_cast(stop, State) ->
  {stop, normal, State}.

handle_info(_Info, State) ->
  {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
