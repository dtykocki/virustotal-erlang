-module(virustotal_tests).

-include_lib("eunit/include/eunit.hrl").

-define(setup(F), {setup, fun start/0, fun stop/1, F}).

start() ->
  {ok, Pid} = virustotal:start_link(foo, <<"apikey">>),
  meck:new(virustotal_client),
  Pid.

stop(_Pid) ->
  meck:unload(virustotal_client),
  virustotal:stop(foo).

file_scan_test_() ->
  [{"file_scan returns results", ?setup(fun results_from_file_scan/1)}].

file_report_test_() ->
  [{"file_report returns results", ?setup(fun results_from_file_report/1)}].

url_scan_test_() ->
  [{"url_scan returns ok", ?setup(fun ok_from_url_scan/1)}].

sync_url_scan_test_() ->
  [{"sync_url_scan returns results", ?setup(fun results_from_sync_url_scan/1)}].

url_report_test_() ->
  [{"url_report returns results", ?setup(fun results_from_url_report/1)}].

results_from_file_scan(_) ->
  meck:expect(virustotal_client, file_scan, fun(_Key, _Resource) -> {ok, []} end),
  {ok, _} = virustotal:file_scan(foo, <<"somefile.zip">>),
  ?_assert(meck:validate(virustotal_client)).

results_from_file_report(_) ->
  meck:expect(virustotal_client, file_report, fun(_Key, _Resource) -> {ok, []} end),
  {ok, _} = virustotal:file_report(foo, <<"somefile.zip">>),
  ?_assert(meck:validate(virustotal_client)).

ok_from_url_scan(_) ->
  meck:expect(virustotal_client, url_scan, fun(_Key, _Resource) -> {ok, []} end),
  ok = virustotal:url_scan(foo, <<"www.google.com">>),
  ?_assert(meck:validate(virustotal_client)).

results_from_sync_url_scan(_) ->
  meck:expect(virustotal_client, url_scan, fun(_Key, _Resource) -> {ok, []} end),
  {ok, _} = virustotal:sync_url_scan(foo, <<"www.google.com">>),
  ?_assert(meck:validate(virustotal_client)).

results_from_url_report(_) ->
  meck:expect(virustotal_client, url_report, fun(_Key, _Resource) -> {ok, []} end),
  {ok, _} = virustotal:url_report(foo, <<"www.google.com">>),
  ?_assert(meck:validate(virustotal_client)).
