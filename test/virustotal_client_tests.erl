-module(virustotal_client_tests).

-include_lib("eunit/include/eunit.hrl").

-define(setup(F), {setup, fun start/0, fun stop/1, F}).

-define(CACHE_NAME, virustotal).

start() ->
  application:ensure_all_started(virustotal),
  {ok, _Pid} = virustotal:start(foo, <<"apikey">>),
  meck:new(hackney, [passthrough]),
  foo.

stop(Name) ->
  meck:unload(hackney),
  virustotal:stop(Name).

file_report_cache_retrieve_test_() ->
  [{"file_report checks cache before attempting api call", ?setup(fun results_from_file_report_cache_retrieve/1)}].

file_report_cache_add_test_() ->
  [{"file_report adds cache result after api call", ?setup(fun results_from_file_report_cache_addition/1)}].

url_report_cache_retrieve_test_() ->
  [{"url_report checks cache before attempting api call", ?setup(fun results_from_url_report_cache_retrieve/1)}].

url_report_cache_add_test_() ->
  [{"url_report adds cache result after api call", ?setup(fun results_from_url_report_cache_addition/1)}].


results_from_file_report_cache_retrieve(Name) ->
  load_cache(),
  Result = {ok,[
    {scans,[
      {'Bkav',[{detected,false},
        {version,<<"1.3.0.8455">>},
        {result,null},
        {update,<<"20161013">>}]},
      {'MicroWorld-eScan',[{detected,true},
        {version,<<"12.0.250.0">>},
        {result,<<"Generic.Malware.V!w.7232B058">>},
        {update,<<"20161013">>}]}]},
    {scan_id,<<"mockfilereportscanid">>},
    {sha1,<<"sha1hash">>},
    {resource,<<"testhash">>},
    {response_code,1},
    {scan_date,<<"2016-10-13 22:35:18">>},
    {permalink,<<"https://www.virustotal.com/file/testhash">>},
    {verbose_msg,<<"Scan finished, information embedded">>},
    {total,56},
    {positives,50},
    {sha256,<<"sha256hash">>},
    {md5,<<"md5hash">>}]},
  ?_assert(Result == virustotal_client:file_report(Name, <<"testhash">>)).

results_from_file_report_cache_addition(Name) ->
  meck_hackney_file_report(),
  ?_assert([] == ets:lookup(?CACHE_NAME, {resource, <<"newhash">>})),
  virustotal_client:file_report(Name, <<"newhash">>),
  Result = [
    {{resource, <<"newhash">>},
      {ok,#{
        md5 => <<"md5hash">>,
        permalink => <<"https://www.virustotal.com/file/testhash">>,
        positives => 50,
        resource => <<"testhash">>,
        response_code => 1,
        scan_date => <<"2016-10-13 22:35:18">>,
        scan_id => <<"mockfilereportscanid">>,
        scans => #{
          'Bkav' => #{detected => false,
            result => null,
            update => <<"20161013">>,
            version => <<"1.3.0.8455">>},
          'MicroWorld-eScan' => #{detected => true,
            result => <<"Generic.Malware.V!w.7232B058">>,
            update => <<"20161013">>,
            version => <<"12.0.250.0">>}},
        sha1 => <<"sha1hash">>,
        sha256 => <<"sha256hash">>,
        total => 56,
        verbose_msg => <<"Scan finished, information embedded">>}}}],
  ?_assert(Result == ets:lookup(?CACHE_NAME, {resource, <<"newhash">>})).


results_from_url_report_cache_retrieve(Name) ->
  load_cache(),
  Result = {ok,[
    {scan_id, <<"mockurlreportscanid">>},
    {resource,<<"http://www.google.com">>},
    {url,<<"http://www.google.com/">>},
    {response_code,1},
    {scan_date,<<"2016-10-14 22:28:00">>},
    {permalink,
      <<"https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1476484080/">>},
    {verbose_msg,
      <<"Scan finished, scan information embedded in this object">>},
    {filescan_id,null},
    {positives,0},
    {total,68},
    {scans, [
      {'CLEAN MX',[{detected,false},{result,<<"clean site">>}]},
      {'Rising',[{detected,false},{result,<<"clean site">>}]},
      {'AegisLab WebGuard',[{detected,false},{result,<<"clean site">>}]},
      {'MalwareDomainList', [
        {detected,false},
        {result,<<"clean site">>},
        {detail, <<"http://www.malwaredomainlist.com/mdl.php?search=www.google.com">>}]}]}]},
  ?_assert(Result == virustotal_client:url_report(Name, <<"http://www.google.com">>)).

results_from_url_report_cache_addition(Name) ->
  meck_hackney_url_report(),
  ?_assert([] == ets:lookup(?CACHE_NAME, {resource, <<"newlink">>})),
  virustotal_client:url_report(Name, <<"newlink">>),
  Result = [
    {{resource, <<"newlink">>},
      {ok,#{
        filescan_id => null,
        permalink => <<"https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1476484080/">>,
        positives => 0,
        resource => <<"http://www.google.com">>,
        response_code => 1,
        scan_date => <<"2016-10-14 22:28:00">>,
        scan_id => <<"mockurlreportscanid">>,
        scans => #{
          'AegisLab WebGuard' => #{detected => false,result => <<"clean site">>},
          'CLEAN MX' => #{detected => false,result => <<"clean site">>},
          'MalwareDomainList' => #{detail => <<"http://www.malwaredomainlist.com/mdl.php?search=www.google.com">>,
            detected => false,
            result => <<"clean site">>},
          'Rising' => #{detected => false,result => <<"clean site">>}},
        total => 68,
        url => <<"http://www.google.com/">>,
        verbose_msg => <<"Scan finished, scan information embedded in this object">>}}}],
  ?_assert(Result == ets:lookup(?CACHE_NAME, {resource, <<"newlink">>})).

load_cache() ->
  ets:insert(virustotal, {{resource, <<"testhash">>}, mock_file_report()}),
  ets:insert(virustotal, {{resource, <<"http://www.google.com">>}, mock_url_report()}).

meck_hackney_file_report() ->
  meck:expect(hackney, request,
    fun(_Method, _URL, _Headers, _Payload, _Options) ->
      {ok, 200, "RespHeaders", "ClientRef"}
    end),
  meck:expect(hackney, body,
    fun("ClientRef") ->
      {ok, <<"{\"scans\":"
        "{\"Bkav\":{\"detected\":false,"
            "\"version\":\"1.3.0.8455\","
            "\"result\":null,"
            "\"update\":\"20161013\"},"
          "\"MicroWorld-eScan\":{\"detected\":true,"
            "\"version\":\"12.0.250.0\","
            "\"result\":\"Generic.Malware.V!w.7232B058\","
            "\"update\":\"20161013\"}},"
        "\"scan_id\":\"mockfilereportscanid\","
        "\"sha1\":\"sha1hash\","
        "\"resource\":\"testhash\","
        "\"response_code\":1,"
        "\"scan_date\":\"2016-10-13 22:35:18\","
        "\"permalink\":\"https://www.virustotal.com/file/testhash\","
        "\"verbose_msg\":\"Scan finished, information embedded\","
        "\"total\":56,"
        "\"positives\":50,"
        "\"sha256\":\"sha256hash\","
        "\"md5\":\"md5hash\"}">>}
    end).

meck_hackney_url_report() ->
  meck:expect(hackney, request,
    fun(_Method, _URL, _Headers, _Payload, _Options) ->
      {ok, 200, "RespHeaders", "ClientRef"}
    end),
  meck:expect(hackney, body,
    fun("ClientRef") ->
      {ok, <<"{\"scan_id\":\"mockurlreportscanid\","
        "\"resource\":\"http://www.google.com\","
        "\"url\":\"http://www.google.com/\","
        "\"response_code\":1,"
        "\"scan_date\":\"2016-10-14 22:28:00\","
        "\"permalink\":\"https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1476484080/\","
        "\"verbose_msg\":\"Scan finished, scan information embedded in this object\","
        "\"filescan_id\":null,"
        "\"positives\":0,"
        "\"total\":68,"
        "\"scans\":"
          "{\"CLEAN MX\":{"
              "\"detected\":false,"
              "\"result\":\"clean site\"},"
            "\"Rising\":{"
              "\"detected\":false,"
              "\"result\":\"clean site\"},"
            "\"AegisLab WebGuard\":{"
              "\"detected\":false,"
              "\"result\":\"clean site\"},"
            "\"MalwareDomainList\":{"
              "\"detected\":false,"
              "\"result\":\"clean site\","
              "\"detail\":\"http://www.malwaredomainlist.com/mdl.php?search=www.google.com\"}}}">>}
    end).

mock_file_report() ->
  {ok,[
    {scans,[
      {'Bkav',[{detected,false},
        {version,<<"1.3.0.8455">>},
        {result,null},
        {update,<<"20161013">>}]},
      {'MicroWorld-eScan',[{detected,true},
        {version,<<"12.0.250.0">>},
        {result,<<"Generic.Malware.V!w.7232B058">>},
        {update,<<"20161013">>}]}]},
    {scan_id,<<"mockfilereportscanid">>},
    {sha1,<<"sha1hash">>},
    {resource,<<"testhash">>},
    {response_code,1},
    {scan_date,<<"2016-10-13 22:35:18">>},
    {permalink,<<"https://www.virustotal.com/file/testhash">>},
    {verbose_msg,<<"Scan finished, information embedded">>},
    {total,56},
    {positives,50},
    {sha256,<<"sha256hash">>},
    {md5,<<"md5hash">>}]}.

mock_url_report() ->
  {ok,[
    {scan_id, <<"mockurlreportscanid">>},
    {resource,<<"http://www.google.com">>},
    {url,<<"http://www.google.com/">>},
    {response_code,1},
    {scan_date,<<"2016-10-14 22:28:00">>},
    {permalink,
      <<"https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1476484080/">>},
    {verbose_msg,
      <<"Scan finished, scan information embedded in this object">>},
    {filescan_id,null},
    {positives,0},
    {total,68},
    {scans, [
      {'CLEAN MX',[{detected,false},{result,<<"clean site">>}]},
      {'Rising',[{detected,false},{result,<<"clean site">>}]},
      {'AegisLab WebGuard',[{detected,false},{result,<<"clean site">>}]},
      {'MalwareDomainList', [
        {detected,false},
        {result,<<"clean site">>},
        {detail, <<"http://www.malwaredomainlist.com/mdl.php?search=www.google.com">>}]}]}]}.