%%%-------------------------------------------------------------------
%% @author Doug Tykocki <tykockda@gmail.com>
%% @doc virustotal HTTP client
%% @end
%%%-------------------------------------------------------------------

-module(virustotal_client).

%% API
-export([url_scan/2, url_report/2, ip_address_report/2, domain_report/2]).

-define(BASE_URL, <<"https://www.virustotal.com/vtapi/v2">>).
-define(URL_SCAN_PATH, <<"/url/scan">>).
-define(URL_REPORT_PATH, <<"/url/report">>).
-define(IP_REPORT_PATH, <<"/ip-address/report">>).
-define(DOMAIN_REPORT_PATH, <<"/domain/report">>).

%%%===================================================================
%%% API
%%%===================================================================

url_scan(Key, UrlToScan) ->
  Body = [{url, UrlToScan}, {apikey, Key}],
  do_post(?BASE_URL, ?URL_SCAN_PATH, Body).

url_report(Key, Resource) ->
  Body = [{resource, Resource}, {apikey, Key}],
  do_post(?BASE_URL, ?URL_REPORT_PATH, Body).

ip_address_report(Key, Resource) ->
  Query = [{ip, Resource}, {apikey, Key}],
  do_get(?BASE_URL, ?IP_REPORT_PATH, Query).

domain_report(Key, Resource) ->
  Query = [{domain, Resource}, {apikey, Key}],
  do_get(?BASE_URL, ?DOMAIN_REPORT_PATH, Query).


%%%===================================================================
%%% Internal Functions
%%%===================================================================

do_get(BaseUrl, Path, Query) ->
  Url = hackney_url:make_url(BaseUrl, Path, Query),
  {ok, StatusCode, _, ClientRef} = hackney:request(get, Url, [], <<>>, []),
  case StatusCode of
    200 ->
      {ok, Body} = hackney:body(ClientRef),
      Decoded = jsx:decode(Body, [{labels, atom}]),
      {ok, Decoded};
    403 ->
      {error, permission_denied};
    204 ->
      {error, rate_limit}
  end.

do_post(BaseUrl, Path, Params) ->
  Url = hackney_url:make_url(BaseUrl, Path, []),
  ReqBody = {form, Params},
  {ok, StatusCode, _, ClientRef} = hackney:request(post, Url, [], ReqBody, []),
  case StatusCode of
    200 ->
      {ok, Body} = hackney:body(ClientRef),
      Decoded = jsx:decode(Body, [{labels, atom}]),
      {ok, Decoded};
    403 ->
      {error, permission_denied};
    204 ->
      {error, rate_limit}
  end.
