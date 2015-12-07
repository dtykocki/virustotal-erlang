%%%-------------------------------------------------------------------
%% @author Doug Tykocki <tykockda@gmail.com>
%% @doc
%% @end
%%%-------------------------------------------------------------------

-module(virustotal_client).

%% Public API
-export([url_scan/2, url_report/2]).

-define(BASE_URL, "https://www.virustotal.com/vtapi/v2").

%%%===================================================================
%%% Public API
%%%===================================================================

url_scan(Key, UrlToScan) ->
  Url = ?BASE_URL ++ "/url/scan",
  Params = [{url, UrlToScan}, {apikey, Key}],
  do_post(Url, Params).

url_report(Key, Resource) ->
  Url = ?BASE_URL ++ "/url/report",
  Params = [{resource, Resource}, {apikey, Key}],
  do_post(Url, Params).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

do_post(Url, Params) ->
  ReqBody = {form, Params},
  {ok, StatusCode, _, ClientRef} = hackney:request(post, Url, [], ReqBody, []),
  case StatusCode of
    200 ->
      {ok, Body} = hackney:body(ClientRef),
      Decoded = jsx:decode(Body, [{labels, atom}]),
      {ok, Decoded};
    403 ->
      {error, permission_denied};
    203 ->
      {error, rate_limit}
  end.
