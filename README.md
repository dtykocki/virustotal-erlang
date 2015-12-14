# virustotal-erlang

**virustotal-erlang** is an OTP Erlang application for the [`VirusTotal Public API v2.0`](https://www.virustotal.com/en/documentation/public-api/v2/).

[![Build Status](https://travis-ci.org/dtykocki/virustotal-erlang.svg)](https://travis-ci.org/dtykocki/virustotal-erlang)

## Things you can do with `virustotal-erlang`:
1. Start several `gen_servers` representing different applications defined by different VirusTotal API keys.
2. Send and scan files.
3. Retrieve file scan reports.
4. Send and scan URLs.
5. Retrieve URL scan reports.
6. Retrieve IP address reports.
7. Retrieve domain reports.

## Installation

Add to your `rebar.confg`:

```erlang
{deps, [
    ....
    {virustotal, ".*", {git, "git://github.com/dtykocki/virustotal-erlang.git", {branch, "master"}}}
]}.
```

## Basic Usage

virustotal-erlang is an OTP application. It will need to be started before using any of the features.

To start in the console run:

```erlang-repl
$ ./rebar3 shell
1> hackney:start().
ok
2> application:start(virustotal).
ok
```

### How start and stop different gen_servers

```erlang-repl
4> virustotal:start(foo, <<"myapikey">>).
{ok,<0.149.0>}
5> virustotal:start(bar, <<"myotherapikey">>).
{ok,<0.151.0>}
6> virustotal:start(baz, <<"andotherapikey">>).
{ok,<0.153.0>}
```

You can stop a `gen_server` using:

```erlang-repl
7> virustotal:stop(foo).
```

### Send and scan a file

```erlang-repl
1> virustotal:file_scan(foo, <<"rebar.config">>).
{ok,[{scan_id,<<"5a504b67597853ba52e88bf6afca6010139bfc80f3cf1d9d7758536fd9749e02-1449955847">>},
     {sha1,<<"466d2da02ef188a8245f95e3003e16a85181a697">>},
     {resource,<<"5a504b67597853ba52e88bf6afca6010139bfc80f3cf1d9d7758536fd9749e02">>},
     {response_code,1},
     {sha256,<<"5a504b67597853ba52e88bf6afca6010139bfc80f3cf1d9d7758536fd9749e02">>},
     {permalink,<<"https://www.virustotal.com/file/5a504b67597853ba52e88bf6afca6010139bfc80f3cf"...>>},
     {md5,<<"cb0c545a7029ab86d27ce0b3189ac441">>},
     {verbose_msg,<<"Scan request successfully queued, come back later for the report">>}]}
```

### Retrieve file scan reports

Using the `scan_id` from the above response:

```erlang-repl
1> virustotal:file_report(foo, <<"5a504b67597853ba52e88bf6afca6010139bfc80f3cf1d9d7758536fd9749e02-1449955847">>).
{ok,[{scans,[{'Bkav',[{detected,false},
                      {version,<<"1.3.0.7383">>},
                      {result,null},
                      {update,<<"20151212">>}]},
             {'MicroWorld-eScan',[{detected,false},
                                  {version,<<"12.0.250.0">>},
                                  {result,null},
                                  {update,<<"20151212">>}]},
...
```

### Send and scan URLs

```erlang-repl
1> virustotal:sync_url_scan(foo, <<"www.google.com">>).
{ok,[{permalink,<<"https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/"...>>},
     {resource,<<"http://www.google.com/">>},
     {url,<<"http://www.google.com/">>},
     {response_code,1},
     {scan_date,<<"2015-12-12 21:36:34">>},
     {scan_id,<<"dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1449956194">>},
     {verbose_msg,<<"Scan request successfully queued, come back later for the report">>}]}
```

### Retrieve URL scan reports

Using the `scan_id` from the above response:

```erlang-repl
1> virustotal:url_report(foo, <<"dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1449956194">>).
{ok,[{permalink,<<"https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/"...>>},
     {resource,<<"dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1449956194">>},
     {url,<<"http://www.google.com/">>},
     {response_code,1},
     {scan_date,<<"2015-12-12 21:36:34">>},
     {scan_id,<<"dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1449956194">>},
     {verbose_msg,<<"Scan finished, scan information embedded in this object">>},
     {filescan_id,null},
     {positives,0},
     {total,66},
     {scans,[{'CLEAN MX',[{detected,false},
                          {result,<<"clean site">>}]},
             {'Rising',[{detected,false},{result,<<"clean site">>}]},
...
```

### Retrieve IP address reports

```erlang-repl
1> virustotal:ip_address_report(foo, <<"90.156.201.27">>).
{ok,[{detected_urls,[[{url,<<"http://bms.anw.ru/">>},
                      {positives,1},
                      {total,65},
                      {scan_date,<<"2015-10-12 10:55:21">>}],
                     [{url,<<"http://shop.albione.ru/">>},
                      {positives,2},
                      {total,52},
                      {scan_date,<<"2014-04-06 11:18:17">>}],
                     [{url,<<"http://www.orlov.ru/">>},
                      {positives,3},
                      {total,52},
                      {scan_date,<<"2014-03-05 09:13:31">>}]]},
     {asn,<<"25532">>},
...
```

### Retrieve domain reports

```erlang-repl
1> virustotal:ip_address_report(foo, <<"90.156.201.27">>).
{ok,[{detected_urls,[[{url,<<"http://bms.anw.ru/">>},
                      {positives,1},
                      {total,65},
                      {scan_date,<<"2015-10-12 10:55:21">>}],
                     [{url,<<"http://shop.albione.ru/">>},
                      {positives,2},
                      {total,52},
                      {scan_date,<<"2014-04-06 11:18:17">>}],
                     [{url,<<"http://www.orlov.ru/">>},
                      {positives,3},
                      {total,52},
                      {scan_date,<<"2014-03-05 09:13:31">>}]]},
...
```

## Contribute

For issues, comments, or feedback please [create an issue](http://github.com/dtykocki/virustotal-erlang/issues)

