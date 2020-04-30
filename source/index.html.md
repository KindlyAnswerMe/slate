---
title: API Gateway v1.0
language_tabs:
  - shell: Shell
  - http: HTTP
  - javascript: JavaScript
  - ruby: Ruby
  - python: Python
  - php: PHP
  - java: Java
  - go: Go
toc_footers: []
includes: []
search: true
highlight_theme: darkula
headingLevel: 2
---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="api-gateway">API Reference</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

<!-- Base URLs: -->

Welcome to Kindly’s API!

You can use this API to access all our API endpoints and never have to switch again between providers, such as the CVE API to look up MITRE ATT&CK, or the IP API to look up company information related to an IP.

The API is developed around RESTful principles. All request and response bodies, including errors, are encoded in JSON.
We also have some specific language bindings to make integration easier. You can switch the programming language of the examples with the tabs in the top right.

To play around with a few examples, we recommend a REST client called Postman. Simply tap the button below to import a pre-made collection of examples [coming soon].

# Authentication

Authentication is done via your account’s API key.

You can pass your API key in the 'X-API-key' header. We're working on an user dashboard so you can see your account's API keys and renew them if necessary. For now, it will be included in our welcome email, for any requests regarding your API key just send us an email at hi@kindlyanswer.me

# Errors

Our API returns standard HTTP success or error status codes. For errors, we will also include extra information about what went wrong encoded in the response as JSON. The various HTTP status codes we might return are listed below.

HTTP Status Codes

| Code | Title             | Message                     |
| ---- | ----------------- | --------------------------- |
| 200  | OK                |                             |
| 400  | Bad request       |                             |
| 401  | Unauthorized      | No API key found in request |
| 404  | Not found         |                             |
| 429  | Too many requests | Api rate limit exceeded     |

# Rate limiting

You can make 600 requests per minute to each API unless you are using IP API. Check the response HTTP headers of any API request to see your current rate limit status. If you’re running into this error or think you’ll need a higher rate limit, drop us a line at hi@kindlyanswer.me.

| Header                                     |
| ------------------------------------------ |
| X-RateLimit-Limit-logged-in-user-limit     |
| X-RateLimit-Remaining-logged-in-user-limit |
| X-RateLimit-Limit-record-limit             |
| X-RateLimit-Remaining-record-limit         |
| X-RateLimit-Limit-month                    |
| X-RateLimit-Remaining-month                |

Once you go over the rate limit you will receive a rate_limit error response.

# Versioning

When we make backward-incompatible changes to any of our APIs, we release new dated versions. Each API we provide has a separate version (listed below).

| API | Current version | Your version |
| --- | --------------- | ------------ |
| CVE | 4/1/2020        | 4/1/2020     |

<!-- - <a href="http://api.kindlyanswer.me/">http://api.kindlyanswer.me/</a> -->

# CVE API

## Lookup a CVE

<!-- <a id="opIdMockDataAPIUsers"></a> -->

> To look up a CVE

```shell
# You can also use wget
curl -X GET https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614
  -H 'x-api-key: string'

```

```http
GET https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614 HTTP/1.1
Host: api.kindlyanswer.me

x-api-key: string

```

```javascript
const headers = {
  "x-api-key": "string",
};

fetch("https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614", {
  method: "GET",

  headers: headers,
})
  .then(function (res) {
    return res.json();
  })
  .then(function (body) {
    console.log(body);
  });
```

```ruby
require 'rest-client'
require 'json'

headers = {
  'x-api-key' => 'string'
}

result = RestClient.get 'https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'x-api-key': 'string'
}

r = requests.get('https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614, headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'x-api-key' => 'string',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "x-api-key": []string{"string"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

> To look up more than one CVE

```shell
# You can also use wget
curl -X GET https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266
  -H 'x-api-key: string'

```

```http
GET https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266 HTTP/1.1
Host: api.kindlyanswer.me

x-api-key: string

```

```javascript
const headers = {
  "x-api-key": "string",
};

fetch(
  "https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266",
  {
    method: "GET",

    headers: headers,
  }
)
  .then(function (res) {
    return res.json();
  })
  .then(function (body) {
    console.log(body);
  });
```

```ruby
require 'rest-client'
require 'json'

headers = {
  'x-api-key' => 'string'
}

result = RestClient.get 'https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'x-api-key': 'string'
}

r = requests.get('https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266, headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'x-api-key' => 'string',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266', array(
        'headers' => $headers,
        'json' => $request_body,
       )
    );
    print_r($response->getBody()->getContents());
 }
 catch (\GuzzleHttp\Exception\BadResponseException $e) {
    // handle exception or api errors.
    print_r($e->getMessage());
 }

 // ...

```

```java
URL obj = new URL("https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("GET");
int responseCode = con.getResponseCode();
BufferedReader in = new BufferedReader(
    new InputStreamReader(con.getInputStream()));
String inputLine;
StringBuffer response = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
    response.append(inputLine);
}
in.close();
System.out.println(response.toString());

```

```go
package main

import (
       "bytes"
       "net/http"
)

func main() {

    headers := map[string][]string{
        "x-api-key": []string{"string"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0609,CVE-2020-0611,CVE-2017-8620,CVE-2020-3266", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

In order to build complex cyber security scenarios one must map more than +100k vulnerabilities (CVEs) to the corresponding MITRE ATT&CK. The benefit of the corresponding controls allows the organization to better prioritize what actions should be taken. We use natural language processing to achieve this task.

To use the CVE API, send us a CVE and we’ll return the information we have on it. If we can’t match the CVE to MITRE ATT&CK, we’ll return a 404 HTTP status instead of a 200.

HTTP Request
GET https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614

## HTTP GET headers

| Name      | in     | Type   | Description |
| --------- | ------ | ------ | ----------- |
| X-API-key | header | string | API Key     |

## Response Headers

| Status | Header                  | Type   |
| ------ | ----------------------- | ------ |
| 200    | Connection              | string |
| 200    | Content-Length          | string |
| 200    | Date                    | string |
| 200    | Server                  | string |
| 200    | Via                     | string |
| 200    | X-Kong-Proxy-Latency    | string |
| 200    | X-Kong-Upstream-Latency | string |

<!-- backwards compatibility -->

<a id="schemawhatisthemitreatt_ckmappingforthiscve_"></a>
<a id="schema_WhatistheMITREATT_CKmappingforthisCVE_"></a>
<a id="tocSwhatisthemitreatt_ckmappingforthiscve_"></a>
<a id="tocswhatisthemitreatt_ckmappingforthiscve_"></a>

## Properties

| Name    | Type   | Required |
| ------- | ------ | -------- |
| results | Result | true     |

<!-- backwards compatibility -->

## Results

<a id="schemaresult"></a>
<a id="schema_Result"></a>
<a id="tocSresult"></a>
<a id="tocsresult"></a>

> Example responses

```json
{
  "results": [
    {
      "CVE": "CVE-2020-0614",
      "CVSS2_Score": 4.6,
      "CVSS2_Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
      "CVSS3_Score": 7.8,
      "CVSS3_Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      "CWEs": "CWE-269",
      "Coverage": "High",
      "Exploit_Code": "Unproven",
      "Industry_Spread": "Retail,Banking,Government - Federal,Education,Consulting",
      "Mitre_Techniques": [
        {
          "Technique_ID": "T1068",
          "Technique_Name": "Exploitation for Privilege Escalation",
          "Technique_Tactic_IDS": "TA0004"
        }
      ],
      "Threat_Activity": "Very Low"
    }
  ]
}
```

| Name             | Type           | Required |
| ---------------- | -------------- | -------- |
| CVE              | string         | true     |
| CVSS2_Score      | number(double) | true     |
| CVSS2_Vector     | string         | true     |
| CVSS3_Score      | number(double) | true     |
| CVSS3_Vector     | string         | true     |
| CWEs             | string         | true     |
| Coverage         | string         | true     |
| Exploit_Code     | string         | true     |
| Industry_Spread  | string         | true     |
| Mitre_Techniques | MitreTechnique | true     |
| Threat_Activity  | string         | true     |

## Technique

<a id="schemamitretechnique"></a>
<a id="schema_MitreTechnique"></a>
<a id="tocSmitretechnique"></a>
<a id="tocsmitretechnique"></a>

```json
{
  "Technique_ID": "T1068",
  "Technique_Name": "Exploitation for Privilege Escalation",
  "Technique_Tactic_IDS": "TA0004"
}
```

| Name                 | Type   | Required |
| -------------------- | ------ | -------- |
| Technique_ID         | string | true     |
| Technique_Name       | string | true     |
| Technique_Tactic_IDS | string | true     |

<!-- backwards compatibility -->
