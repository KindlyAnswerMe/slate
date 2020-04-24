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

Welcome to Kindly’s API! You can use this API to access all our API endpoints and never have to switch again between providers, such as the CVE API to look up MITRE ATT&CK, or the IP API to look up company information related to an IP.

The API is organized around REST. All request and response bodies, including errors, are encoded in JSON.

We also have some specific language bindings to make integration easier. You can switch the programming language of the examples with the tabs in the top right.

Currently, we support the following official client bindings:

- **Shell**
- **HTTP**
- **JavaScript**
- **Ruby**
- **Python**
- **PHP**
- **Java**
- **Go**

To play around with a few examples, we recommend a REST client called Postman. Simply tap the button below to import a pre-made collection of examples [coming soon].

# Authentication

Authentication is done via your account’s API key which looks like:
uAEDJWy3eucjwQ6UEkVNHC4unxGs897S

You can pass your API key as a bearer token in an Authorization header. You can see your account’s API keys, and roll them if necessary, in the dashboard [coming soon]. For now please look out for our email:

Welcome to Kindly!
Getting started is simple. Here is your API key [XXX]. Take advantage of our documentation for all the details on implementation via one of our SDKs as well as information on our advanced features. If you have any questions, please let us know, we’re here to help you succeed.
hi@kindlyanswer.me

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

| Header                                     | Name |
| ------------------------------------------ | ---- |
| X-RateLimit-Limit-logged-in-user-limit     |      |
| X-RateLimit-Remaining-logged-in-user-limit |      |
| X-RateLimit-Limit-record-limit             |      |
| X-RateLimit-Remaining-record-limit         |      |
| X-RateLimit-Limit-month                    |      |
| X-RateLimit-Remaining-month                |      |

Once you go over the rate limit you will receive a rate_limit error response.

# Versioning

When we make backward-incompatible changes to any of our APIs, we release new dated versions. Each API we provide has a separate version (listed below).

| API | Current version | Your version |
| --- | --------------- | ------------ |
| CVE | 4/1/2020        | 4/1/2020     |

<!-- - <a href="http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/">http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/</a> -->

<h1 id="api-gateway">Misc</h1>

## What is the MITRE ATT&CK mapping for this CVE

<a id="opIdWhatistheMITREATT&CKmappingforthisCVE?"></a>

> Code samples

```shell
# You can also use wget
curl -X GET http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614 \
  -H 'Accept: application/json' \
  -H 'X-RC: 0' \
  -H 'X-user: string' \
  -H 'X-IP: string' \
  -H 'x-api-key: string'

```

```http
GET http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614 HTTP/1.1
Host: ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000
Accept: application/json
X-RC: 0
X-user: string
X-IP: string
x-api-key: string

```

```javascript
const headers = {
  Accept: "application/json",
  "X-RC": "0",
  "X-user": "string",
  "X-IP": "string",
  "x-api-key": "string",
};

fetch(
  "http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614",
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
  'Accept' => 'application/json',
  'X-RC' => '0',
  'X-user' => 'string',
  'X-IP' => 'string',
  'x-api-key' => 'string'
}

result = RestClient.get 'http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'Accept': 'application/json',
  'X-RC': '0',
  'X-user': 'string',
  'X-IP': 'string',
  'x-api-key': 'string'
}

r = requests.get('http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'Accept' => 'application/json',
    'X-RC' => '0',
    'X-user' => 'string',
    'X-IP' => 'string',
    'x-api-key' => 'string',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('GET','http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614', array(
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
URL obj = new URL("http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614");
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
        "Accept": []string{"application/json"},
        "X-RC": []string{"0"},
        "X-user": []string{"string"},
        "X-IP": []string{"string"},
        "x-api-key": []string{"string"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("GET", "http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`GET /cveintel/CVE/CVE-2020-0614`

_What is the MITRE ATT&CK mapping for this CVE?_

In order to build complex cyber security scenarios one must map more than +100k vulnerabilities (CVEs) to the corresponding MITRE ATT&CK. The benefit of the corresponding controls allows the organization to better prioritize what actions should be taken. We use natural language processing to achieve this task.

<h3 id="whatisthemitreatt&ckmappingforthiscve-parameters">Parameters</h3>

| Name      | In     | Type           | Required | Description                                       |
| --------- | ------ | -------------- | -------- | ------------------------------------------------- |
| X-RC      | header | integer(int32) | true     | Record Count - Used for billing purposes          |
| X-user    | header | string         | true     | User - Extracted from logged in user (WEB API)    |
| X-IP      | header | string         | true     | IP - Extracted from the requesting user (WEB API) |
| x-api-key | header | string         | true     | API Key - Provided to KAM customers               |

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

<h3 id="whatisthemitreatt&ckmappingforthiscve-responses">Responses</h3>

| Status | Meaning                                                 | Description | Schema                                                                                         |
| ------ | ------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------- |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | none        | [What is the MITRE ATT&CK mapping for this CVE](#schemawhatisthemitreatt_ckmappingforthiscve_) |

### Response Headers

| Status | Header                  | Type   | Format | Description |
| ------ | ----------------------- | ------ | ------ | ----------- |
| 200    | Connection              | string |        | none        |
| 200    | Content-Length          | string |        | none        |
| 200    | Date                    | string |        | none        |
| 200    | Server                  | string |        | none        |
| 200    | Via                     | string |        | none        |
| 200    | X-Kong-Proxy-Latency    | string |        | none        |
| 200    | X-Kong-Upstream-Latency | string |        | none        |

<aside class="success">
This operation does not require authentication
</aside>

## Mock Data API Users

<a id="opIdMockDataAPIUsers"></a>

> Code samples

```shell
# You can also use wget
curl -X POST http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users \
  -H 'X-RC: 0' \
  -H 'X-user: string' \
  -H 'X-IP: string' \
  -H 'x-api-key: string'

```

```http
POST http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users HTTP/1.1
Host: ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000

X-RC: 0
X-user: string
X-IP: string
x-api-key: string

```

```javascript
const headers = {
  "X-RC": "0",
  "X-user": "string",
  "X-IP": "string",
  "x-api-key": "string",
};

fetch(
  "http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users",
  {
    method: "POST",

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
  'X-RC' => '0',
  'X-user' => 'string',
  'X-IP' => 'string',
  'x-api-key' => 'string'
}

result = RestClient.post 'http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users',
  params: {
  }, headers: headers

p JSON.parse(result)

```

```python
import requests
headers = {
  'X-RC': '0',
  'X-user': 'string',
  'X-IP': 'string',
  'x-api-key': 'string'
}

r = requests.post('http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users', headers = headers)

print(r.json())

```

```php
<?php

require 'vendor/autoload.php';

$headers = array(
    'X-RC' => '0',
    'X-user' => 'string',
    'X-IP' => 'string',
    'x-api-key' => 'string',
);

$client = new \GuzzleHttp\Client();

// Define array of request body.
$request_body = array();

try {
    $response = $client->request('POST','http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users', array(
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
URL obj = new URL("http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users");
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.setRequestMethod("POST");
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
        "X-RC": []string{"0"},
        "X-user": []string{"string"},
        "X-IP": []string{"string"},
        "x-api-key": []string{"string"},
    }

    data := bytes.NewBuffer([]byte{jsonReq})
    req, err := http.NewRequest("POST", "http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users", data)
    req.Header = headers

    client := &http.Client{}
    resp, err := client.Do(req)
    // ...
}

```

`POST /users-poc/users`

_Mock Data API Users_

In order to build complex cyber security scenarios one must map more than +100k vulnerabilities (CVEs) to the corresponding MITRE ATT&CK. The benefit of the corresponding controls allows the organization to better prioritize what actions should be taken. We use natural language processing to achieve this task.

<h3 id="mockdataapiusers-parameters">Parameters</h3>

| Name      | In     | Type           | Required | Description                                       |
| --------- | ------ | -------------- | -------- | ------------------------------------------------- |
| X-RC      | header | integer(int32) | true     | Record Count - Used for billing purposes          |
| X-user    | header | string         | true     | User - Extracted from logged in user (WEB API)    |
| X-IP      | header | string         | true     | IP - Extracted from the requesting user (WEB API) |
| x-api-key | header | string         | true     | API Key - Must be provided by KAM Staff           |

<h3 id="mockdataapiusers-responses">Responses</h3>

| Status | Meaning                                                 | Description | Schema |
| ------ | ------------------------------------------------------- | ----------- | ------ |
| 200    | [OK](https://tools.ietf.org/html/rfc7231#section-6.3.1) | none        | None   |

<aside class="success">
This operation does not require authentication
</aside>

# CVE API

What is the MITRE ATT&CK mapping for this CVE? Our CVE API takes a CVE and returns the MITRE ATT&CK associated with that CVE. In order to build complex cybersecurity scenarios, one must map more than +130k vulnerabilities (CVEs) to the corresponding MITRE ATT&CK. The benefit of the corresponding controls allows the organization to better prioritize what actions should be taken.

### Lookup a CVE

To use the CVE API, send us a CVE and we’ll return the information we have on it. If we can’t match the CVE to MITRE ATT&CK, we’ll return a 404 HTTP status instead of a 200.

HTTP Request
GET https://api.kindlyanswer.me/cveintel/CVE/CVE-2020-0614

HTTP GET Parameters

| Name      | in     | Type   | Description |
| --------- | ------ | ------ | ----------- |
| X-API-key | header | string | API Key     |

HTTP Response Types

| Coe | Meaning |
| --- | ------- |
| 200 | OK      |

<h2 id="tocS_Result">Attributes</h2>
<!-- backwards compatibility -->
<a id="schemaresult"></a>
<a id="schema_Result"></a>
<a id="tocSresult"></a>
<a id="tocsresult"></a>

```json
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
```

### Properties

| Name             | Type                                      | Required | Restrictions | Description |
| ---------------- | ----------------------------------------- | -------- | ------------ | ----------- |
| CVE              | string                                    | true     | none         | none        |
| CVSS2_Score      | number(double)                            | true     | none         | none        |
| CVSS2_Vector     | string                                    | true     | none         | none        |
| CVSS3_Score      | number(double)                            | true     | none         | none        |
| CVSS3_Vector     | string                                    | true     | none         | none        |
| CWEs             | string                                    | true     | none         | none        |
| Coverage         | string                                    | true     | none         | none        |
| Exploit_Code     | string                                    | true     | none         | none        |
| Industry_Spread  | string                                    | true     | none         | none        |
| Mitre_Techniques | [[MitreTechnique](#schemamitretechnique)] | true     | none         | none        |
| Threat_Activity  | string                                    | true     | none         | none        |

<h2 id="tocS_MitreTechnique">Mitre Technique</h2>
<!-- backwards compatibility -->
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

MitreTechnique

### Properties

| Name                 | Type   | Required | Restrictions | Description |
| -------------------- | ------ | -------- | ------------ | ----------- |
| Technique_ID         | string | true     | none         | none        |
| Technique_Name       | string | true     | none         | none        |
| Technique_Tactic_IDS | string | true     | none         | none        |

<h2 id="tocS_WhatistheMITREATT_CKmappingforthisCVE_">What is the MITRE ATT&CK mapping for this CVE</h2>
<!-- backwards compatibility -->
<a id="schemawhatisthemitreatt_ckmappingforthiscve_"></a>
<a id="schema_WhatistheMITREATT_CKmappingforthisCVE_"></a>
<a id="tocSwhatisthemitreatt_ckmappingforthiscve_"></a>
<a id="tocswhatisthemitreatt_ckmappingforthiscve_"></a>

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

What is the MITRE ATT&CK mapping for this CVE?

### Properties

| Name    | Type                      | Required | Restrictions | Description |
| ------- | ------------------------- | -------- | ------------ | ----------- |
| results | [[Result](#schemaresult)] | true     | none         | none        |
