---
title: Kong API Gateway copy v1.0
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

<h1 id="kong-api-gateway-copy">Kong API Gateway copy v1.0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

Base URLs:

* <a href="http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/">http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/</a>

<h1 id="kong-api-gateway-copy-misc">Misc</h1>

## WhatistheMITREATT&CKmappingforthisCVE

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
  'Accept':'application/json',
  'X-RC':'0',
  'X-user':'string',
  'X-IP':'string',
  'x-api-key':'string'
};

fetch('http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/cveintel/CVE/CVE-2020-0614',
{
  method: 'GET',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
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

*What is the MITRE ATT&CK mapping for this CVE?*

In order to build complex cyber security scenarios one must map more than +100k vulnerabilities (CVEs) to the corresponding MITRE ATT&CK. The benefit of the corresponding controls allows the organization to better prioritize what actions should be taken. We use natural language processing to achieve this task.

<h3 id="whatisthemitreatt&ckmappingforthiscve-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|X-RC|header|integer(int32)|true|Record Count - Used for billing purposes|
|X-user|header|string|true|User - Extracted from logged in user (WEB API)|
|X-IP|header|string|true|IP - Extracted from the requesting user (WEB API)|
|x-api-key|header|string|true|API Key - Provided to KAM customers|

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

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|[WhatistheMITREATT_CKmappingforthisCVE_](#schemawhatisthemitreatt_ckmappingforthiscve_)|

### Response Headers

|Status|Header|Type|Format|Description|
|---|---|---|---|---|
|200|Connection|string||none|
|200|Content-Length|string||none|
|200|Date|string||none|
|200|Server|string||none|
|200|Via|string||none|
|200|X-Kong-Proxy-Latency|string||none|
|200|X-Kong-Upstream-Latency|string||none|

<aside class="success">
This operation does not require authentication
</aside>

## MockDataAPIUsers

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
  'X-RC':'0',
  'X-user':'string',
  'X-IP':'string',
  'x-api-key':'string'
};

fetch('http://ec2-52-13-73-88.us-west-2.compute.amazonaws.com:20000/users-poc/users',
{
  method: 'POST',

  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
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

*MockDataAPI Users*

In order to build complex cyber security scenarios one must map more than +100k vulnerabilities (CVEs) to the corresponding MITRE ATT&CK. The benefit of the corresponding controls allows the organization to better prioritize what actions should be taken. We use natural language processing to achieve this task.

<h3 id="mockdataapiusers-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|X-RC|header|integer(int32)|true|Record Count - Used for billing purposes|
|X-user|header|string|true|User - Extracted from logged in user (WEB API)|
|X-IP|header|string|true|IP - Extracted from the requesting user (WEB API)|
|x-api-key|header|string|true|API Key - Must be provided by KAM Staff|

<h3 id="mockdataapiusers-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|none|None|

<aside class="success">
This operation does not require authentication
</aside>

# Schemas

<h2 id="tocS_Result">Result</h2>
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

Result

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|CVE|string|true|none|none|
|CVSS2_Score|number(double)|true|none|none|
|CVSS2_Vector|string|true|none|none|
|CVSS3_Score|number(double)|true|none|none|
|CVSS3_Vector|string|true|none|none|
|CWEs|string|true|none|none|
|Coverage|string|true|none|none|
|Exploit_Code|string|true|none|none|
|Industry_Spread|string|true|none|none|
|Mitre_Techniques|[[MitreTechnique](#schemamitretechnique)]|true|none|none|
|Threat_Activity|string|true|none|none|

<h2 id="tocS_MitreTechnique">MitreTechnique</h2>
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

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|Technique_ID|string|true|none|none|
|Technique_Name|string|true|none|none|
|Technique_Tactic_IDS|string|true|none|none|

<h2 id="tocS_WhatistheMITREATT_CKmappingforthisCVE_">WhatistheMITREATT_CKmappingforthisCVE_</h2>
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

WhatistheMITREATT&CKmappingforthisCVE?

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|results|[[Result](#schemaresult)]|true|none|none|

