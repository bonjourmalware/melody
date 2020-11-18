## HTTP
### Rules

|Key|Type|Example|
|---|---|---|
|`http.uri`|*complex*|<pre>http.uri:<br>&nbsp;&nbsp;contains:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "/console/css/%2e"</pre>|
|`http.body`|*complex*|<pre>http.body:<br>&nbsp;&nbsp;contains:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "I made a discovery today."</pre>|
|`http.headers`|*complex*|<pre>http.headers:<br>&nbsp;&nbsp;is:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "User-agent: Mozilla/5.0 zgrab/0.x"</pre>|
|`http.method`|*complex*|<pre>http.method:<br>&nbsp;&nbsp;is:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "POST"</pre>|
|`http.proto`|*complex*|<pre>http.proto:<br>&nbsp;&nbsp;is:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "HTTP/1.1"</pre>|
|`http.tls`|*bool*|<pre>false</pre>|

!!! Note
    HTTP rules applies to HTTPS packets as well.
    
!!! Important
    HTTP being an application protocol, the full packet is assembled from multiple frames and thus does not have its transport information embedded.
     
    However, the reassembled packet data share its session with the TCP frames it comes from. You can link them together by looking up the session.
    
    !!! Note
        Since HTTPS packets are captured by the webserver and not reassembled, they have their own session and are **not** linked with the assembled frames.    

### Log data

!!! Example
    ```json
    {
      "http": {
        "verb": "POST",
        "proto": "HTTP/1.1",
        "uri": "/",
        "src_port": 51746,
        "dst_host": "127.0.0.1",
        "user_agent": "curl/7.58.0",
        "headers": {
          "Accept": "*/*",
          "Content-Length": "14",
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "curl/7.58.0"
        },
        "headers_keys": [
          "User-Agent",
          "Accept",
          "Content-Length",
          "Content-Type"
        ],
        "headers_values": [
          "curl/7.58.0",
          "*/*",
          "14",
          "application/x-www-form-urlencoded"
        ],
        "errors": null,
        "body": {
          "content": "Enter my world",
          "base64": "RW50ZXIgbXkgd29ybGQ=",
          "truncated": false
        },
        "is_tls": false
      },
      "ip": null,
      "timestamp": "2020-11-17T21:16:23.847161686+01:00",
      "session": "buq2v5oo4skos28gfp20",
      "type": "http",
      "src_ip": "127.0.0.1",
      "dst_port": 10080,
      "matches": {},
      "embedded": {}
    }
    ```

## TCP
### Rules
|Key|Type|Example|
|---|---|---|
|`tcp.payload`|*complex*|<pre>tcp.uri:<br>&nbsp;&nbsp;contains:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "/console/css/%2e"<pre>|
|`tcp.flags`|*flags*|<pre>tcp.flags:<br>&nbsp;&nbsp;- "PA"<br>&nbsp;&nbsp;- "S"<pre>|
|`tcp.fragbits`|*flags*|<pre>tcp.fragbits:<br>&nbsp;&nbsp;- "M"</pre>|
|`tcp.dsize`|*number*|<pre>tcp.dsize: 1234</pre>|
|`tcp.seq`|*number*|<pre>tcp.seq: 4321</pre>|
|`tcp.ack`|*number*|<pre>tcp.ack: 0</pre>|
|`tcp.window`|*number*|<pre>tcp.window: 512</pre>|

TCP flags values :

|Keyword|Name|Value|
|---|---|---|
|`F`|FIN|<pre>0x01</pre>|
|`S`|SYN|<pre>0x02</pre>|
|`R`|RST|<pre>0x04</pre>|
|`P`|PSH|<pre>0x08</pre>|
|`A`|ACK|<pre>0x10</pre>|
|`U`|URG|<pre>0x20</pre>|
|`E`|ECE|<pre>0x40</pre>|
|`C`|CWR|<pre>0x80</pre>|
|`0`|NULL|<pre>0x00</pre>|

TCP fragbits values :

|Keyword|Name|Value|
|---|---|---|
|`M`|More Fragments|<pre>0x01</pre>|
|`D`|Don't Fragment| <pre>0x02</pre>|
|`R`|Reserved Bit|<pre>0x04</pre>|

### Log data

!!! Example
    ```json
    {
      "tcp": {
        "window": 512,
        "seq": 1906765553,
        "ack": 2514263732,
        "data_offset": 8,
        "flags": "PA",
        "urgent": 0,
        "payload": {
          "content": "I made a discovery today. I found a computer.\n",
          "base64": "SSBtYWRlIGEgZGlzY292ZXJ5IHRvZGF5LiAgSSBmb3VuZCBhIGNvbXB1dGVyLgo=",
          "truncated": false
        }
      },
      "ip": {
        "version": 4,
        "ihl": 5,
        "tos": 0,
        "length": 99,
        "id": 39114,
        "fragbits": "DF",
        "frag_offset": 0,
        "ttl": 64,
        "protocol": 6
      },
      "timestamp": "2020-11-16T15:50:01.277828+01:00",
      "session": "bup9368o4skolf20rt8g",
      "type": "tcp",
      "src_ip": "127.0.0.1",
      "dst_port": 1234,
      "matches": {},
      "embedded": {}
    }
    ```

## UDP
### Rules

|Key|Type|Example|
|---|---|---|
|`udp.payload`|*complex*|<pre>udp.uri:<br>&nbsp;&nbsp;contains:<br>&nbsp;&nbsp;&nbsp;&nbsp;- "/console/css/%2e"<pre>|
|`udp.checksum`|*number*|<pre>udp.checksum: 0xfe37</pre>|
|`udp.length`|*number*|<pre>udp.length: 36</pre>|
|`udp.dsize`|*number*|<pre>udp.dsize: 28</pre>|

!!! Tip
    `udp.dsize` check the payload size, while the `udp.length` check the UDP packet's length.

### Log data

!!! Example

    ```json
    {
      "udp": {
        "payload": {
          "content": "I made a discovery today. I found a computer.\n",
          "base64": "SSBtYWRlIGEgZGlzY292ZXJ5IHRvZGF5LiBJIGZvdW5kIGEgY29tcHV0ZXIuCg==",
          "truncated": false
        },
        "length": 54,
        "checksum": 65097
      },
      "ip": {
        "version": 4,
        "ihl": 5,
        "tos": 0,
        "length": 74,
        "id": 3230,
        "fragbits": "DF",
        "frag_offset": 0,
        "ttl": 64,
        "protocol": 17
      },
      "timestamp": "2020-11-17T19:02:12.90819+01:00",
      "session": "buq1090o4sktrqnfoe6g",
      "type": "udp",
      "src_ip": "127.0.0.1",
      "dst_port": 1234,
      "matches": {},
      "embedded": {}
    }
    ```

## ICMPv4
### Rules

|Key|Type|Example|
|---|---|---|
|`icmpv4.type`|*number*|<pre>icmpv4.type: 0x8</pre>|
|`icmpv4.typecode`|*number*|<pre>icmpv4.typecode: 2048</pre>|
|`icmpv4.checksum`|*number*|<pre>icmpv4.checksum: 0x0416</pre>|
|`icmpv4.code`|*number*|<pre>icmpv4.code: 0</pre>|
|`icmpv4.seq`|*number*|<pre>icmpv4.seq: 1</pre>|

### Log data

!!! Example

    ```json
    {
      "icmpv4": {
        "type_code": 2048,
        "type": 8,
        "code": 0,
        "type_code_name": "EchoRequest",
        "checksum": 23981,
        "id": 8140,
        "seq": 1
      },
      "ip": {
        "version": 4,
        "ihl": 5,
        "tos": 0,
        "length": 84,
        "id": 50747,
        "fragbits": "DF",
        "frag_offset": 0,
        "ttl": 64,
        "protocol": 1
      },
      "timestamp": "2020-11-17T19:05:24.541282+01:00",
      "session": "n/a",
      "type": "icmpv4",
      "src_ip": "127.0.0.1",
      "dst_port": 0,
      "matches": {},
      "embedded": {}
    }
    ```

## ICMPv6
### Rules

|Key|Type|Example|
|---|---|---|
|`icmpv6.type`|*number*|<pre>icmpv6.type: 0x80</pre>|
|`icmpv6.typecode`|*number*|<pre>icmpv6.typecode: 32768</pre>|
|`icmpv6.checksum`|*number*|<pre>icmpv6.checksum: 0x275b</pre>|
|`icmpv6.code`|*number*|<pre>icmpv6.code: 0</pre>|

### Log data

!!! Example

    ```json
    {
      "icmpv6": {
        "type_code": 32768,
        "type": 128,
        "code": 0,
        "type_code_name": "EchoRequest",
        "checksum": 55474
      },
      "ip": {
        "version": 6,
        "length": 64,
        "next_header": 58,
        "next_header_name": "ICMPv6",
        "traffic_class": 0,
        "flow_label": 366894,
        "hop_limit": 64
      },
      "timestamp": "2020-11-17T19:06:25.056576+01:00",
      "session": "n/a",
      "type": "icmpv6",
      "src_ip": "::1",
      "dst_port": 0,
      "matches": {},
      "embedded": {}
    }
    ```
