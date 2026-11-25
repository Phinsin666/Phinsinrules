# Phinsin个人自用配置

## 微信 RSS 图片修复

用于修复 NetNewsWire 等原样渲染 RSS 内容的阅读器中，搜狗微信订阅图片因
`img2.jintiankansha.me` 返回 403 而无法显示的问题。插件会从失效代理 URL
中提取 `mmbiz.qpic.cn` 原图地址，并移除会触发微信防盗链占位图的 Referer，
无需 MitM。

```text
https://raw.githubusercontent.com/Phinsin666/Phinsinrules/main/plugin/wechat_rss_image_fix_v2/wechat_rss_image_fix_v2.lpx
```

## 国内 CDN 与直连优化

用于修复国内网站虽然直连、但因 DNS/CDN 调度或规则遗漏而绕行境外节点的问题。规则不包含节点、订阅地址或密钥。

- Loon 插件：`plugin/domestic_cdn_direct/domestic_cdn_direct.lpx`
- 统一域名源：`rules/domestic_cdn_direct/domains.txt`
- Mihomo/Clash 规则集：`rules/domestic_cdn_direct/DomesticCDN.yaml`

### Loon

安装以下插件即可同时应用国内加密 DNS 与 DIRECT 规则，无需再订阅单独的 `.list`：

```text
https://raw.githubusercontent.com/Phinsin666/Phinsinrules/main/plugin/domestic_cdn_direct/domestic_cdn_direct.lpx
```

### Mihomo / Clash Verge Rev

```yaml
rule-providers:
  DomesticCDN:
    type: http
    behavior: domain
    format: yaml
    interval: 86400
    url: https://raw.githubusercontent.com/Phinsin666/Phinsinrules/main/rules/domestic_cdn_direct/DomesticCDN.yaml
    path: ./ruleset/DomesticCDN.yaml
```

在 `dns.nameserver-policy` 中让 `rule-set:DomesticCDN` 使用国内 DoH，并在 `rules` 中加入：

```yaml
- RULE-SET,DomesticCDN,DIRECT
```
