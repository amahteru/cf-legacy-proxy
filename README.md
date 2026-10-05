# CF-Legacy-Proxy

让不支持现代 TLS/SSL 加密协议的老旧设备（如塞班系统、早期功能机、复古 PDA 等）能够访问现代 HTTPS 网站的 Cloudflare Worker 反向代理脚本。

## 功能

* **协议降级**：向客户端返回纯 HTTP 内容，自动剥离 HSTS 与 CSP，防止浏览器强制跳转 HTTPS。
* **链接重写**：自动拦截 `Location` 重定向，并将网页及资源（HTML/CSS/JS/JSON）中的源站链接替换为代理地址。
* **状态保持**：自动移除 Cookie 中的 `Secure` 与 `Domain`，确保纯 HTTP 下正常保持登录态。
* **字符转码**：自动将 GBK/GB2312 等编码转为 UTF-8，防止网页字符乱码。
* **透传与跨域**：透传访客真实 IP (`X-Real-IP`) 与压缩协商，并自动添加 CORS 跨域响应头。

## 部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)，进入 **Workers & Pages**。
2. 点击 **Create Worker**，起名并创建。
3. 点击 **Edit code**，将本项目中的代码（`cf-legacy-proxy.js`）复制粘贴替换默认代码。
4. 点击右上角的 **Deploy** 保存。

## 配置

为了让脚本知道你需要代理哪个网站，你需要配置一个环境变量：

1. 在你的 Worker 管理页面，进入 **Settings** (设置) -> **Variables and Secrets** (变量和机密)。
2. 在 **Environment Variables** (环境变量) 下点击 **Add**。
3. 添加以下变量：
   * **Variable name**: `TARGET_DOMAIN`
   * **Value**: 你想要代理的目标域名 (例如: `api.github.com` 或 `your-modern-site.com`)
4. **Deploy** 重新部署使配置生效。

**注意**：为了正常访问，为你的 Worker 绑定一个**未强制开启 HTTPS** 的自定义域名（并在 Cloudflare 边缘证书设置中关闭“始终使用 HTTPS”）。

## 协议

本项目基于 [MIT](LICENSE) 协议开源。
