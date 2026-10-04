# CF-Legacy-Proxy

让不支持现代 TLS/SSL 加密协议的老旧设备（如塞班系统、早期功能机、复古 PDA 等）能够重新访问现代 HTTPS 网站的 Cloudflare Worker 反向代理脚本。

## 功能

* **协议降级**：强制使用 HTTPS 请求目标网站，但向老旧客户端返回纯 HTTP 内容。
* **HSTS 剥离**：自动移除 `Strict-Transport-Security` 响应头，防止浏览器强制跳转 HTTPS。
* **重定向重写**：自动拦截 `Location` 头，将后端返回的 `https://` 重定向链接替换为 `http://`。
* **IP 透传**：保留并传递访客的真实 IP (`X-Real-IP`) 及地理位置信息给后端服务器。
* **跨域支持 (CORS)**：自动添加允许跨域的响应头，方便前端静态资源的加载。

## 部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)，进入 **Workers & Pages**。
2. 点击 **Create Worker**，起个名字并创建。
3. 点击 **Edit code**，将本项目中的代码（`universal-proxy.js`）复制并粘贴替换掉默认代码。
4. 点击右上角的 **Deploy** 保存。

## 配置

为了让脚本知道你需要代理哪个网站，你需要配置一个环境变量：

1. 在你的 Worker 管理页面，进入 **Settings** (设置) -> **Variables and Secrets** (变量和机密)。
2. 在 **Environment Variables** (环境变量) 下点击 **Add**。
3. 添加以下变量：
   * **Variable name**: `TARGET_DOMAIN`
   * **Value**: 你想要代理的目标域名 (例如: `api.github.com` 或 `your-modern-site.com`)
4. **Deploy** 重新部署使配置生效。

**注意**：为了让老手机正常访问，请务必为你的 Worker 绑定一个**未强制开启 HTTPS** 的自定义域名，并使用该自定义域名的 `http://` 协议进行访问。

## 协议

本项目基于 [MIT](LICENSE) 协议开源。
