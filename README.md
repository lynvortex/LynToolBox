# 绘萤工具箱 (LynToolBox)

清爽的在线工具箱：200+ 免费工具，纯前端处理、数据不上传。

- 在线使用：<https://box.lynvortex.top>
- 命令行版：<https://github.com/lynvortex/LynToolBox-cli>

## 功能分类

🌐 网络工具 · 📝 文本处理 · 🖼️ 图像工具 · ⚙️ 编程开发 · 🎬 音视频处理 · 📄 文档处理 · 🕐 日常通用

支持全局搜索（Ctrl+K 命令面板）、工具直达链接、独立部署。

## 部署

纯静态 + 少量 PHP（仅数据管理后台与 API 代理），任意支持 PHP 8 的虚拟主机 / Apache / Nginx 均可：

1. 将本仓库全部文件上传到站点根目录；
2. 复制 `config.example.php` 为 `config.php`，填入你的 API 密钥（不使用管理后台与代理功能可留空）；
3. **初始化管理后台**：在站点根目录执行 `php make-hash.php 你的密码`，按提示把生成的 JSON 保存为 `data/admin_auth.json`（`data/` 目录不存在请先创建）。项目不内置任何默认密码，未初始化前 `admin.php` 会拒绝登录；之后可在后台「修改密码」中直接更改；
4. 访问 `index.html` 即可使用；`admin.php` 为数据管理后台；
5. 工具数据集中在 `data.json`，可通过后台或直接编辑维护。

> `config.php` 与 `data/admin_auth.json` 含密钥/密码，已被 `.gitignore` 排除，请勿提交。

## 安全说明

- 管理后台：登录失败限速（10 分钟 5 次）、Session Cookie 加固（HttpOnly / SameSite / HTTPS 下 Secure）、写文件加锁防并发损坏；
- 前端渲染：工具卡片与各工具页对数据统一转义，SVG 预览/压缩在 iframe 沙箱中渲染（脚本不执行）；
- API 代理：仅限同源调用（不做跨域开放）、频率限制 15 次/分钟/IP，代理只转发到固定接口；
- 服务器需支持 `flock` 与 `sys_get_temp_dir()`（频率限制/登录限速使用）。

## 目录结构

```
index.html / network.html / ...   分类入口页
network/ text/ image/ work/ ...   各工具页面（纯前端单文件）
assets/                           公共脚本与第三方库
data.json                         工具清单数据（后台可维护）
admin.php / admin/                数据管理后台
make-hash.php                     管理密码哈希生成器（仅命令行执行，Web 访问被拒绝）
proxy.php / config.php            API 代理与配置（服务端专用）
```

## 协议

MIT License，详见 [LICENSE](LICENSE)。
