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
3. 访问 `index.html` 即可使用；`admin.php` 为数据管理后台（首次登录使用默认密码，**请立即修改**）；
4. 工具数据集中在 `data.json`，可通过后台或直接编辑维护。

> `config.php` 与 `data/admin_auth.json` 含密钥/密码，已被 `.gitignore` 排除，请勿提交。

## 目录结构

```
index.html / network.html / ...   分类入口页
network/ text/ image/ work/ ...   各工具页面（纯前端单文件）
assets/                           公共脚本与第三方库
data.json                         工具清单数据（后台可维护）
admin.php / admin/                数据管理后台
proxy.php / config.php            API 代理与配置（服务端专用）
```

## 协议

MIT License，详见 [LICENSE](LICENSE)。
