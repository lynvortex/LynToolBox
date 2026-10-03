/**
 * 绘萤工具箱 - API 配置文件
 * 所有 API 请求通过 PHP 代理 (proxy.php) 转发，密钥保存在服务端
 * 前端不存储任何密钥信息
 */
window.API_CONFIG = {
    // 各接口地址 — 指向本地 PHP 代理（密钥在服务端，安全）
    // 由 network/ 子目录页面使用，路径固定相对站点根一级深度
    apihz: {
        endpoints: {
            port:     '../proxy.php?action=port',
            ping:     '../proxy.php?action=ping',
            icp:      '../proxy.php?action=icp',
            ssl:      '../proxy.php?action=ssl',
            redirect: '../proxy.php?action=redirect',
            phone:    '../proxy.php?action=phone'
        }
    }
};
