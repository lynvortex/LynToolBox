<?php
/**
 * 绘萤工具箱 - 配置文件示例
 * 使用方法：复制本文件为 config.php 并填入真实配置。
 * config.php 已被 .gitignore 排除，不会提交到仓库。
 */

// ========== API 密钥配置（apihz.cn，供 proxy.php 使用） ==========
define('API_HZ_ID',  '你的ID');
define('API_HZ_KEY', '你的KEY');

// ========== 数据文件路径 ==========
define('DATA_FILE', __DIR__ . '/data.json');

// ========== 管理员密码存储 ==========
// 密码哈希存储在独立文件 data/admin_auth.json 中（同样不入库）。
// 可通过 /admin.php 后台修改密码；该文件不存在时使用下方默认哈希。
// 注意：源码公开后默认密码即公开，部署后请务必第一时间修改！
define('ADMIN_AUTH_FILE', __DIR__ . '/data/admin_auth.json');

function getAdminPasswordHash() {
    if (file_exists(ADMIN_AUTH_FILE)) {
        $auth = json_decode(file_get_contents(ADMIN_AUTH_FILE), true);
        if ($auth && isset($auth['hash'])) {
            return $auth['hash'];
        }
    }
    // 默认哈希（对应默认密码，部署后请立即修改）
    return '默认密码的password_hash哈希值';
}

define('ADMIN_PASSWORD_HASH', getAdminPasswordHash());
