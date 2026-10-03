<?php
/**
 * 绘萤工具箱 - 管理密码哈希生成器（仅命令行使用）
 *
 * 用法:
 *   php make-hash.php <密码>
 *   php make-hash.php           （交互输入，不回显在命令历史里）
 *
 * 生成后按提示写入 data/admin_auth.json（或手工保存）。
 * 通过浏览器访问本文件会被直接拒绝。
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Forbidden');
}

echo "绘萤工具箱 管理密码哈希生成器\n";

if (isset($argv[1]) && $argv[1] !== '') {
    $password = $argv[1];
} else {
    echo "请输入新密码: ";
    $password = trim(fgets(STDIN));
}
if (strlen($password) < 6) {
    fwrite(STDERR, "错误: 密码至少 6 位\n");
    exit(1);
}

$hash = password_hash($password, PASSWORD_BCRYPT);
echo "\nbcrypt 哈希:\n" . $hash . "\n\n";
echo "请将以下内容保存为 data/admin_auth.json（data 目录不存在请先创建）:\n\n";
echo json_encode(['hash' => $hash], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
