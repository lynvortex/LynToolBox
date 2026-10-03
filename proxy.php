<?php
/**
 * 绘萤工具箱 - API 代理文件
 * 将 API 密钥保存在服务端，前端通过此代理调用第三方 API
 *
 * 安全措施：
 * 1. 频率限制（flock 加锁，防并发绕过）
 * 2. SSL 证书验证 - 防止中间人攻击
 * 3. 同源限制 - 不再开放跨域，防止第三方站点白嫖 API 配额
 */

require_once __DIR__ . '/config.php';

// ========== 接口映射 ==========
$endpoints = [
    'port'     => 'https://cn.apihz.cn/api/wangzhan/port.php',
    'ping'     => 'https://cn.apihz.cn/api/wangzhan/ping.php',
    'icp'      => 'https://cn.apihz.cn/api/wangzhan/icpf.php',
    'ssl'      => 'https://cn.apihz.cn/api/wangzhan/sslq.php',
    'redirect' => 'https://cn.apihz.cn/api/wangzhan/tiaozhuan.php',
    'phone'    => 'https://cn.apihz.cn/api/ip/shouji.php',
    'portscan' => 'https://v2.xxapi.cn/api/portscan',
];

// ========== 参数映射 ==========
$paramMap = [
    'port'     => ['host', 'port', 'type'],
    'ping'     => ['host'],
    'icp'      => ['domain'],
    'ssl'      => ['url'],
    'redirect' => ['url'],
    'phone'    => ['phone'],
    'portscan' => ['address'],
];

// ========== 频率限制（flock 保证并发安全） ==========
function checkRateLimit() {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $limitFile = sys_get_temp_dir() . '/box_rate_' . md5($clientIp);

    $fp = @fopen($limitFile, 'c+');
    if (!$fp) {
        return; // 限速器自身故障时不阻塞正常业务
    }
    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw, true);
    if (!is_array($data) || !isset($data['count'], $data['time'])) {
        $data = ['count' => 0, 'time' => time()];
    }

    // 每分钟最多 15 次请求
    if (time() - $data['time'] > 60) {
        $data = ['count' => 1, 'time' => time()];
    } else {
        $data['count']++;
    }

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    if ($data['count'] > 15) {
        http_response_code(429);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['code' => -1, 'msg' => '请求过于频繁，请稍后再试']);
        exit;
    }
}

// ========== 处理请求 ==========
header('Content-Type: application/json; charset=utf-8');

// 页面与代理同源部署，无需开放跨域；开放 * 等于把付费 API 配额公开给任意第三方站点
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$action = isset($_GET['action']) ? trim($_GET['action']) : '';
if (!$action || !isset($endpoints[$action])) {
    checkRateLimit();
    http_response_code(400);
    echo json_encode(['code' => -1, 'msg' => '无效的 action 参数']);
    exit;
}

// 频率限制检查（action 合法之后才计数，避免无效请求白白消耗额度）
checkRateLimit();

// SSRF 防护：检查用户传入的主机参数（防止把内网地址交给第三方探测接口）
$hostParams = ['host', 'domain', 'url', 'address'];
foreach ($paramMap[$action] as $key) {
    if (in_array($key, $hostParams) && isset($_GET[$key])) {
        if (isPrivateAddress($_GET[$key])) {
            http_response_code(403);
            echo json_encode(['code' => -1, 'msg' => '出于安全考虑，不允许查询内网地址']);
            exit;
        }
    }
}

$apiUrl = $endpoints[$action];
$params = ['id' => API_HZ_ID, 'key' => API_HZ_KEY];

// 收集该 action 所需的参数
foreach ($paramMap[$action] as $key) {
    if (isset($_GET[$key])) {
        $params[$key] = $_GET[$key];
    }
}

// 构建完整 URL
$query = http_build_query($params);
$fullUrl = $apiUrl . '?' . $query;

// 使用 cURL 发起请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $fullUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
// 安全：启用 SSL 证书验证
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; BoxLynvortex/1.0)');

// 安全处理 FOLLOWLOCATION（兼容 open_basedir 限制）
$followLocation = ini_get('open_basedir') ? false : true;
if ($followLocation) {
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
}

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($error) {
    // 详细错误只写日志，避免向客户端泄露服务器内网信息
    error_log('[proxy.php] action=' . $action . ' curl error: ' . $error);
    http_response_code(502);
    echo json_encode(['code' => -1, 'msg' => '代理请求失败，请稍后再试']);
    exit;
}

http_response_code($httpCode);
echo $response;

// ========== SSRF 防护：检查是否为内网地址 ==========
function isPrivateAddress($host) {
    // 移除协议前缀和路径
    $host = preg_replace('#^(https?://)?#i', '', $host);
    $host = explode('/', $host)[0];
    // IPv6 字面量 [::1] → ::1
    $host = trim($host, '[]');

    if ($host === '') {
        return true; // 空主机名一律拒绝
    }
    // IPv6 字面量（含冒号）直接按 IP 校验
    if (strpos($host, ':') !== false) {
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    // 检查特殊主机名
    $blockedHosts = ['localhost', '0.0.0.0', 'metadata.google.internal', '169.254.169.254'];
    foreach ($blockedHosts as $b) {
        if (strcasecmp($host, $b) === 0) return true;
    }

    // 主机本身就是 IP 字面量时直接校验（覆盖十六进制/十进制等写法之外的标准形式）
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
        && filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    // 解析 IP 地址
    $ip = gethostbyname($host);
    if ($ip === $host) return false; // 无法解析（如纯 IPv6 域名），放行交给第三方接口

    // 检查私有 IP 段
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return true; // 是私有或保留地址
    }

    return false;
}
