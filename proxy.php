<?php
/**
 * 绘萤工具箱 - API 代理文件
 * 将 API 密钥保存在服务端，前端通过此代理调用第三方 API
 *
 * 安全措施：
 * 1. SSRF 防护 - 拒绝内网地址
 * 2. SSL 证书验证 - 防止中间人攻击
 * 3. 频率限制 - 防止 API 滥用
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

// ========== SSRF 防护：检查是否为内网地址 ==========
function isPrivateAddress($host) {
    // 移除协议前缀和路径
    $host = preg_replace('#^(https?://)?#', '', $host);
    $host = explode('/', $host)[0];
    $host = explode(':', $host)[0];

    // 检查特殊主机名
    $blockedHosts = ['localhost', '0.0.0.0', 'metadata.google.internal'];
    foreach ($blockedHosts as $b) {
        if (strcasecmp($host, $b) === 0) return true;
    }

    // 解析 IP 地址
    $ip = gethostbyname($host);
    if ($ip === $host) return false; // 无法解析，放行（可能是域名）

    // 检查私有 IP 段
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return true; // 是私有或保留地址
    }

    return false;
}

// ========== 频率限制 ==========
function checkRateLimit() {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $limitFile = sys_get_temp_dir() . '/box_rate_' . md5($clientIp);

    $data = ['count' => 0, 'time' => time()];
    if (file_exists($limitFile)) {
        $data = json_decode(file_get_contents($limitFile), true) ?: $data;
    }

    // 每分钟最多 15 次请求
    if (time() - $data['time'] > 60) {
        $data = ['count' => 1, 'time' => time()];
    } else {
        $data['count']++;
    }

    file_put_contents($limitFile, json_encode($data));

    if ($data['count'] > 15) {
        http_response_code(429);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['code' => -1, 'msg' => '请求过于频繁，请稍后再试']);
        exit;
    }
}

// ========== 处理请求 ==========
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: *');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// 频率限制检查
checkRateLimit();

$action = isset($_GET['action']) ? trim($_GET['action']) : '';
if (!$action || !isset($endpoints[$action])) {
    http_response_code(400);
    echo json_encode(['code' => -1, 'msg' => '无效的 action 参数']);
    exit;
}

// SSRF 防护：检查用户传入的主机参数
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
    http_response_code(502);
    echo json_encode(['code' => -1, 'msg' => '代理请求失败: ' . $error]);
    exit;
}

http_response_code($httpCode);
echo $response;
