<?php
/**
 * 绘萤工具箱 - 管理后台（服务端版本）
 * 安全措施：
 * 1. CSRF Token 防护
 * 2. Session Fixation 防护（登录后重新生成 Session ID）
 * 3. 密码哈希存储在独立 JSON 文件中，不修改 PHP 源文件
 */

require_once __DIR__ . '/config.php';

// ========== 会话安全配置 ==========
$secureCookie = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,                       // 防 XSS 窃取会话 Cookie
    'samesite' => 'Lax',                      // 缓解跨站携带
    'secure'   => $secureCookie,              // HTTPS 部署时仅经加密通道传输
]);
session_start();
// 防 Session Fixation 的另一半：会话中未建立管理员身份前，每次页面加载都轮换 ID
if (empty($_SESSION['admin_logged_in'])) {
    session_regenerate_id(true);
}

// ========== 登录失败限速（防在线爆破，flock 保证并发安全） ==========
function loginThrottleCheck() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $file = sys_get_temp_dir() . '/box_admin_throttle_' . md5($ip);
    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return; // 限速器故障时不阻塞登录
    }
    flock($fp, LOCK_EX);
    $data = json_decode(stream_get_contents($fp), true);
    if (!is_array($data) || !isset($data['fails'], $data['since'])) {
        $data = ['fails' => 0, 'since' => time()];
    }
    if (time() - $data['since'] > 600) { // 10 分钟窗口
        $data = ['fails' => 0, 'since' => time()];
    }
    $blocked = $data['fails'] >= 5;
    if (!$blocked) {
        $data['fails']++;
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if ($blocked) {
        http_response_code(429);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['code' => -1, 'msg' => '失败次数过多，请 10 分钟后再试']);
        exit;
    }
}

function loginThrottleClear() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    @unlink(sys_get_temp_dir() . '/box_admin_throttle_' . md5($ip));
}

// ========== CSRF Token 生成与验证 ==========
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken($token) {
    return !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ========== API 模式处理 ==========
$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action === 'login') {
    header('Content-Type: application/json; charset=utf-8');
    // 安全：未初始化密码哈希时拒绝一切登录（防止 fallback 到公开默认密码）
    if (ADMIN_PASSWORD_HASH === '') {
        http_response_code(503);
        echo json_encode(['code' => -1, 'msg' => '管理后台未初始化：请先在服务器运行 php make-hash.php 生成 data/admin_auth.json']);
        exit;
    }
    // 安全：登录失败限速，防在线爆破
    loginThrottleCheck();
    $password = isset($_POST['password']) ? $_POST['password'] : '';

    if (password_verify($password, ADMIN_PASSWORD_HASH)) {
        loginThrottleClear();
        // 安全：登录后重新生成 Session ID，防止 Session Fixation
        session_regenerate_id(true);
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['login_time'] = time();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        echo json_encode(['code' => 200, 'msg' => '登录成功', 'csrf_token' => $_SESSION['csrf_token']]);
    } else {
        http_response_code(401);
        echo json_encode(['code' => -1, 'msg' => '密码错误']);
    }
    exit;
}

if ($action === 'logout') {
    header('Content-Type: application/json; charset=utf-8');
    $_SESSION = [];
    session_destroy();
    echo json_encode(['code' => 200, 'msg' => '已退出']);
    exit;
}

if ($action === 'check') {
    header('Content-Type: application/json; charset=utf-8');
    $loggedIn = !empty($_SESSION['admin_logged_in']);
    echo json_encode(['code' => $loggedIn ? 200 : 401, 'logged_in' => $loggedIn]);
    exit;
}

if ($action === 'update_pw') {
    header('Content-Type: application/json; charset=utf-8');
    if (empty($_SESSION['admin_logged_in'])) {
        http_response_code(401);
        echo json_encode(['code' => -1, 'msg' => '未登录']);
        exit;
    }
    // CSRF 验证
    $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf_token'] ?? '';
    if (!verifyCsrfToken($csrfToken)) {
        http_response_code(403);
        echo json_encode(['code' => -1, 'msg' => 'CSRF 验证失败']);
        exit;
    }

    $oldPw = isset($_POST['old']) ? $_POST['old'] : '';
    $newPw = isset($_POST['new']) ? $_POST['new'] : '';

    if (!password_verify($oldPw, ADMIN_PASSWORD_HASH)) {
        http_response_code(400);
        echo json_encode(['code' => -1, 'msg' => '旧密码错误']);
        exit;
    }
    if (strlen($newPw) < 6) {
        http_response_code(400);
        echo json_encode(['code' => -1, 'msg' => '新密码至少6位']);
        exit;
    }

    // 安全：密码哈希写入独立 JSON 文件，不修改 PHP 源文件
    $newHash = password_hash($newPw, PASSWORD_BCRYPT);
    $authDir = dirname(ADMIN_AUTH_FILE);
    if (!is_dir($authDir)) {
        mkdir($authDir, 0755, true);
    }
    $result = file_put_contents(ADMIN_AUTH_FILE, json_encode(['hash' => $newHash]), LOCK_EX);

    if ($result === false) {
        http_response_code(500);
        echo json_encode(['code' => -1, 'msg' => '密码保存失败']);
        exit;
    }

    echo json_encode(['code' => 200, 'msg' => '密码修改成功']);
    exit;
}

// 以下接口需要登录验证
$requireAuth = in_array($action, ['get_data', 'save_data', 'get_config']);
if ($requireAuth && empty($_SESSION['admin_logged_in'])) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(401);
    echo json_encode(['code' => -1, 'msg' => '未登录']);
    exit;
}

// save_data 需要 CSRF 验证
if ($action === 'save_data') {
    $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $input = file_get_contents('php://input');
    $parsed = json_decode($input, true);
    $csrfFromBody = $parsed['csrf_token'] ?? '';
    if (!verifyCsrfToken($csrfToken) && !verifyCsrfToken($csrfFromBody)) {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(403);
        echo json_encode(['code' => -1, 'msg' => 'CSRF 验证失败']);
        exit;
    }
}

if ($action === 'get_data') {
    header('Content-Type: application/json; charset=utf-8');
    if (file_exists(DATA_FILE)) {
        readfile(DATA_FILE);
    } else {
        echo json_encode(['code' => -1, 'msg' => '数据文件不存在']);
    }
    exit;
}

if ($action === 'save_data') {
    header('Content-Type: application/json; charset=utf-8');
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);

    if (!$data || !isset($data['tools']) || !isset($data['categories'])) {
        http_response_code(400);
        echo json_encode(['code' => -1, 'msg' => '数据格式错误']);
        exit;
    }

    // 验证数据完整性
    foreach ($data['tools'] as $tool) {
        if (empty($tool['id']) || empty($tool['name']) || empty($tool['url'])) {
            http_response_code(400);
            echo json_encode(['code' => -1, 'msg' => '工具数据不完整：缺少 id/name/url']);
            exit;
        }
    }

    // 安全：校验 URL 协议，杜绝 javascript:/data:/vbscript: 等进入 data.json 造成存储型 XSS
    foreach ($data['tools'] as $tool) {
        if (!isValidToolUrl($tool['url'])) {
            http_response_code(400);
            echo json_encode(['code' => -1, 'msg' => '工具 URL 不合法：' . $tool['url']]);
            exit;
        }
    }

    $result = file_put_contents(DATA_FILE, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);
    if ($result === false) {
        http_response_code(500);
        echo json_encode(['code' => -1, 'msg' => '写入文件失败']);
        exit;
    }

    echo json_encode(['code' => 200, 'msg' => '保存成功']);
    exit;
}

// 工具 URL 只允许站内相对路径与 http(s) 链接
function isValidToolUrl($url) {
    if (!is_string($url) || $url === '' || strlen($url) > 2048) {
        return false;
    }
    if ($url[0] === '/') {
        return true; // 站内根相对路径
    }
    if (preg_match('#^https?://#i', $url)) {
        return true; // http(s) 外链
    }
    // 其余必须是纯相对路径：拒绝任何协议前缀（javascript: data: vbscript: 等）
    return !preg_match('#^[a-z][a-z0-9+.\-]*:#i', $url);
}

if ($action === 'get_config') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'code' => 200,
        'data' => [
            'php_version' => PHP_VERSION,
            'data_file_exists' => file_exists(DATA_FILE),
            'data_file_size' => file_exists(DATA_FILE) ? filesize(DATA_FILE) : 0,
        ]
    ]);
    exit;
}

// ========== 默认：显示管理界面 HTML ==========
$csrfToken = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>绘萤工具箱 - 管理后台</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif; background: #f5f7fa; color: #333; }

        .login-wrap { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-box { background: #fff; border-radius: 12px; padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,.08); width: 360px; }
        .login-box h2 { text-align: center; margin-bottom: 24px; color: #2c3e50; }
        .login-box input { width: 100%; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 15px; margin-bottom: 16px; outline: none; }
        .login-box input:focus { border-color: #4a90e2; }
        .login-box button { width: 100%; padding: 12px; background: #4a90e2; color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; }
        .login-box button:hover { background: #357abd; }
        .login-error { color: #e74c3c; text-align: center; margin-bottom: 12px; font-size: 14px; display: none; }

        .admin-layout { display: none; }
        .admin-header { background: #fff; padding: 16px 24px; border-bottom: 1px solid #eee; display: flex; align-items: center; justify-content: space-between; }
        .admin-header h1 { font-size: 18px; color: #2c3e50; }
        .admin-header .header-actions { display: flex; gap: 10px; align-items: center; }
        .admin-header .logout-btn { background: none; border: 1px solid #e74c3c; color: #e74c3c; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; }
        .admin-header .logout-btn:hover { background: #e74c3c; color: #fff; }
        .admin-header .change-pw-btn { background: none; border: 1px solid #4a90e2; color: #4a90e2; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; }
        .admin-header .change-pw-btn:hover { background: #4a90e2; color: #fff; }

        .admin-body { display: flex; min-height: calc(100vh - 57px); }
        .admin-sidebar { width: 200px; background: #fff; border-right: 1px solid #eee; padding: 16px 0; }
        .admin-sidebar a { display: block; padding: 10px 24px; color: #555; text-decoration: none; font-size: 14px; cursor: pointer; }
        .admin-sidebar a:hover, .admin-sidebar a.active { background: #4a90e2; color: #fff; }

        .admin-main { flex: 1; padding: 24px; overflow-y: auto; }

        .stat-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,.04); }
        .stat-card .num { font-size: 28px; font-weight: 700; color: #4a90e2; }
        .stat-card .label { font-size: 13px; color: #888; margin-top: 4px; }

        .panel { background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,.04); margin-bottom: 24px; }
        .panel-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #f0f0f0; }
        .panel-header h3 { font-size: 16px; }
        .panel-body { padding: 20px; }

        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        th { color: #888; font-weight: 500; background: #fafafa; }
        tr:hover { background: #f8f9ff; }

        .btn { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .btn-primary { background: #4a90e2; color: #fff; }
        .btn-primary:hover { background: #357abd; }
        .btn-danger { background: #e74c3c; color: #fff; }
        .btn-danger:hover { background: #c0392b; }
        .btn-sm { padding: 4px 10px; font-size: 12px; }
        .btn-success { background: #27ae60; color: #fff; }

        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; }
        .badge-green { background: #d4edda; color: #155724; }
        .badge-gray { background: #e9ecef; color: #6c757d; }

        .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.4); z-index: 1000; align-items: center; justify-content: center; }
        .modal-overlay.show { display: flex; }
        .modal { background: #fff; border-radius: 12px; padding: 24px; width: 480px; max-width: 90vw; max-height: 80vh; overflow-y: auto; }
        .modal h3 { margin-bottom: 16px; }
        .modal label { display: block; font-size: 13px; color: #666; margin-bottom: 4px; margin-top: 12px; }
        .modal input, .modal select { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
        .modal-actions { margin-top: 20px; display: flex; gap: 10px; justify-content: flex-end; }
        .modal-actions .btn { padding: 8px 20px; }

        .toggle { position: relative; width: 40px; height: 22px; display: inline-block; }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .toggle .slider { position: absolute; inset: 0; background: #ccc; border-radius: 22px; cursor: pointer; transition: .3s; }
        .toggle .slider:before { content: ''; position: absolute; width: 18px; height: 18px; left: 2px; bottom: 2px; background: #fff; border-radius: 50%; transition: .3s; }
        .toggle input:checked + .slider { background: #4a90e2; }
        .toggle input:checked + .slider:before { transform: translateX(18px); }

        .toast { position: fixed; top: 20px; right: 20px; padding: 12px 20px; border-radius: 8px; color: #fff; font-size: 14px; z-index: 2000; transition: opacity .3s; }
        .toast.success { background: #27ae60; }
        .toast.error { background: #e74c3c; }

        @media (max-width: 768px) {
            .admin-sidebar { display: none; }
            .admin-body { flex-direction: column; }
            .stat-cards { grid-template-columns: 1fr 1fr; }
            table { font-size: 12px; }
            th, td { padding: 6px 8px; }
        }
    </style>
</head>
<body>

<div class="login-wrap" id="loginWrap">
    <div class="login-box">
        <h2>🔐 绘萤工具箱管理后台</h2>
        <div class="login-error" id="loginError">密码错误，请重试</div>
        <input type="password" id="loginPassword" placeholder="请输入管理密码">
        <button onclick="doLogin()">登 录</button>
    </div>
</div>

<div class="admin-layout" id="adminLayout">
    <header class="admin-header">
        <h1>⚙️ 绘萤工具箱 · 管理后台</h1>
        <div class="header-actions">
            <button class="change-pw-btn" onclick="showChangePw()">修改密码</button>
            <button class="logout-btn" onclick="doLogout()">退出登录</button>
        </div>
    </header>
    <div class="admin-body">
        <nav class="admin-sidebar">
            <a class="active" onclick="showSection('dashboard',this)">📊 仪表盘</a>
            <a onclick="showSection('tools',this)">🛠️ 工具管理</a>
            <a onclick="showSection('categories',this)">📁 分类管理</a>
        </nav>
        <main class="admin-main">
            <div id="sec-dashboard">
                <div class="stat-cards" id="statCards"></div>
            </div>
            <div id="sec-tools" style="display:none">
                <div class="panel">
                    <div class="panel-header">
                        <h3>工具列表</h3>
                        <button class="btn btn-primary" onclick="openToolModal()">+ 添加工具</button>
                    </div>
                    <div class="panel-body">
                        <table>
                            <thead><tr><th>ID</th><th>图标</th><th>名称</th><th>分类</th><th>状态</th><th>推荐</th><th>排序</th><th>操作</th></tr></thead>
                            <tbody id="toolsTable"></tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div id="sec-categories" style="display:none">
                <div class="panel">
                    <div class="panel-header">
                        <h3>分类列表</h3>
                        <button class="btn btn-primary" onclick="openCatModal()">+ 添加分类</button>
                    </div>
                    <div class="panel-body">
                        <table>
                            <thead><tr><th>ID</th><th>图标</th><th>名称</th><th>标识</th><th>工具数</th><th>状态</th><th>排序</th><th>操作</th></tr></thead>
                            <tbody id="catsTable"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>
    </div>
</div>

<!-- Tool Modal -->
<div class="modal-overlay" id="toolModal">
    <div class="modal" style="width:600px;max-width:95vw;">
        <h3 id="toolModalTitle">添加工具</h3>
        <input type="hidden" id="toolId">
        <label>分类</label>
        <select id="toolCategory"></select>
        <label>图标 (emoji)</label>
        <input type="text" id="toolIcon" placeholder="如 🌏">
        <label>名称 *</label>
        <input type="text" id="toolName" placeholder="工具名称">
        <label>描述</label>
        <input type="text" id="toolDesc" placeholder="一句话描述">
        <label>URL *</label>
        <input type="text" id="toolUrl" placeholder="如 network/ip-tool.html">
        <label>排序 (越小越前)</label>
        <input type="number" id="toolSort" value="0">
        <label style="display:flex;align-items:center;gap:8px;margin-top:8px;">
            <label class="toggle"><input type="checkbox" id="toolEnabled" checked><span class="slider"></span></label> 启用
        </label>
        <label style="display:flex;align-items:center;gap:8px;">
            <label class="toggle"><input type="checkbox" id="toolFeatured"><span class="slider"></span></label> 首页推荐
        </label>
        <div class="modal-actions">
            <button class="btn" onclick="closeToolModal()" style="background:#eee">取消</button>
            <button class="btn btn-primary" onclick="saveTool()">保存</button>
        </div>
    </div>
</div>

<!-- Category Modal -->
<div class="modal-overlay" id="catModal">
    <div class="modal">
        <h3 id="catModalTitle">添加分类</h3>
        <input type="hidden" id="catId">
        <label>图标 (emoji)</label>
        <input type="text" id="catIcon" placeholder="如 🌐">
        <label>名称 *</label>
        <input type="text" id="catName" placeholder="分类名称">
        <label>标识 (slug) *</label>
        <input type="text" id="catSlug" placeholder="如 network">
        <label>排序</label>
        <input type="number" id="catSort" value="0">
        <label style="display:flex;align-items:center;gap:8px;margin-top:8px;">
            <label class="toggle"><input type="checkbox" id="catEnabled" checked><span class="slider"></span></label> 启用
        </label>
        <div class="modal-actions">
            <button class="btn" onclick="closeCatModal()" style="background:#eee">取消</button>
            <button class="btn btn-primary" onclick="saveCat()">保存</button>
        </div>
    </div>
</div>

<!-- Change Password Modal -->
<div class="modal-overlay" id="pwModal">
    <div class="modal">
        <h3>🔑 修改管理密码</h3>
        <label>旧密码</label>
        <input type="password" id="pwOld" placeholder="请输入旧密码">
        <label>新密码（至少6位）</label>
        <input type="password" id="pwNew" placeholder="请输入新密码">
        <label>确认新密码</label>
        <input type="password" id="pwConfirm" placeholder="再次输入新密码">
        <div class="modal-actions">
            <button class="btn" onclick="closePwModal()" style="background:#eee">取消</button>
            <button class="btn btn-primary" onclick="changePassword()">确认修改</button>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';

    let allTools = [];
    let allCats = [];
    let csrfToken = '';

    // ========== Auth ==========
    async function doLogin() {
        const pw = document.getElementById('loginPassword').value;
        if (!pw) return;
        try {
            const formData = new FormData();
            formData.append('password', pw);
            const res = await fetch('admin.php?action=login', { method: 'POST', body: formData });
            const data = await res.json();
            if (data.code === 200) {
                csrfToken = data.csrf_token || '';
                document.getElementById('loginWrap').style.display = 'none';
                document.getElementById('adminLayout').style.display = 'block';
                showAdmin();
            } else {
                document.getElementById('loginError').style.display = 'block';
            }
        } catch (e) {
            document.getElementById('loginError').textContent = '网络错误: ' + e.message;
            document.getElementById('loginError').style.display = 'block';
        }
    }

    async function doLogout() {
        await fetch('admin.php?action=logout');
        csrfToken = '';
        document.getElementById('loginWrap').style.display = 'flex';
        document.getElementById('adminLayout').style.display = 'none';
    }

    async function checkAuth() {
        try {
            const res = await fetch('admin.php?action=check');
            const data = await res.json();
            return data.logged_in === true;
        } catch {
            return false;
        }
    }

    async function showAdmin() {
        await loadAllData();
        loadDashboard();
    }

    // ========== Data ==========
    async function loadAllData() {
        try {
            const res = await fetch('admin.php?action=get_data');
            const data = await res.json();
            if (data.tools) {
                allTools = data.tools || [];
                allCats = data.categories || [];
            } else {
                allTools = [];
                allCats = [];
            }
        } catch (e) {
            toast('加载数据失败: ' + e.message, 'error');
        }
    }

    async function saveToServer() {
        try {
            const res = await fetch('admin.php?action=save_data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                body: JSON.stringify({ tools: allTools, categories: allCats, csrf_token: csrfToken })
            });
            const data = await res.json();
            if (data.code === 200) {
                toast('保存成功');
            } else {
                toast('保存失败: ' + data.msg, 'error');
            }
        } catch (e) {
            toast('保存失败: ' + e.message, 'error');
        }
    }

    // ========== Toast ==========
    function toast(msg, type) {
        type = type || 'success';
        var el = document.createElement('div');
        el.className = 'toast ' + type;
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(function () {
            el.style.opacity = '0';
            setTimeout(function () { el.remove(); }, 300);
        }, 2000);
    }

    // ========== Navigation ==========
    function showSection(name, el) {
        document.querySelectorAll('[id^="sec-"]').forEach(function (s) { s.style.display = 'none'; });
        document.getElementById('sec-' + name).style.display = 'block';
        document.querySelectorAll('.admin-sidebar a').forEach(function (a) { a.classList.remove('active'); });
        if (el) el.classList.add('active');
        if (name === 'dashboard') loadDashboard();
        if (name === 'tools') loadTools();
        if (name === 'categories') loadCats();
    }

    // ========== Dashboard ==========
    function loadDashboard() {
        var enabled = allTools.filter(function (t) { return t.enabled; }).length;
        var featured = allTools.filter(function (t) { return t.featured; }).length;
        document.getElementById('statCards').innerHTML =
            '<div class="stat-card"><div class="num">' + allTools.length + '</div><div class="label">工具总数</div></div>' +
            '<div class="stat-card"><div class="num">' + enabled + '</div><div class="label">已启用</div></div>' +
            '<div class="stat-card"><div class="num">' + featured + '</div><div class="label">首页推荐</div></div>' +
            '<div class="stat-card"><div class="num">' + allCats.length + '</div><div class="label">分类数</div></div>';
    }

    // ========== 通用工具函数 ==========
    function escapeHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ========== Tools ==========
    function loadTools() {
        var catMap = {};
        allCats.forEach(function (c) { catMap[c.slug] = c.name; });

        document.getElementById('toolsTable').innerHTML = allTools.map(function (t) {
            return '<tr>' +
                '<td>' + escapeHtml(t.id) + '</td>' +
                '<td>' + escapeHtml(t.icon || '') + '</td>' +
                '<td>' + escapeHtml(t.name) + '</td>' +
                '<td>' + escapeHtml(catMap[t.category_slug] || t.category_slug) + '</td>' +
                '<td>' + (t.enabled ? '<span class="badge badge-green">启用</span>' : '<span class="badge badge-gray">禁用</span>') + '</td>' +
                '<td>' + (t.featured ? '⭐' : '-') + '</td>' +
                '<td>' + (t.sort_order || 0) + '</td>' +
                '<td>' +
                    '<button class="btn btn-primary btn-sm" onclick="window.editTool(' + t.id + ')">编辑</button> ' +
                    '<button class="btn btn-danger btn-sm" onclick="window.deleteTool(' + t.id + ')">删除</button>' +
                '</td>' +
                '</tr>';
        }).join('');
    }

    function getNextToolId() {
        var maxId = allTools.reduce(function (max, t) { return Math.max(max, t.id || 0); }, 0);
        return maxId + 1;
    }

    function getNextCatId() {
        var maxId = allCats.reduce(function (max, c) { return Math.max(max, c.id || 0); }, 0);
        return maxId + 1;
    }

    function openToolModal(tool) {
        document.getElementById('toolModalTitle').textContent = tool ? '编辑工具' : '添加工具';
        document.getElementById('toolId').value = tool ? tool.id : '';
        document.getElementById('toolIcon').value = tool ? tool.icon : '';
        document.getElementById('toolName').value = tool ? tool.name : '';
        document.getElementById('toolDesc').value = tool ? tool.description : '';
        document.getElementById('toolSort').value = tool ? tool.sort_order : 0;
        document.getElementById('toolEnabled').checked = tool ? !!tool.enabled : true;
        document.getElementById('toolFeatured').checked = tool ? !!tool.featured : false;
        document.getElementById('toolUrl').value = tool ? tool.url : '';

        var sel = document.getElementById('toolCategory');
        sel.innerHTML = allCats.map(function (c) {
            var selected = tool && tool.category_slug === c.slug ? ' selected' : '';
            return '<option value="' + escapeHtml(c.slug) + '"' + selected + '>' + escapeHtml(c.icon) + ' ' + escapeHtml(c.name) + '</option>';
        }).join('');

        document.getElementById('toolModal').classList.add('show');
    }

    function closeToolModal() { document.getElementById('toolModal').classList.remove('show'); }

    window.editTool = function (id) {
        var tool = allTools.find(function (t) { return t.id === id; });
        if (tool) openToolModal(tool);
    };

    function saveTool() {
        var id = document.getElementById('toolId').value;
        var body = {
            category_slug: document.getElementById('toolCategory').value,
            icon: document.getElementById('toolIcon').value,
            name: document.getElementById('toolName').value,
            description: document.getElementById('toolDesc').value,
            sort_order: parseInt(document.getElementById('toolSort').value) || 0,
            enabled: document.getElementById('toolEnabled').checked ? 1 : 0,
            featured: document.getElementById('toolFeatured').checked ? 1 : 0,
        };

        if (!body.name) { toast('名称必填', 'error'); return; }

        var url = document.getElementById('toolUrl').value.trim();
        if (!url) { toast('URL 必填', 'error'); return; }
        body.url = url;

        if (id) {
            var idx = allTools.findIndex(function (t) { return t.id === parseInt(id); });
            if (idx >= 0) {
                for (var key in body) {
                    if (body.hasOwnProperty(key)) {
                        allTools[idx][key] = body[key];
                    }
                }
                toast('更新成功');
            }
        } else {
            body.id = getNextToolId();
            allTools.push(body);
            toast('添加成功');
        }
        saveToServer();
        closeToolModal();
        loadTools();
    }

    window.deleteTool = function (id) {
        var tool = allTools.find(function (t) { return t.id === id; });
        if (!tool) return;
        if (!confirm('确定删除工具「' + tool.name + '」？')) return;
        allTools = allTools.filter(function (t) { return t.id !== id; });
        saveToServer();
        toast('删除成功');
        loadTools();
    };

    // ========== Categories ==========
    function loadCats() {
        document.getElementById('catsTable').innerHTML = allCats.map(function (c) {
            var toolCount = allTools.filter(function (t) { return t.category_slug === c.slug; }).length;
            return '<tr>' +
                '<td>' + escapeHtml(c.id) + '</td>' +
                '<td>' + escapeHtml(c.icon || '') + '</td>' +
                '<td>' + escapeHtml(c.name) + '</td>' +
                '<td><code>' + escapeHtml(c.slug) + '</code></td>' +
                '<td>' + toolCount + '</td>' +
                '<td>' + (c.enabled ? '<span class="badge badge-green">启用</span>' : '<span class="badge badge-gray">禁用</span>') + '</td>' +
                '<td>' + (c.sort_order || 0) + '</td>' +
                '<td>' +
                    '<button class="btn btn-primary btn-sm" onclick="window.editCat(' + c.id + ')">编辑</button> ' +
                    '<button class="btn btn-danger btn-sm" onclick="window.deleteCat(' + c.id + ')">删除</button>' +
                '</td>' +
                '</tr>';
        }).join('');
    }

    function openCatModal(cat) {
        document.getElementById('catModalTitle').textContent = cat ? '编辑分类' : '添加分类';
        document.getElementById('catId').value = cat ? cat.id : '';
        document.getElementById('catIcon').value = cat ? cat.icon : '';
        document.getElementById('catName').value = cat ? cat.name : '';
        document.getElementById('catSlug').value = cat ? cat.slug : '';
        document.getElementById('catSort').value = cat ? cat.sort_order : 0;
        document.getElementById('catEnabled').checked = cat ? !!cat.enabled : true;
        document.getElementById('catModal').classList.add('show');
    }

    function closeCatModal() { document.getElementById('catModal').classList.remove('show'); }

    window.editCat = function (id) {
        var cat = allCats.find(function (c) { return c.id === id; });
        if (cat) openCatModal(cat);
    };

    function saveCat() {
        var id = document.getElementById('catId').value;
        var body = {
            icon: document.getElementById('catIcon').value,
            name: document.getElementById('catName').value,
            slug: document.getElementById('catSlug').value,
            sort_order: parseInt(document.getElementById('catSort').value) || 0,
            enabled: document.getElementById('catEnabled').checked ? 1 : 0,
        };
        if (!body.name || !body.slug) { toast('名称和标识必填', 'error'); return; }

        if (id) {
            var idx = allCats.findIndex(function (c) { return c.id === parseInt(id); });
            if (idx >= 0) {
                for (var key in body) {
                    if (body.hasOwnProperty(key)) {
                        allCats[idx][key] = body[key];
                    }
                }
                toast('更新成功');
            }
        } else {
            body.id = getNextCatId();
            allCats.push(body);
            toast('添加成功');
        }
        saveToServer();
        closeCatModal();
        loadCats();
    }

    window.deleteCat = function (id) {
        var cat = allCats.find(function (c) { return c.id === id; });
        if (!cat) return;
        if (!confirm('确定删除分类「' + cat.name + '」？')) return;
        allCats = allCats.filter(function (c) { return c.id !== id; });
        saveToServer();
        toast('删除成功');
        loadCats();
    };

    // ========== Password ==========
    function showChangePw() {
        document.getElementById('pwModal').classList.add('show');
    }

    function closePwModal() {
        document.getElementById('pwModal').classList.remove('show');
        document.getElementById('pwOld').value = '';
        document.getElementById('pwNew').value = '';
        document.getElementById('pwConfirm').value = '';
    }

    async function changePassword() {
        var oldPw = document.getElementById('pwOld').value;
        var newPw = document.getElementById('pwNew').value;
        var confirmPw = document.getElementById('pwConfirm').value;

        if (!oldPw || !newPw || !confirmPw) { toast('请填写完整', 'error'); return; }
        if (newPw !== confirmPw) { toast('两次密码不一致', 'error'); return; }
        if (newPw.length < 6) { toast('新密码至少6位', 'error'); return; }

        try {
            var formData = new FormData();
            formData.append('old', oldPw);
            formData.append('new', newPw);
            formData.append('csrf_token', csrfToken);
            var res = await fetch('admin.php?action=update_pw', { method: 'POST', body: formData });
            var data = await res.json();
            if (data.code === 200) {
                toast('密码修改成功，请牢记新密码');
                closePwModal();
            } else {
                toast(data.msg, 'error');
            }
        } catch (e) {
            toast('网络错误: ' + e.message, 'error');
        }
    }

    // ========== Init ==========
    document.getElementById('loginPassword').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') doLogin();
    });

    checkAuth().then(function (loggedIn) {
        if (loggedIn) {
            document.getElementById('loginWrap').style.display = 'none';
            document.getElementById('adminLayout').style.display = 'block';
            showAdmin();
        }
    });

    // Expose functions for inline onclick
    window.doLogin = doLogin;
    window.doLogout = doLogout;
    window.showSection = showSection;
    window.openToolModal = openToolModal;
    window.closeToolModal = closeToolModal;
    window.saveTool = saveTool;
    window.openCatModal = openCatModal;
    window.closeCatModal = closeCatModal;
    window.saveCat = saveCat;
    window.showChangePw = showChangePw;
    window.closePwModal = closePwModal;
    window.changePassword = changePassword;
})();
</script>
<p style="text-align:center;padding:12px;font-size:12px;color:#888;"><a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener" style="color:#4a90e2;text-decoration:underline;font-weight:600;">湘ICP备2026031078号-1</a> <a href="https://beian.mps.gov.cn/#/query/webSearch?code=43050302000259" target="_blank" rel="noopener" style="color:#4a90e2;text-decoration:underline;font-weight:600;margin-left:10px;"><img src="https://beian.mps.gov.cn/web/assets/logo01.6189a29f.png" alt="公安备案徽标" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;border:0;">湘公网安备43050302000259号</a></p>
</body>
</html>
