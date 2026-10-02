/**
 * 绘萤工具箱 - 侧边栏共享模块
 * 所有工具文件通过 <script src="assets/sidebar.js"></script> 引入
 * 在每个文件底部调用 initSidebar('current-slug') 初始化
 * 保留原有 CSS 样式，仅复用 HTML 结构
 */
(function () {
    'use strict';

    /**
     * 全局 HTML 转义函数，防止 XSS 攻击
     * @param {*} str - 需要转义的字符串
     * @returns {string} 转义后的安全字符串
     */
    window.escapeHtml = function (str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    // 计算相对于根目录的路径前缀
    // 通过 <script> 标签的 src 属性推断：页面引用 sidebar.js 时用的相对路径即为路径前缀
    // 根目录页面: src="assets/sidebar.js"     → 前缀 "./"
    // 子目录页面: src="../assets/sidebar.js"  → 前缀 "../"
    var pathPrefix = (function() {
        var scripts = document.querySelectorAll('script[src*="sidebar.js"]');
        if (scripts.length > 0) {
            var src = scripts[scripts.length - 1].getAttribute('src');
            var match = src.match(/^((?:\.\.\/)+)assets\/sidebar\.js/);
            if (match) return match[1];
        }
        return './';
    })();

    const SIDEBAR_HTML = '\
        <header class="mobile-header">\
            <div class="mobile-brand">绘萤工具箱</div>\
            <button class="menu-toggle" id="menuOpen">☰</button>\
        </header>\
        <div class="overlay" id="overlay"></div>\
        <nav class="sidebar" id="sidebar">\
            <div class="brand-header">\
                <div class="brand-name-wrap">\
                    <img class="brand-icon" src="' + pathPrefix + 'logo.webp" alt="绘萤工具箱" />\
                    <div class="brand-name">绘萤工具箱</div>\
                </div>\
                <button class="close-sidebar" id="menuClose">✕</button>\
            </div>\
            <div class="category-list" id="categoryList">\
                <a href="' + pathPrefix + 'index.html" class="category-item" data-slug="home">🏠 首页推荐</a>\
                <a href="' + pathPrefix + 'network.html" class="category-item" data-slug="network">🌐 网络工具</a>\
                <a href="' + pathPrefix + 'text.html" class="category-item" data-slug="text">📝 文本处理</a>\
                <a href="' + pathPrefix + 'image.html" class="category-item" data-slug="image">🖼️ 图像工具</a>\
                <a href="' + pathPrefix + 'work.html" class="category-item" data-slug="work">⚙️ 编程开发</a>\
                <a href="' + pathPrefix + 'media.html" class="category-item" data-slug="media">🎬 音视频处理</a>\
                <a href="' + pathPrefix + 'document.html" class="category-item" data-slug="document">📄 文档处理</a>\
                <a href="' + pathPrefix + 'daily.html" class="category-item" data-slug="daily">🕐 日常通用</a>\
                <a href="' + pathPrefix + 'offline.html" class="category-item" data-slug="offline">📦 离线版&源代码</a>\
            </div>\
        </nav>';

    /**
     * 全局状态栏更新函数
     * @param {string} msg - 状态消息文本
     * @param {string} type - 状态类型: 'success' | 'error' | 'info'
     */
    window.setStatus = function (msg, type) {
        var sb = document.getElementById('statusBar');
        if (sb) { sb.textContent = msg; sb.className = 'status-bar ' + (type || 'info'); }
    };

    window.initSidebar = function (currentSlug) {
        // 防止重复注入
        if (document.getElementById('sidebar')) return;

        // 注入侧边栏 HTML 到 body 最前面
        const temp = document.createElement('div');
        temp.innerHTML = SIDEBAR_HTML;
        while (temp.firstChild) {
            document.body.insertBefore(temp.firstChild, document.body.firstChild);
        }

        // 高亮当前分类
        if (currentSlug) {
            const items = document.querySelectorAll('#categoryList .category-item');
            for (let i = 0; i < items.length; i++) {
                if (items[i].getAttribute('data-slug') === currentSlug) {
                    items[i].classList.add('active');
                }
            }
        }

        // 绑定移动端菜单事件
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        const menuOpen = document.getElementById('menuOpen');
        const menuClose = document.getElementById('menuClose');

        if (menuOpen) {
            menuOpen.addEventListener('click', function () {
                sidebar.classList.add('active');
                overlay.classList.add('active');
            });
        }

        const closeMenu = function () {
            sidebar.classList.remove('active');
            overlay.classList.remove('active');
        };

        if (menuClose) {
            menuClose.addEventListener('click', closeMenu);
        }
        if (overlay) {
            overlay.addEventListener('click', closeMenu);
        }

        // 动态加载平台增强模块（命令面板）
        var enhanceScripts = ['command-palette.js'];
        enhanceScripts.forEach(function (name) {
            if (document.querySelector('script[src*="' + name + '"]')) return;
            var s = document.createElement('script');
            s.src = pathPrefix + 'assets/' + name;
            s.async = true;
            document.body.appendChild(s);
        });
    };
})();