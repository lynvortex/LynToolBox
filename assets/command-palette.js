/**
 * 绘萤工具箱 - 全局命令面板 Cmd+K / Ctrl+K
 * 在任意页面按 Cmd+K (Mac) 或 Ctrl+K (Win) 唤出搜索面板
 * 从 data.json 加载全部工具，支持模糊搜索与键盘导航跳转
 */
(function () {
    'use strict';

    var palette = null;
    var input = null;
    var results = null;
    var allTools = [];
    var selectedIdx = 0;
    var pathPrefix = (function () {
        var scripts = document.querySelectorAll('script[src*="sidebar.js"]');
        if (scripts.length > 0) {
            var src = scripts[scripts.length - 1].getAttribute('src');
            var match = src.match(/^((?:\.\.\/)+)assets\/sidebar\.js/);
            if (match) return match[1];
        }
        return './';
    })();

    function injectStyles() {
        var style = document.createElement('style');
        style.textContent = '\
.cmd-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.4);z-index:99998;backdrop-filter:blur(4px);}\
.cmd-overlay.active{display:block;}\
.cmd-palette{position:fixed;top:15%;left:50%;transform:translateX(-50%);width:90%;max-width:560px;background:#fff;border-radius:12px;box-shadow:0 8px 40px rgba(0,0,0,0.2);z-index:99999;overflow:hidden;}\
.cmd-input-wrap{padding:16px 20px;border-bottom:1px solid #f0f2f5;}\
.cmd-input{width:100%;border:none;outline:none;font-size:16px;color:#2c3e50;background:transparent;font-family:inherit;}\
.cmd-input::placeholder{color:#94a3b8;}\
.cmd-results{max-height:400px;overflow-y:auto;}\
.cmd-item{display:flex;align-items:center;gap:12px;padding:12px 20px;cursor:pointer;transition:background 0.15s;text-decoration:none;color:#333;}\
.cmd-item:hover,.cmd-item.selected{background:#ebf5ff;}\
.cmd-item-icon{width:32px;height:32px;border-radius:50%;background:#f0f5ff;display:flex;align-items:center;justify-content:center;font-size:1.1em;flex-shrink:0;}\
.cmd-item-text{flex:1;min-width:0;}\
.cmd-item-name{font-size:0.9em;font-weight:600;color:#2c3e50;}\
.cmd-item-desc{font-size:0.78em;color:#909399;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}\
.cmd-item-cat{font-size:0.7em;color:#4a90e2;background:#ebf5ff;padding:2px 8px;border-radius:10px;flex-shrink:0;}\
.cmd-empty{text-align:center;padding:30px;color:#94a3b8;font-size:0.85em;}\
.cmd-hint{text-align:center;padding:8px;font-size:0.72em;color:#c0c4cc;border-top:1px solid #f0f2f5;}\
.cmd-hint kbd{background:#f1f5f9;padding:1px 6px;border-radius:4px;font-size:0.9em;}\
';
        document.head.appendChild(style);
    }

    function createPalette() {
        injectStyles();
        var overlay = document.createElement('div');
        overlay.className = 'cmd-overlay';
        overlay.innerHTML = '\
<div class="cmd-palette">\
<div class="cmd-input-wrap"><input type="text" class="cmd-input" placeholder="🔎 搜索工具名称或功能..." autocomplete="off"/></div>\
<div class="cmd-results" id="cmdResults"></div>\
<div class="cmd-hint"><kbd>↑↓</kbd> 导航 <kbd>Enter</kbd> 跳转 <kbd>Esc</kbd> 关闭</div>\
</div>';
        document.body.appendChild(overlay);
        palette = overlay;
        input = overlay.querySelector('.cmd-input');
        results = overlay.querySelector('#cmdResults');

        overlay.addEventListener('click', function (e) { if (e.target === overlay) hide(); });
        input.addEventListener('input', doSearch);
        input.addEventListener('keydown', handleKeydown);
    }

    function handleKeydown(e) {
        var items = results.querySelectorAll('.cmd-item');
        if (e.key === 'ArrowDown') { e.preventDefault(); selectedIdx = Math.min(items.length - 1, selectedIdx + 1); updateSelection(); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); selectedIdx = Math.max(0, selectedIdx - 1); updateSelection(); }
        else if (e.key === 'Enter') { e.preventDefault(); if (items[selectedIdx]) items[selectedIdx].click(); }
        else if (e.key === 'Escape') { e.preventDefault(); hide(); }
    }

    function updateSelection() {
        var items = results.querySelectorAll('.cmd-item');
        items.forEach(function (item, idx) { item.classList.toggle('selected', idx === selectedIdx); });
        if (items[selectedIdx]) items[selectedIdx].scrollIntoView({ block: 'nearest' });
    }

    function doSearch() {
        var q = input.value.trim().toLowerCase();
        var filtered;
        if (!q) {
            filtered = allTools.slice(0, 20);
        } else {
            filtered = allTools.filter(function (t) {
                return t.name.toLowerCase().indexOf(q) >= 0 || (t.description || '').toLowerCase().indexOf(q) >= 0;
            }).slice(0, 30);
        }
        selectedIdx = 0;
        if (filtered.length === 0) {
            results.innerHTML = '<div class="cmd-empty">没有找到匹配的工具</div>';
            return;
        }
        results.innerHTML = filtered.map(function (t, i) {
            var url = t.url.indexOf('http') === 0 ? t.url : pathPrefix + t.url;
            return '<a href="' + url + '" class="cmd-item' + (i === 0 ? ' selected' : '') + '">\
<div class="cmd-item-icon">' + (t.icon || '🔧') + '</div>\
<div class="cmd-item-text"><div class="cmd-item-name">' + escapeHtml(t.name) + '</div><div class="cmd-item-desc">' + escapeHtml(t.description || '') + '</div></div>\
<div class="cmd-item-cat">' + escapeHtml(t.category_slug) + '</div></a>';
        }).join('');
    }

    function show() {
        if (!palette) createPalette();
        palette.classList.add('active');
        input.value = '';
        if (allTools.length === 0) loadTools();
        else doSearch();
        setTimeout(function () { input.focus(); }, 50);
    }

    function hide() { if (palette) palette.classList.remove('active'); }

    function loadTools() {
        fetch(pathPrefix + 'data.json', { cache: 'no-cache' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                allTools = (data.tools || []).filter(function (t) { return t.enabled === 1; });
                doSearch();
            })
            .catch(function (e) { results.innerHTML = '<div class="cmd-empty">加载失败</div>'; });
    }

    document.addEventListener('keydown', function (e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            if (palette && palette.classList.contains('active')) hide();
            else show();
        }
        if (e.key === 'Escape' && palette && palette.classList.contains('active')) hide();
    });

    // 导出
    window.CommandPalette = { show: show, hide: hide };
})();
