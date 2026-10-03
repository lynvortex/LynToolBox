/**
 * 绘萤工具箱 - 前端数据加载模块（虚拟主机版）
 * 从 data.json 加载静态数据，无需后端 API
 */

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

(function () {
    let _cachedData = null;

    // data.json 中的字段是用户/管理端可控数据，进入 innerHTML 前必须转义
    const esc = window.escapeHtml;

    // 渲染用 URL 白名单：站内相对路径与 http(s)；拦截 javascript:/data: 等危险协议
    function safeUrl(u) {
        const s = String(u == null ? '' : u).trim();
        if (!s) return '';
        if (/^https?:\/\//i.test(s)) return esc(s);
        if (s[0] === '/') return esc(s);
        if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return '#'; // 含协议前缀但非 http(s)，一律丢弃
        return esc(s);
    }

    async function loadData() {
        if (_cachedData) return _cachedData;
        try {
            // cache: 'no-cache' 强制浏览器每次向服务器验证是否有更新
            // 有更新返回 200 新内容，无更新返回 304 用本地缓存，避免读到旧数据
            const res = await fetch('data.json', { cache: 'no-cache' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            _cachedData = await res.json();
            return _cachedData;
        } catch (e) {
            console.error('[BoxAPI] Failed to load data.json:', e);
            return { categories: [], tools: [] };
        }
    }

    window.BoxAPI = {
        /**
         * 获取所有启用的工具
         * @param {Object} filters - { category, featured, search }
         * @returns {Promise<Array>}
         */
        async getTools(filters = {}) {
            const data = await loadData();
            let tools = data.tools || [];

            if (filters.category) {
                tools = tools.filter(t => t.category_slug === filters.category);
            }
            if (filters.featured !== undefined) {
                tools = tools.filter(t => !!t.featured === !!filters.featured);
            }
            if (filters.search) {
                const q = filters.search.toLowerCase();
                tools = tools.filter(t =>
                    t.name.toLowerCase().includes(q) ||
                    (t.description || '').toLowerCase().includes(q)
                );
            }
            // 只返回启用的工具
            tools = tools.filter(t => t.enabled === 1);

            return tools.sort((a, b) => a.sort_order - b.sort_order);
        },

        /**
         * 获取所有启用的分类
         * @returns {Promise<Array>}
         */
        async getCategories() {
            const data = await loadData();
            return (data.categories || []).filter(c => c.enabled === 1);
        },

        /**
         * 渲染工具卡片 HTML
         * @param {Object} tool - 工具对象
         * @returns {string} HTML 字符串
         */
        renderToolCard(tool) {
            return `
                <a href="${safeUrl(tool.url)}" class="tool-card">
                    <div class="icon-box">${esc(tool.icon || '🔧')}</div>
                    <div class="card-text">
                        <h3>${esc(tool.name)}</h3>
                        <p>${esc(tool.description || '')}</p>
                    </div>
                </a>
            `;
        },

        /**
         * 渲染工具网格
         * @param {HTMLElement} container - 容器元素
         * @param {Array} tools - 工具数组
         */
        renderTools(container, tools) {
            if (!container) return;
            container.innerHTML = tools.map(t => this.renderToolCard(t)).join('');
        },

        /**
         * 渲染侧边栏分类列表
         * @param {HTMLElement} container - category-list 容器
         * @param {Array} categories - 分类数组
         * @param {string} currentSlug - 当前分类标识（用于高亮）
         */
        renderSidebar(container, categories, currentSlug) {
            if (!container) return;
            container.innerHTML = categories.map(c => {
                const active = c.slug === currentSlug ? ' active' : '';
                return `<a href="${c.slug === 'home' ? 'index.html' : safeUrl(c.slug + '.html')}" class="category-item${active}">${esc(c.icon)} ${esc(c.name)}</a>`;
            }).join('');
        }
    };
})();