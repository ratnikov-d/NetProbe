/* Тема оформления + сохранение позиции прокрутки при POST-переходах. */
(function () {
    'use strict';

    // 2026-11-12T10:20:19 -> 2026.11.12 10:20:19
    window.npFmtDt = function (value) {
        if (!value) return '—';
        var s = String(value).trim();
        if (s.length >= 19 && s[4] === '-' && s[7] === '-' && (s[10] === 'T' || s[10] === ' ')) {
            return s.slice(0, 4) + '.' + s.slice(5, 7) + '.' + s.slice(8, 10) +
                ' ' + s.slice(11, 19);
        }
        return s;
    };

    // всплывающее уведомление внизу экрана
    var toastTimer = null;
    window.npToast = function (text) {
        var t = document.getElementById('npToast');
        if (!t) return;
        t.textContent = text;
        t.classList.add('is-visible');
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { t.classList.remove('is-visible'); }, 3000);
    };

    var THEME_KEY = 'ps.theme';
    var SCROLL_KEY = 'ps.scroll';
    var root = document.documentElement;

    function applyTheme(theme) {
        root.setAttribute('data-theme', theme);
        var btn = document.getElementById('themeToggle');
        if (btn) {
            btn.textContent = theme === 'dark' ? '☀' : '☾';
            btn.title = theme === 'dark' ? 'Светлая тема' : 'Тёмная тема';
            btn.setAttribute('aria-label', btn.title);
        }
    }

    var saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (e) { /* приватный режим */ }
    var preferred = saved || (window.matchMedia &&
        window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    applyTheme(preferred);

    document.addEventListener('click', function (e) {
        var btn = e.target.closest('#themeToggle');
        if (!btn) return;
        var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(THEME_KEY, next); } catch (err) { /* ignore */ }
        applyTheme(next);
    });

    // --- прокрутка: возвращаемся туда же после отправки формы ---
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (form && form.matches && form.matches('form[data-keep-scroll]')) {
            try { sessionStorage.setItem(SCROLL_KEY, String(window.scrollY)); } catch (err) { /* ignore */ }
        }
    }, true);

    window.addEventListener('load', function () {
        var y = null;
        try { y = sessionStorage.getItem(SCROLL_KEY); } catch (e) { /* ignore */ }
        if (y !== null) {
            try { sessionStorage.removeItem(SCROLL_KEY); } catch (e) { /* ignore */ }
            window.scrollTo(0, parseInt(y, 10) || 0);
        }
    });

    window.keepScrollReload = function () {
        try { sessionStorage.setItem(SCROLL_KEY, String(window.scrollY)); } catch (e) { /* ignore */ }
        window.location.reload();
    };

    // ------------------------------------------------- прогресс сканирования

    document.addEventListener('DOMContentLoaded', function () {
    applyTheme(root.getAttribute('data-theme') || 'light');
    var line = document.getElementById('scanLine');
    var chip = document.getElementById('scanChip');
    if (line && chip) {
        var wasRunning = false;
        var stopping = false;
        var currentJob = null;

        function setText(id, value) {
            var el = document.getElementById(id);
            if (el) el.textContent = value;
        }

        function poll() {
            fetch('/api/scan/progress')
                .then(function (r) { return r.json(); })
                .then(function (p) {
                    if (!p || !p.log_id) return;
                    currentJob = p.log_id;
                    setText('progRange', p.ip_range);
                    var isUdp = p.phase === 'udp' || (!p.running && (p.udp_total || 0) > 0);
                    var pct = isUdp ? p.percent_udp || 0 : p.percent || 0;
                    setText('progPct', isUdp ? 'обработка ' + pct + '%' :
                            (p.phase === 'finishing' ? 'обработка' : pct + '%'));
                    setText('progDone', isUdp ? p.udp_done || 0 : p.done);
                    setText('progTotal', isUdp ? p.udp_total || 0 : p.total);
                    setText('progOpened', p.open_found);
                    var bar = document.getElementById('progBar');
                    if (bar) bar.style.width = pct + '%';

                    var dot = document.getElementById('scanDot');
                    var stop = document.getElementById('stopBtn');

                    if (p.running) {
                        wasRunning = true;
                        line.classList.add('is-active');
                        chip.classList.add('is-visible');
                        if (dot) dot.classList.remove('is-done');
                        if (stop) stop.disabled = stopping;
                        return;
                    }

                    if (wasRunning) {
                        wasRunning = false;
                        if (dot) dot.classList.add('is-done');
                        setText('progPct', p.status === 'completed' ? 'готово' :
                                p.status === 'stopped' ? 'остановлено' : 'прервано');
                        if (stop) stop.style.display = 'none';
                        setTimeout(function () {
                            chip.classList.remove('is-visible');
                            line.classList.remove('is-active');
                        }, 1600);
                        if (window.location.pathname === '/dashboard') {
                            setTimeout(function () {
                                if (window.keepScrollReload) window.keepScrollReload();
                                else window.location.reload();
                            }, 2000);
                        }
                    } else {
                        line.classList.remove('is-active');
                        chip.classList.remove('is-visible');
                    }
                })
                .catch(function () {});
        }

        // немедленный опрос после запуска сканирования из массовых действий
        window.npStartProgressWatch = function () {
            wasRunning = false;
            stopping = false;
            if (stopBtn) stopBtn.style.display = '';
            poll();
        };

        var stopBtn = document.getElementById('stopBtn');
        if (stopBtn) {
            stopBtn.addEventListener('click', function () {
                if (!currentJob) return;
                stopping = true;
                this.disabled = true;
                fetch('/api/scan/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ log_id: currentJob })
                });
            });
        }

        poll();
        setInterval(poll, 1000);
    }
    });

    document.addEventListener('DOMContentLoaded', function () {
        var items = document.querySelectorAll('[data-port-tip]');
        if (!items.length) return;

        var tip = document.createElement('div');
        tip.className = 'floating-tip';
        document.body.appendChild(tip);

        function place(x, y) {
            var pad = 12;
            var r = tip.getBoundingClientRect();
            var left = Math.min(Math.max(pad, x - r.width / 2), window.innerWidth - r.width - pad);
            var top = y - r.height - 12;
            if (top < pad) top = y + 20;
            tip.style.left = left + 'px';
            tip.style.top = top + 'px';
        }

        items.forEach(function (el) {
            el.addEventListener('mouseenter', function (e) {
                tip.textContent = el.dataset.portTip;
                tip.classList.add('is-visible');
                place(e.clientX, e.clientY);
            });
            el.addEventListener('mousemove', function (e) { place(e.clientX, e.clientY); });
            el.addEventListener('mouseleave', function () { tip.classList.remove('is-visible'); });
        });
    });
})();
