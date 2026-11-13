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

    // Метка «только что запустили проверку». Короткая проверка (один порт)
    // заканчивается раньше первого опроса прогресса, и таблица не обновлялась.
    var SCAN_KEY = 'ps.scan.start';
    var SCAN_TTL = 15 * 60 * 1000;

    function scanJustStarted() {
        try {
            var at = Number(sessionStorage.getItem(SCAN_KEY) || 0);
            if (!at) return false;
            sessionStorage.removeItem(SCAN_KEY);
            return Date.now() - at < SCAN_TTL;
        } catch (err) {
            return false;
        }
    }

    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!form || !form.matches) return;
        if (form.matches('form[data-keep-scroll]')) {
            try { sessionStorage.setItem(SCROLL_KEY, String(window.scrollY)); } catch (err) { /* ignore */ }
        }
        // формы запуска проверки адреса: /ip/<ip>/scan и /ip/<ip>/scan-port
        var action = form.getAttribute('action') || '';
        if (/\/scan(-port)?$/.test(action)) {
            try { sessionStorage.setItem(SCAN_KEY, String(Date.now())); } catch (err) { /* ignore */ }
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
        var overallPct = 0;
        // сканирование запустили на предыдущей странице: обновим таблицу,
        // даже если задание закончилось до первого опроса
        var pendingScan = scanJustStarted();

        // перечитываем таблицу результатов, сохраняя позицию прокрутки
        function refreshResults(delay) {
            if (window.location.pathname !== '/dashboard') return;
            setTimeout(function () {
                if (window.keepScrollReload) window.keepScrollReload();
                else window.location.reload();
            }, typeof delay === 'number' ? delay : 2000);
        }

        function setText(id, value) {
            var el = document.getElementById(id);
            if (el) el.textContent = value;
        }

        function formatPct(value) {
            var rounded = Math.round(value * 10) / 10;
            return (rounded % 1 === 0 ? rounded.toFixed(0) : rounded.toFixed(1)) + '%';
        }

        function poll() {
            fetch('/api/scan/progress')
                .then(function (r) { return r.json(); })
                .then(function (p) {
                    if (pendingScan) {
                        pendingScan = false;
                        // задание создаётся до возврата на страницу: если оно уже
                        // закончилось, ждать нечего — сразу обновляем таблицу
                        if (!p || !p.log_id || !p.running) {
                            refreshResults(400);
                            return;
                        }
                    }
                    if (!p || !p.log_id) return;
                    if (currentJob !== p.log_id) {
                        currentJob = p.log_id;
                        overallPct = 0;
                    }
                    setText('progRange', p.ip_range);
                    // общий прогресс не должен уменьшаться, когда проверка
                    // добавляет второй круг и общий объём растёт
                    var totalPct = p.percent_total || 0;
                    if (totalPct > overallPct) overallPct = totalPct;
                    setText('progTotalPct', formatPct(overallPct));
                    var phase = p.phase;
                    var isUdp = phase === 'udp' || phase === 'udp_verify';
                    var isVerify = phase === 'verify';
                    var pct = isUdp ? (p.percent_udp || 0)
                            : isVerify ? (p.percent_verify || 0)
                            : (p.percent || 0);
                    if (phase === 'tcp') {
                        setText('progPct', 'tcp сканирование ' + pct + '%');
                        setText('progDone', p.done);
                        setText('progTotal', p.total);
                    } else if (isVerify) {
                        setText('progPct', 'tcp проверка ' + pct + '%');
                        setText('progDone', p.verify_done || 0);
                        setText('progTotal', p.verify_total || 0);
                    } else if (isUdp) {
                        setText('progPct', phase === 'udp_verify'
                            ? 'udp проверка ' + pct + '%'
                            : 'udp сканирование ' + pct + '%');
                        setText('progDone', p.udp_done || 0);
                        setText('progTotal', p.udp_total || 0);
                    } else {
                        // все проверки закончены, задание ещё закрывается
                        setText('progPct', 'обработка');
                    }
                    setText('progOpened', (p.open_found || 0) + (p.closed_found || 0));
                    var bar = document.getElementById('progBar');
                    if (bar) bar.style.width = overallPct + '%';

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
                            refreshResults();
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

        // делегирование: работает и для подсказок, добавленных позже
        document.addEventListener('mouseover', function (e) {
            var el = e.target.closest && e.target.closest('[data-port-tip]');
            if (!el) return;
            tip.textContent = el.dataset.portTip;
            tip.classList.toggle('is-list', el.hasAttribute('data-tip-list'));
            tip.classList.add('is-visible');
            place(e.clientX, e.clientY);
        });
        document.addEventListener('mousemove', function (e) {
            if (tip.classList.contains('is-visible')) place(e.clientX, e.clientY);
        });
        document.addEventListener('mouseout', function (e) {
            var el = e.target.closest && e.target.closest('[data-port-tip]');
            if (!el) return;
            var to = e.relatedTarget;
            if (to && el.contains(to)) return;
            tip.classList.remove('is-visible');
        });
    });

    // ------------------------------------------------- история по адресу
    document.addEventListener('DOMContentLoaded', function () {
        // меню «Проверить» в таблице: fixed-позиционирование, иначе его режет
        // прокручиваемый контейнер таблицы
        if (typeof bootstrap !== 'undefined' && bootstrap.Dropdown) {
            document.querySelectorAll('[data-np-fixed-menu] .dropdown-toggle')
                .forEach(function (btn) {
                    bootstrap.Dropdown.getOrCreateInstance(btn, {
                        popperConfig: {strategy: 'fixed'}
                    });
                });
        }

        var modalEl = document.getElementById('hostHistoryModal');
        if (!modalEl || typeof bootstrap === 'undefined') return;

        var modal = new bootstrap.Modal(modalEl);
        var titleIp = document.getElementById('hostHistoryIp');
        var body = document.getElementById('hostHistoryBody');
        var fullLink = document.getElementById('hostHistoryFull');
        var RECENT_LIMIT = 10;

        function renderHistory(data) {
            if (!body) return;
            if (!data.events || !data.events.length) {
                body.innerHTML = '<div class="text-muted small">' +
                    'Событий по адресу пока нет: адрес сканировался, но порты не менялись.</div>';
                return;
            }
            var all = data.events;
            var recent = all.slice(-RECENT_LIMIT);
            var html = '';
            if (all.length > recent.length) {
                html += '<div class="small-muted mb-2">Последние ' + recent.length +
                    ' из ' + all.length + ' событий</div>';
            }
            recent.forEach(function (e) {
                var closed = e.action !== 'opened';
                var ports = (e.ports || []).map(function (p, i) {
                    var proto = (e.proto && e.proto[i]) === 'udp' ? 'udp' : 'tcp';
                    var cls = (proto === 'udp' ? 'badge-port-udp' : 'badge-port');
                    if (closed) cls += ' np-port-closed';
                    var tip = (proto === 'udp' ? 'UDP' : 'TCP') + ' ' + p;
                    var service = (data.services || {})[String(p)];
                    if (service) tip += ' — ' + service;
                    if (closed) tip += ' · закрыт';
                    return '<span class="badge ' + cls + ' me-1" data-port-tip="' +
                        tip.replace(/"/g, '&quot;') + '">' + p + '</span>';
                }).join('');
                html += '<div class="np-history__row">' +
                    '<span class="np-history__time">' + window.npFmtDt(e.timestamp) + '</span>' +
                    '<span class="np-history__what">' +
                        (e.action === 'opened'
                            ? 'найден порт' + (e.ports.length > 1 ? 'ы' : '')
                            : 'порт' + (e.ports.length > 1 ? 'ы' : '') +
                              ' закрыт' + (e.ports.length > 1 ? 'ы' : '')) +
                    '</span>' +
                    '<span class="np-history__ports">' + ports + '</span>' +
                '</div>';
            });
            body.innerHTML = html;
        }

        function openHistory(ip) {
            if (titleIp) titleIp.textContent = ip;
            if (fullLink) fullLink.href = '/hosts/' + encodeURIComponent(ip) + '/history';
            if (body) body.innerHTML = '<div class="text-muted small">Загрузка…</div>';
            modal.show();
            fetch('/api/hosts/' + encodeURIComponent(ip) + '/history')
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.error) {
                        if (body) body.innerHTML =
                            '<div class="text-danger small">' + data.error + '</div>';
                        return;
                    }
                    renderHistory(data);
                })
                .catch(function () {
                    if (body) body.innerHTML =
                        '<div class="text-danger small">Нет связи с сервером</div>';
                });
        }

        // делегирование: работает и для строк, добавленных позже
        document.addEventListener('click', function (e) {
            var btn = e.target.closest('.ip-link');
            if (!btn || !btn.dataset.ip) return;
            openHistory(btn.dataset.ip);
        });
    });

    // --------------------------------------- порты одного сканирования (лог)
    document.addEventListener('DOMContentLoaded', function () {
        var modalEl = document.getElementById('scanPortsModal');
        if (!modalEl || typeof bootstrap === 'undefined') return;

        var modal = new bootstrap.Modal(modalEl);
        var title = document.getElementById('scanPortsTitle');
        var body = document.getElementById('scanPortsBody');

        function renderPorts(data) {
            if (!body) return;
            if (!data.details_saved) {
                body.innerHTML = '<div class="text-muted small">' +
                    'Данные по этому сканированию не сохранялись.</div>';
                return;
            }
            if (!data.ports || !data.ports.length) {
                body.innerHTML = '<div class="text-muted small">' +
                    'В этом сканировании новые порты не появлялись и закрытых нет.</div>';
                return;
            }
            var html = '<div class="small-muted mb-2">Открыто: ' + data.opened +
                ' · закрыто: ' + data.closed + ' · всего: ' + data.total + '</div>';
            html += '<div class="table-responsive"><table class="table table-sm mb-0">' +
                '<thead><tr><th>Время</th><th>Адрес</th><th>Порт</th>' +
                '<th>Протокол</th><th>Состояние</th></tr></thead><tbody>';
            data.ports.forEach(function (p) {
                var udp = p.proto === 'udp';
                var closed = p.action !== 'opened';
                var cls = udp ? 'badge-port-udp' : 'badge-port';
                if (closed) cls += ' np-port-closed';
                html += '<tr>' +
                    '<td class="small-muted text-nowrap">' + window.npFmtDt(p.timestamp) + '</td>' +
                    '<td class="mono">' + p.ip + '</td>' +
                    '<td><span class="badge ' + cls + '">' + p.port + '</span></td>' +
                    '<td>' + (udp ? 'UDP' : 'TCP') + '</td>' +
                    '<td>' + (closed
                        ? '<span class="badge bg-secondary">закрыт</span>'
                        : '<span class="badge bg-success">открыт</span>') + '</td>' +
                    '</tr>';
            });
            html += '</tbody></table></div>';
            body.innerHTML = html;
        }

        document.addEventListener('click', function (e) {
            var btn = e.target.closest('.np-log-count');
            if (!btn || !btn.dataset.logId) return;
            var id = btn.dataset.logId;
            if (title) title.textContent = '#' + id;
            if (body) body.innerHTML = '<div class="text-muted small">Загрузка…</div>';
            modal.show();
            fetch('/api/logs/' + encodeURIComponent(id) + '/ports')
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.error) {
                        if (body) body.innerHTML =
                            '<div class="text-danger small">' + data.error + '</div>';
                        return;
                    }
                    if (title) {
                        title.textContent = '#' + id + ' · ' + (data.ip_range || '') +
                            ' · ' + window.npFmtDt(data.start_time);
                    }
                    renderPorts(data);
                })
                .catch(function () {
                    if (body) body.innerHTML =
                        '<div class="text-danger small">Нет связи с сервером</div>';
                });
        });
    });
})();
