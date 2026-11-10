/* Универсальные поиск и сортировка для таблиц.
   Разметка: <table id="x" data-table> ... <tr data-row data-ip="..." data-ports="...">
   Заголовки: <th data-sort="ip">
   Поиск: <input data-search-for="x">  Счётчик: <span data-count-for="x"> */
(function () {
    'use strict';

    function rowsOf(tbody) {
        return Array.prototype.slice.call(tbody.querySelectorAll('tr[data-row]'));
    }

    function initTable(table) {
        var tbody = table.tBodies[0];
        if (!tbody) return;
        var rows = rowsOf(tbody);
        var search = document.querySelector('[data-search-for="' + table.id + '"]');
        var counter = document.querySelector('[data-count-for="' + table.id + '"]');
        var sortKey = null;
        var dir = 1;

        function applySearch() {
            if (!search) return;
            var q = search.value.trim().toLowerCase();
            var shown = 0;
            rows.forEach(function (tr) {
                var ok = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
                tr.style.display = ok ? '' : 'none';
                if (ok) shown += 1;
            });
            if (counter) {
                counter.textContent = q ? shown + ' из ' + rows.length : rows.length + ' записей';
            }
        }

        function sortBy(key) {
            dir = (sortKey === key) ? -dir : 1;
            sortKey = key;
            rows.slice().sort(function (a, b) {
                var av = a.dataset[key] === undefined ? '' : a.dataset[key];
                var bv = b.dataset[key] === undefined ? '' : b.dataset[key];
                var an = parseFloat(av.replace(',', '.'));
                var bn = parseFloat(bv.replace(',', '.'));
                var res;
                if (!isNaN(an) && !isNaN(bn) && av !== '' && bv !== '') {
                    res = an - bn;
                } else {
                    res = String(av).localeCompare(String(bv), 'ru');
                }
                return res * dir;
            }).forEach(function (tr) { tbody.appendChild(tr); });

            rows = rowsOf(tbody);
            table.querySelectorAll('th[data-sort]').forEach(function (th) {
                var mark = th.querySelector('.sort-mark');
                if (mark) {
                    mark.textContent = th.dataset.sort === key ? (dir > 0 ? '▲' : '▼') : '';
                }
            });
        }

        table.querySelectorAll('th[data-sort]').forEach(function (th) {
            th.addEventListener('click', function () { sortBy(th.dataset.sort); });
        });

        if (counter) counter.textContent = rows.length + ' записей';
        if (search) search.addEventListener('input', applySearch);
    }

    document.querySelectorAll('table[data-table]').forEach(initTable);
})();
