(function () {
    var statsUrl = window._dc_stats_url || '/api/stats';

    function esc(s) {
        if (s == null) return '';
        var d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    function formatUtc(iso) {
        if (!iso) return '-';
        try {
            var d = new Date(iso);
            if (isNaN(d.getTime())) return '-';
            return d.toISOString().replace('T', ' ').slice(0, 16);
        } catch (e) {
            return '-';
        }
    }

    function renderBars(container, items) {
        if (!container) return;
        if (!items || !items.length) {
            container.innerHTML = '<p class="text-muted dashboard-empty">No data yet.</p>';
            return;
        }
        container.innerHTML = items.map(function (item) {
            var width = item.pct > 0 ? Math.max(item.pct, 2) : 0;
            return (
                '<div class="dashboard-bar-row">' +
                '<span class="dashboard-bar-label">' + esc(item.label) + '</span>' +
                '<div class="dashboard-bar-track">' +
                '<div class="dashboard-bar-fill" style="width:' + width + '%;background:' + esc(item.color) + '"></div>' +
                '</div>' +
                '<span class="dashboard-bar-value">' + esc(item.value) + '</span>' +
                '</div>'
            );
        }).join('');
    }

    function renderRecentAuth(rows) {
        var body = document.getElementById('recent-auth-body');
        if (!body) return;
        if (!rows || !rows.length) {
            body.innerHTML = '<tr><td colspan="4" class="text-muted">No successful authentications yet.</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (row) {
            var acct = row.account_type;
            var badge = acct === 'personal'
                ? '<span class="badge badge-personal">personal</span>'
                : acct === 'corporate'
                    ? '<span class="badge badge-corporate">corporate</span>'
                    : esc(acct);
            return (
                '<tr>' +
                '<td>' + esc(row.display_target) + '</td>' +
                '<td><a href="/campaigns/' + encodeURIComponent(row.campaign_id) + '">' + esc(row.campaign_name) + '</a></td>' +
                '<td>' + badge + '</td>' +
                '<td class="local-time" data-utc="' + esc(row.updated_at || '') + '">' + formatUtc(row.updated_at) + '</td>' +
                '</tr>'
            );
        }).join('');
        if (window._dc_applyLocalTimes) {
            window._dc_applyLocalTimes();
        }
    }

    function renderCampaigns(rows) {
        var body = document.getElementById('campaigns-body');
        if (!body) return;
        if (!rows || !rows.length) {
            body.innerHTML = '<tr><td colspan="4" class="text-muted">No campaigns. <a href="/campaigns/new">Create one</a>.</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (row) {
            return (
                '<tr>' +
                '<td><a href="/campaigns/' + encodeURIComponent(row.id) + '">' + esc(row.name) + '</a></td>' +
                '<td><span class="badge badge-' + esc(row.ui_status) + '">' + esc(row.ui_status) + '</span></td>' +
                '<td>' + esc(row.total_sessions) + '</td>' +
                '<td>' + esc(row.authorized_sessions) + '</td>' +
                '</tr>'
            );
        }).join('');
    }

    function setText(id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function applyStats(d) {
        setText('stat-compromise-rate', d.compromise_rate + '%');
        setText('stat-compromise-meta', d.authorized + ' of ' + d.sessions + ' authorized');
        setText('stat-authorized', d.authorized);
        setText('stat-tokens-meta', d.captured_tokens + ' tokens captured');
        setText('stat-sessions', d.sessions);
        setText('stat-pending-meta', d.pending + ' pending');
        setText('stat-campaigns', d.campaigns);
        setText('stat-running-meta', d.campaigns_running + ' running');
        setText('stat-emails', d.emails_sent);
        setText('stat-delivery-rate', d.delivery_rate);
        setText('stat-expired', d.expired);
        setText('stat-errors', d.error + d.denied);

        setText('badge-corporate', 'corporate ' + d.account_corporate);
        setText('badge-personal', 'personal ' + d.account_personal);
        setText('badge-unknown', 'unknown ' + d.account_unknown);

        var updated = document.getElementById('dashboard-updated');
        if (updated) {
            updated.textContent = 'Updated ' + formatUtc(d.generated_at) + ' UTC';
        }

        renderBars(document.getElementById('outcome-bars'), d.outcomes);
        renderBars(document.getElementById('account-bars'), d.accounts);
        renderRecentAuth(d.recent_authorized);
        renderCampaigns(d.campaigns_recent);
    }

    function loadStats() {
        fetch(statsUrl)
            .then(function (r) { return r.json(); })
            .then(applyStats)
            .catch(function () {
                var kpis = document.getElementById('dashboard-kpis');
                if (kpis) {
                    kpis.innerHTML = '<p class="text-muted">Could not load dashboard stats.</p>';
                }
            });
    }

    loadStats();
    setInterval(loadStats, 10000);

    if (window._dc_socket) {
        window._dc_socket.on('campaign_updated', loadStats);
    }
})();
