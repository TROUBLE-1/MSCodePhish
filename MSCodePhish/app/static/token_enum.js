(function () {
    var cfg = window._tokenEnumConfig;
    if (!cfg || !cfg.tokenId) return;

    var navItems = document.querySelectorAll('.token-enum-nav-item');
    var sectionTitle = document.getElementById('token-enum-section-title');
    var statusEl = document.getElementById('token-enum-status');
    var errorEl = document.getElementById('token-enum-error');
    var loadingEl = document.getElementById('token-enum-loading');
    var thead = document.getElementById('token-enum-thead');
    var tbody = document.getElementById('token-enum-tbody');
    var refreshBtn = document.getElementById('token-enum-refresh');
    var nextBtn = document.getElementById('token-enum-next');

    var openModalBtn = document.getElementById('token-enum-open-modal');
    var closeModalBtn = document.getElementById('token-enum-close-modal');
    var modalOverlay = document.getElementById('token-enum-popup-overlay');
    var tokenModal = document.getElementById('token-enum-modal');
    var modeBadge = document.getElementById('token-enum-mode-badge');
    var headerClientName = document.getElementById('enum-header-client-name');
    var headerClientId = document.getElementById('enum-header-client-id');

    var jwtDisplay = document.getElementById('token-enum-jwt-display');
    var copyJwtBtn = document.getElementById('token-enum-copy-jwt');
    var refetchBtn = document.getElementById('token-enum-refetch');
    var applyCustomBtn = document.getElementById('token-enum-apply-custom');
    var useDisplayJwtBtn = document.getElementById('token-enum-use-display-jwt');
    var customJwtInput = document.getElementById('token-enum-custom-jwt');
    var refreshPanel = document.getElementById('token-enum-refresh-panel');
    var customPanel = document.getElementById('token-enum-custom-panel');
    var tokenStatusEl = document.getElementById('token-enum-token-status');
    var modeRadios = document.querySelectorAll('input[name="token-enum-mode"]');
    var scopeBtn = document.getElementById('token-scopes-btn');
    var scopeTooltip = document.getElementById('token-scopes-tooltip');
    var scopeTooltipBody = document.getElementById('token-scopes-tooltip-body');
    var scopePopover = document.getElementById('token-scope-popover');

    var activeSection = (cfg.sections && cfg.sections[0]) || 'users';
    var nextLink = null;
    var appendMode = false;
    var sectionTotals = {};

    var enumAccessToken = (cfg.initialAccessToken || '').trim();
    var tokenMode = 'refresh';

    function esc(s) {
        if (s == null) return '';
        var d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    function isRealJwt(token) {
        return !!(token && token.indexOf('.') !== -1 && token.split('.').length >= 2);
    }

    function updateModeBadge() {
        if (!modeBadge) return;
        modeBadge.textContent = tokenMode === 'custom' ? 'Custom JWT' : 'Refresh token';
        modeBadge.classList.toggle('is-custom', tokenMode === 'custom');
    }

    function setJwtDisplay(token) {
        enumAccessToken = (token || '').trim();
        if (jwtDisplay) {
            jwtDisplay.textContent = enumAccessToken || '(no access token — re-fetch or paste a custom JWT)';
        }
    }

    function setTokenStatus(msg, isError) {
        if (!tokenStatusEl) return;
        tokenStatusEl.textContent = msg || '';
        tokenStatusEl.classList.toggle('is-error', !!isError);
    }

    function renderScopeTooltip(tokenScopes, errorNote) {
        if (!scopeTooltipBody) return;
        var html = '';
        if (tokenScopes && tokenScopes.scp) {
            html += '<p class="label-hint" style="margin:0 0 0.35rem;">JWT <code>scp</code></p>';
            html += '<div class="token-enum-scopes-value">' + esc(tokenScopes.scp) + '</div>';
        } else if (tokenScopes && tokenScopes.roles && tokenScopes.roles.length) {
            html += '<p class="label-hint" style="margin:0 0 0.35rem;">JWT <code>roles</code></p>';
            html += '<div class="token-enum-scopes-value">' + esc(tokenScopes.roles.join(' ')) + '</div>';
        } else {
            html += '<p class="text-muted">No <code>scp</code> or <code>roles</code> claim in the current access token.</p>';
        }
        if (tokenScopes && tokenScopes.aud) {
            html += '<p class="token-enum-scopes-aud">aud: <code>' + esc(tokenScopes.aud) + '</code></p>';
        }
        if (errorNote) {
            html += '<p class="token-enum-scopes-note">Note: ' + esc(errorNote) + '</p>';
        }
        scopeTooltipBody.innerHTML = html;

        var count = 0;
        if (tokenScopes) {
            if (tokenScopes.scopes && tokenScopes.scopes.length) {
                count = tokenScopes.scopes.length;
            } else if (tokenScopes.roles && tokenScopes.roles.length) {
                count = tokenScopes.roles.length;
            }
        }
        if (scopeBtn) {
            scopeBtn.textContent = count ? ('JWT scopes (' + count + ')') : 'JWT scopes';
        }
    }

    function fetchJwtInfo(token) {
        if (!cfg.jwtInfoUrl || !isRealJwt(token)) {
            return Promise.resolve(null);
        }
        return fetch(cfg.jwtInfoUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ access_token: token }),
        })
            .then(function (r) { return r.json(); })
            .then(function (d) { return d.ok ? d.token_scopes : null; })
            .catch(function () { return null; });
    }

    function applyToken(token, sourceLabel, closeOnSuccess) {
        if (!isRealJwt(token)) {
            setTokenStatus('Enter a valid JWT access token (three base64 segments).', true);
            return Promise.resolve(false);
        }
        setJwtDisplay(token);
        updateModeBadge();
        setTokenStatus('Using ' + (sourceLabel || 'custom JWT') + ' for Graph enumeration.');
        return fetchJwtInfo(token).then(function (scopes) {
            if (scopes) renderScopeTooltip(scopes);
            loadAllCounts();
            loadSection(activeSection);
            if (closeOnSuccess) closeTokenModal();
            return true;
        });
    }

    function showOverlay() {
        if (modalOverlay) {
            modalOverlay.style.display = 'block';
            modalOverlay.setAttribute('aria-hidden', 'false');
        }
    }

    function hideOverlay() {
        if (modalOverlay) {
            modalOverlay.style.display = 'none';
            modalOverlay.setAttribute('aria-hidden', 'true');
        }
    }

    function openTokenModal() {
        if (!tokenModal) return;
        showOverlay();
        tokenModal.style.display = 'block';
        setTokenStatus('');
    }

    function closeTokenModal() {
        if (tokenModal) tokenModal.style.display = 'none';
        hideOverlay();
    }

    function enumFetchHeaders() {
        var headers = {};
        if (tokenMode === 'custom' && enumAccessToken && isRealJwt(enumAccessToken)) {
            headers['X-Enum-Access-Token'] = enumAccessToken;
        }
        return headers;
    }

    function setActiveNav(sectionId) {
        navItems.forEach(function (btn) {
            btn.classList.toggle('active', btn.getAttribute('data-section') === sectionId);
        });
    }

    function showError(msg) {
        if (!errorEl) return;
        if (msg) {
            errorEl.textContent = msg;
            errorEl.style.display = 'block';
        } else {
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        }
    }

    function setLoading(on) {
        if (loadingEl) loadingEl.style.display = on ? 'block' : 'none';
        if (refreshBtn) refreshBtn.disabled = on;
        if (nextBtn) nextBtn.disabled = on;
        if (refetchBtn) refetchBtn.disabled = on;
    }

    function setNavCount(sectionId, count) {
        var badge = document.querySelector('.token-enum-nav-count[data-section="' + sectionId + '"]');
        if (!badge) return;
        if (count == null || count === undefined || Number.isNaN(count)) {
            badge.textContent = '—';
            return;
        }
        badge.textContent = String(count);
    }

    function updateStatusText(sectionId, shownCount, totalCount, hasMore) {
        if (!statusEl) return;
        var total = totalCount != null ? totalCount : sectionTotals[sectionId];
        var parts = ['Live Graph data'];
        if (tokenMode === 'custom') {
            parts.push('custom JWT');
        }
        if (total != null && total !== undefined) {
            parts.push(shownCount + ' of ' + total + ' shown');
        } else {
            parts.push(shownCount + ' row(s) shown');
        }
        if (hasMore) {
            parts.push('more available');
        }
        statusEl.textContent = parts.join(' · ');
    }

    function loadAllCounts() {
        if (!cfg.countsUrl) return;
        fetch(cfg.countsUrl, { headers: enumFetchHeaders() })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (!d.ok || !d.counts) return;
                Object.keys(d.counts).forEach(function (sid) {
                    var val = d.counts[sid];
                    if (val != null) {
                        sectionTotals[sid] = val;
                        setNavCount(sid, val);
                    }
                });
                if (sectionTotals[activeSection] != null) {
                    var shown = tbody ? tbody.querySelectorAll('tr').length : 0;
                    updateStatusText(activeSection, shown, sectionTotals[activeSection], !!nextLink);
                }
            })
            .catch(function () { /* counts are optional */ });
    }

    function renderTable(columns, rows, isAppend) {
        if (!thead || !tbody) return;
        if (!isAppend) {
            thead.innerHTML = '<tr>' + columns.map(function (col) {
                return '<th>' + esc(col.label) + '</th>';
            }).join('') + '</tr>';
            tbody.innerHTML = '';
        }
        if (!rows.length && !isAppend) {
            tbody.innerHTML = '<tr><td colspan="' + columns.length + '" class="text-muted">No results returned.</td></tr>';
            return;
        }
        rows.forEach(function (row) {
            var tr = document.createElement('tr');
            tr.innerHTML = columns.map(function (col) {
                return '<td>' + esc(row[col.key] != null ? row[col.key] : '-') + '</td>';
            }).join('');
            tbody.appendChild(tr);
        });
    }

    function loadSection(sectionId, options) {
        options = options || {};
        appendMode = !!options.append;
        if (!appendMode) {
            nextLink = null;
            if (nextBtn) nextBtn.style.display = 'none';
        }

        activeSection = sectionId;
        setActiveNav(sectionId);
        var navBtn = document.querySelector('.token-enum-nav-item[data-section="' + sectionId + '"]');
        if (sectionTitle && navBtn) {
            sectionTitle.textContent = navBtn.getAttribute('data-label') || sectionId;
        }

        showError(null);
        setLoading(true);
        if (!appendMode && tbody) {
            tbody.innerHTML = '<tr><td class="text-muted">Loading…</td></tr>';
        }

        var url = cfg.apiBase + sectionId;
        var params = new URLSearchParams();
        if (appendMode && nextLink) {
            params.set('next', nextLink);
        }
        if (params.toString()) {
            url += '?' + params.toString();
        }

        fetch(url, { headers: enumFetchHeaders() })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                setLoading(false);
                if (!d.ok) {
                    showError(d.error || 'Enumeration failed');
                    if (!appendMode && tbody) {
                        tbody.innerHTML = '<tr><td class="text-muted">Request failed.</td></tr>';
                    }
                    return;
                }
                renderTable(d.columns || [], d.rows || [], appendMode);
                nextLink = d.next_link || null;
                if (d.total_count != null) {
                    sectionTotals[sectionId] = d.total_count;
                    setNavCount(sectionId, d.total_count);
                }
                var totalShown = (tbody && tbody.querySelectorAll('tr').length) || d.count || 0;
                updateStatusText(
                    sectionId,
                    totalShown,
                    d.total_count != null ? d.total_count : sectionTotals[sectionId],
                    !!nextLink
                );
                if (nextBtn) {
                    nextBtn.style.display = nextLink ? 'inline-block' : 'none';
                }
            })
            .catch(function () {
                setLoading(false);
                showError('Network error while calling Microsoft Graph.');
                if (!appendMode && tbody) {
                    tbody.innerHTML = '<tr><td class="text-muted">Request failed.</td></tr>';
                }
            });
    }

    function refetchAccessToken() {
        setTokenStatus('Requesting new access token…');
        if (refetchBtn) refetchBtn.disabled = true;

        fetch(cfg.accessTokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (refetchBtn) refetchBtn.disabled = false;
                if (!d.ok) {
                    setTokenStatus(d.error || 'Token refresh failed', true);
                    return;
                }
                tokenMode = 'refresh';
                updateModeBadge();
                setJwtDisplay(d.access_token || '');
                if (d.token_scopes) renderScopeTooltip(d.token_scopes);
                setTokenStatus('Token refreshed using campaign client and Graph (.default).');
                loadAllCounts();
                loadSection(activeSection);
            })
            .catch(function () {
                if (refetchBtn) refetchBtn.disabled = false;
                setTokenStatus('Network error while refreshing token.', true);
            });
    }

    function setTokenMode(mode) {
        tokenMode = mode;
        updateModeBadge();
        var isCustom = mode === 'custom';
        if (refreshPanel) refreshPanel.hidden = isCustom;
        if (customPanel) customPanel.hidden = !isCustom;
    }

    navItems.forEach(function (btn) {
        btn.addEventListener('click', function () {
            loadSection(btn.getAttribute('data-section'));
        });
    });

    if (refreshBtn) {
        refreshBtn.addEventListener('click', function () {
            loadSection(activeSection);
            loadAllCounts();
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', function () {
            if (nextLink) {
                loadSection(activeSection, { append: true });
            }
        });
    }

    if (openModalBtn) openModalBtn.addEventListener('click', openTokenModal);
    if (closeModalBtn) closeModalBtn.addEventListener('click', closeTokenModal);
    if (modalOverlay) {
        modalOverlay.addEventListener('click', closeTokenModal);
    }

    if (refetchBtn) refetchBtn.addEventListener('click', refetchAccessToken);

    if (applyCustomBtn) {
        applyCustomBtn.addEventListener('click', function () {
            tokenMode = 'custom';
            updateModeBadge();
            var token = customJwtInput ? customJwtInput.value.trim() : '';
            applyToken(token, 'custom JWT', false);
        });
    }

    if (useDisplayJwtBtn) {
        useDisplayJwtBtn.addEventListener('click', function () {
            tokenMode = 'custom';
            updateModeBadge();
            applyToken(enumAccessToken, 'displayed JWT', true);
        });
    }

    if (copyJwtBtn) {
        copyJwtBtn.addEventListener('click', function () {
            if (!enumAccessToken || !isRealJwt(enumAccessToken)) {
                setTokenStatus('Nothing to copy — fetch or paste a JWT first.', true);
                return;
            }
            navigator.clipboard.writeText(enumAccessToken).then(function () {
                copyJwtBtn.textContent = 'Copied';
                setTimeout(function () { copyJwtBtn.textContent = 'Copy'; }, 1500);
            }).catch(function () {
                setTokenStatus('Copy failed — select the JWT text manually.', true);
            });
        });
    }

    modeRadios.forEach(function (radio) {
        radio.addEventListener('change', function () {
            if (radio.checked) setTokenMode(radio.value);
        });
    });

    function closeScopeTooltip() {
        if (!scopeTooltip || !scopeBtn) return;
        scopeTooltip.hidden = true;
        scopeBtn.setAttribute('aria-expanded', 'false');
    }

    function toggleScopeTooltip() {
        if (!scopeTooltip || !scopeBtn) return;
        var open = scopeTooltip.hidden;
        scopeTooltip.hidden = !open;
        scopeBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    if (scopeBtn && scopeTooltip) {
        scopeBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            toggleScopeTooltip();
        });
    }

    document.addEventListener('click', function (e) {
        if (!scopePopover || !scopeTooltip || scopeTooltip.hidden) return;
        if (!scopePopover.contains(e.target)) {
            closeScopeTooltip();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            if (tokenModal && tokenModal.style.display === 'block') {
                closeTokenModal();
            } else {
                closeScopeTooltip();
            }
        }
    });

    if (headerClientName) headerClientName.textContent = cfg.defaultClientName || '';
    if (headerClientId) headerClientId.textContent = cfg.defaultClientId || '';

    updateModeBadge();
    if (isRealJwt(enumAccessToken)) {
        fetchJwtInfo(enumAccessToken).then(function (scopes) {
            if (scopes) renderScopeTooltip(scopes);
        });
    }

    loadAllCounts();
    loadSection(activeSection);
})();
