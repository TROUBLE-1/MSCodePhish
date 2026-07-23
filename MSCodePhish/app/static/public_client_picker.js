(function () {
    var pickerInstances = [];

    function getClientPickerPortal() {
        var portal = document.getElementById('client-picker-portal');
        if (!portal) {
            portal = document.createElement('div');
            portal.id = 'client-picker-portal';
            portal.className = 'client-id-picker-portal';
            portal.setAttribute('aria-hidden', 'true');
            document.body.appendChild(portal);
        }
        return portal;
    }

    function initPublicClientPickerRoot(root) {
        var clients = Array.isArray(window._publicClients) ? window._publicClients : [];
        var input = root.querySelector('.client-id-picker-input');
        var browseBtn = root.querySelector('.client-id-picker-browse-btn');
        var panel = root.querySelector('.client-id-picker-panel');
        var searchInput = root.querySelector('.client-id-picker-search');
        var listEl = root.querySelector('.client-id-picker-list');
        var emptyEl = root.querySelector('.client-id-picker-empty');
        var matchEl = root.querySelector('.client-id-picker-match');

        if (!input || !browseBtn || !panel || !searchInput || !listEl) return;

        var byId = {};
        clients.forEach(function (client) {
            if (client && client.id) {
                byId[client.id.toLowerCase()] = client;
            }
        });

        var useFloatingPanel = !!(
            root.closest('.popup-box') ||
            root.closest('.popup-overflow-visible') ||
            root.closest('.token-enum-token-popup')
        );
        var panelParent = panel.parentNode;
        var panelNextSibling = panel.nextSibling;
        var floatingActive = false;
        var isOpen = false;

        function normalize(value) {
            return (value || '').trim().toLowerCase();
        }

        function updateMatchHint() {
            if (!matchEl) return;
            var value = (input.value || '').trim();
            if (!value) {
                matchEl.hidden = true;
                matchEl.textContent = '';
                return;
            }
            var known = byId[value.toLowerCase()];
            if (known) {
                matchEl.hidden = false;
                matchEl.textContent = 'Selected: ' + known.name;
                matchEl.classList.remove('is-custom');
            } else {
                matchEl.hidden = false;
                matchEl.textContent = 'Custom client ID';
                matchEl.classList.add('is-custom');
            }
        }

        function filterClients(query) {
            var q = normalize(query);
            if (!q) {
                return clients.slice(0, 80);
            }
            return clients.filter(function (client) {
                var name = (client.name || '').toLowerCase();
                var id = (client.id || '').toLowerCase();
                return name.indexOf(q) !== -1 || id.indexOf(q) !== -1;
            }).slice(0, 120);
        }

        function renderList(query) {
            var results = filterClients(query);
            listEl.innerHTML = '';
            results.forEach(function (client) {
                var row = document.createElement('button');
                row.type = 'button';
                row.className = 'client-id-picker-option';
                row.setAttribute('role', 'option');
                row.setAttribute('data-id', client.id);
                row.innerHTML =
                    '<span class="client-id-picker-option-name"></span>' +
                    '<code class="client-id-picker-option-id"></code>';
                row.querySelector('.client-id-picker-option-name').textContent = client.name || '(unnamed)';
                row.querySelector('.client-id-picker-option-id').textContent = client.id;
                row.addEventListener('mousedown', function (e) {
                    e.preventDefault();
                });
                row.addEventListener('click', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    input.value = client.id;
                    updateMatchHint();
                    closePanel();
                    input.focus();
                });
                listEl.appendChild(row);
            });
            if (emptyEl) {
                emptyEl.hidden = results.length > 0;
            }
        }

        function positionFloatingPanel() {
            if (!floatingActive) return;
            var rect = input.getBoundingClientRect();
            var viewportPad = 8;
            var gap = 6;
            var width = Math.max(rect.width, 300);
            var left = Math.min(
                Math.max(viewportPad, rect.left),
                window.innerWidth - width - viewportPad
            );
            var spaceBelow = window.innerHeight - rect.bottom - viewportPad;
            var spaceAbove = rect.top - viewportPad;
            var openBelow = spaceBelow >= 120 || spaceBelow >= spaceAbove;
            var listMax = Math.min(560, Math.round(window.innerHeight * 0.7));
            var top;
            var listHeight;

            if (openBelow) {
                top = rect.bottom + gap;
                listHeight = Math.min(listMax, spaceBelow - gap);
            } else {
                listHeight = Math.min(listMax, spaceAbove - gap);
                top = Math.max(viewportPad, rect.top - gap - listHeight - 44);
            }

            panel.style.left = left + 'px';
            panel.style.top = top + 'px';
            panel.style.width = width + 'px';
            panel.style.maxHeight = 'none';
            panel.style.zIndex = '1101';
            listEl.style.maxHeight = Math.max(120, listHeight) + 'px';
        }

        function enableFloatingPanel() {
            if (!useFloatingPanel || floatingActive) return;
            var portal = getClientPickerPortal();
            portal.appendChild(panel);
            portal.setAttribute('aria-hidden', 'false');
            panel.classList.add('client-id-picker-panel--floating');
            floatingActive = true;
            positionFloatingPanel();
        }

        function disableFloatingPanel() {
            if (!floatingActive) return;
            panel.classList.remove('client-id-picker-panel--floating');
            panel.style.left = '';
            panel.style.top = '';
            panel.style.width = '';
            panel.style.maxHeight = '';
            panel.style.zIndex = '';
            listEl.style.maxHeight = '';
            if (panel.parentNode !== panelParent) {
                if (panelNextSibling) {
                    panelParent.insertBefore(panel, panelNextSibling);
                } else {
                    panelParent.appendChild(panel);
                }
            }
            floatingActive = false;
            var portal = document.getElementById('client-picker-portal');
            if (portal && !portal.querySelector('.client-id-picker-panel:not([hidden])')) {
                portal.setAttribute('aria-hidden', 'true');
            }
        }

        function onFloatingReposition() {
            if (isOpen && floatingActive) {
                positionFloatingPanel();
            }
        }

        function isPanelOpen() {
            return isOpen && !panel.hidden;
        }

        function openPanel() {
            closeAllClientPickerPanels(root);
            isOpen = true;
            panel.hidden = false;
            panel.removeAttribute('hidden');
            browseBtn.setAttribute('aria-expanded', 'true');
            renderList(searchInput.value || input.value);
            if (useFloatingPanel) {
                enableFloatingPanel();
                positionFloatingPanel();
            }
            searchInput.focus();
            searchInput.select();
        }

        function closePanel() {
            if (!isOpen && panel.hidden) {
                return;
            }
            isOpen = false;
            panel.hidden = true;
            panel.setAttribute('hidden', '');
            browseBtn.setAttribute('aria-expanded', 'false');
            if (searchInput) searchInput.value = '';
            disableFloatingPanel();
        }

        function togglePanel() {
            if (isPanelOpen()) {
                closePanel();
            } else {
                openPanel();
            }
        }

        function onDocumentPointer(e) {
            if (!isPanelOpen()) return;
            if (root.contains(e.target) || panel.contains(e.target)) {
                return;
            }
            closePanel();
        }

        browseBtn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            togglePanel();
        });

        input.addEventListener('input', updateMatchHint);
        input.addEventListener('change', updateMatchHint);
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && isPanelOpen()) {
                e.preventDefault();
                e.stopPropagation();
                closePanel();
            }
        });

        searchInput.addEventListener('input', function () {
            renderList(searchInput.value);
        });

        searchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                closePanel();
                input.focus();
            }
        });

        document.addEventListener('mousedown', onDocumentPointer, true);
        document.addEventListener('touchstart', onDocumentPointer, true);

        if (useFloatingPanel) {
            window.addEventListener('resize', onFloatingReposition);
            window.addEventListener('scroll', onFloatingReposition, true);
        }

        pickerInstances.push({ root: root, closePanel: closePanel, isPanelOpen: isPanelOpen });
        updateMatchHint();
    }

    function closeAllClientPickerPanels(exceptRoot) {
        pickerInstances.forEach(function (instance) {
            if (exceptRoot && instance.root === exceptRoot) return;
            instance.closePanel();
        });
        var portal = document.getElementById('client-picker-portal');
        if (portal) {
            portal.setAttribute('aria-hidden', 'true');
        }
    }

    window.closeAllClientPickerPanels = function () {
        closeAllClientPickerPanels(null);
    };

    function initAllPublicClientPickers() {
        document.querySelectorAll('.client-id-picker').forEach(initPublicClientPickerRoot);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAllPublicClientPickers);
    } else {
        initAllPublicClientPickers();
    }
})();
