function initConfirmPopup() {
    var overlay = document.getElementById('confirm-popup-overlay');
    var popup = document.getElementById('confirm-popup');
    var msgEl = document.getElementById('confirm-popup-message');
    var okBtn = document.getElementById('confirm-popup-ok');
    var cancelBtn = document.getElementById('confirm-popup-cancel');
    var pendingHandler = null;

    if (!overlay || !popup || !okBtn || !cancelBtn || !msgEl) {
        window._dc_openConfirm = function (message, onConfirm) {
            if (window.confirm(message)) {
                onConfirm();
            }
        };
        return;
    }

    function openConfirm(message, onConfirm, options) {
        pendingHandler = (typeof onConfirm === 'function') ? onConfirm : null;
        msgEl.textContent = message || 'Are you sure?';
        var okLabel = (options && options.okLabel) || 'Delete';
        okBtn.textContent = okLabel;
        overlay.style.display = 'block';
        popup.style.display = 'block';
        overlay.setAttribute('aria-hidden', 'false');
        cancelBtn.focus();
    }

    function closeConfirm() {
        overlay.style.display = 'none';
        popup.style.display = 'none';
        overlay.setAttribute('aria-hidden', 'true');
        pendingHandler = null;
        okBtn.textContent = 'Delete';
    }

    okBtn.addEventListener('click', function () {
        if (pendingHandler) {
            pendingHandler();
        }
        closeConfirm();
    });

    cancelBtn.addEventListener('click', closeConfirm);

    overlay.addEventListener('click', function (e) {
        if (e.target === overlay) {
            closeConfirm();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && overlay.getAttribute('aria-hidden') === 'false') {
            closeConfirm();
        }
    });

    window._dc_openConfirm = openConfirm;
}

// Timestamps are stored as UTC in the database; render them in the browser timezone.
window._dc_parseUtcDate = function (utcIso) {
    if (!utcIso) return null;
    var s = String(utcIso).trim();
    if (!s) return null;
    if (!/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) {
        s += 'Z';
    }
    var d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
};

window._dc_formatLocalTime = function (utcIso, options) {
    var d = window._dc_parseUtcDate(utcIso);
    if (!d) return '-';
    return d.toLocaleString(undefined, options || {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
};

window._dc_formatUtcLabel = function (utcIso) {
    var d = window._dc_parseUtcDate(utcIso);
    if (!d) return '';
    return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
};

window._dc_applyLocalTimes = function (root) {
    var scope = root || document;
    scope.querySelectorAll('.local-time[data-utc]').forEach(function (el) {
        var utc = el.getAttribute('data-utc');
        if (!utc) {
            el.textContent = '-';
            el.removeAttribute('title');
            return;
        }
        el.textContent = window._dc_formatLocalTime(utc);
        el.setAttribute('title', 'UTC: ' + window._dc_formatUtcLabel(utc));
    });
};

document.addEventListener('DOMContentLoaded', function () {
    initConfirmPopup();
    window._dc_applyLocalTimes();
    // Global Socket.IO connection for live campaign/session updates.
    if (window.io) {
        try {
            var socket = io(); // default namespace
            window._dc_socket = socket;
        } catch (e) {
            console.warn('Socket.IO connection failed', e);
        }
    }

    // Profile dropdown toggle on click.
    var profileMenu = document.getElementById('profile-menu');
    var profileTrigger = document.getElementById('profile-trigger');
    if (profileMenu && profileTrigger) {
        profileTrigger.addEventListener('click', function (e) {
            e.stopPropagation();
            profileMenu.classList.toggle('open');
        });
        document.addEventListener('click', function () {
            profileMenu.classList.remove('open');
        });
    }
});
