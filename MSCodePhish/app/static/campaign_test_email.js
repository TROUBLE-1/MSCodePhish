(function () {
    function collectFormPayload(form) {
        var data = {};
        if (!form) return data;
        var fd = new FormData(form);
        fd.forEach(function (value, key) {
            if (key.indexOf('test_email_') === 0) return;
            data[key] = value;
        });
        return data;
    }

    function setButtonState(btn, sending) {
        if (!btn) return;
        btn.disabled = sending;
        btn.textContent = sending ? 'Sending…' : (btn.getAttribute('data-label') || btn.textContent);
    }

    function showStatus(actionsRow, message, isError) {
        if (!actionsRow) return;
        var status = actionsRow.querySelector('.campaign-test-email-status');
        if (!status) {
            status = document.createElement('span');
            status.className = 'campaign-test-email-status';
            actionsRow.insertBefore(status, actionsRow.firstChild);
        }
        status.textContent = message || '';
        status.classList.toggle('is-error', !!isError);
        status.classList.toggle('is-success', !isError && !!message);
    }

    function initTestEmailButtons() {
        var form = document.querySelector('.campaign-form');
        var endpoint = window._campaignTestEmailUrl;
        if (!form || !endpoint) return;

        document.querySelectorAll('[data-email-test-btn]').forEach(function (btn) {
            if (!btn.getAttribute('data-label')) {
                btn.setAttribute('data-label', btn.textContent.trim());
            }
        });

        document.addEventListener('click', function (e) {
            var btn = e.target && e.target.closest ? e.target.closest('[data-email-test-btn]') : null;
            if (!btn || !form.contains(btn)) return;
            e.preventDefault();

            var mode = btn.getAttribute('data-email-test-mode') || 'device_code';
            var actionsRow = btn.closest('.campaign-email-actions');
            var input = actionsRow ? actionsRow.querySelector('.campaign-test-email-input') : null;
            var toEmail = input ? input.value.trim() : '';

            showStatus(actionsRow, '', false);
            if (!toEmail) {
                showStatus(actionsRow, 'Enter a test recipient email.', true);
                if (input) input.focus();
                return;
            }

            var payload = collectFormPayload(form);
            payload.to_email = toEmail;
            payload.email_type = mode;

            setButtonState(btn, true);
            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            })
            .then(function (r) {
                return r.json().then(function (d) { return { ok: r.ok, data: d }; });
            })
            .then(function (x) {
                if (x.ok) {
                    showStatus(actionsRow, x.data.message || 'Test email sent.', false);
                } else {
                    showStatus(actionsRow, x.data.error || 'Failed to send test email.', true);
                }
            })
            .catch(function () {
                showStatus(actionsRow, 'Request failed.', true);
            })
            .finally(function () {
                setButtonState(btn, false);
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTestEmailButtons);
    } else {
        initTestEmailButtons();
    }
})();
