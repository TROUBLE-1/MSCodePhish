(function () {
    function fieldValue(form, name) {
        var el = form.querySelector('[name="' + name + '"]');
        if (!el) return '';
        return (el.value || '').trim();
    }

    function setStatus(platform, message, isError) {
        var status = document.querySelector('[data-notification-test-status="' + platform + '"]');
        if (!status) return;
        status.textContent = message || '';
        status.classList.toggle('is-error', !!isError);
        status.classList.toggle('is-success', !isError && !!message);
    }

    function setButtonState(btn, sending) {
        if (!btn) return;
        btn.disabled = sending;
        btn.textContent = sending ? 'Sending…' : (btn.getAttribute('data-label') || 'Send test message');
    }

    function initNotificationTestButtons() {
        var form = document.querySelector('.campaign-form');
        var endpoint = window._notificationTestUrl;
        if (!form || !endpoint) return;

        document.querySelectorAll('[data-notification-test]').forEach(function (btn) {
            if (!btn.getAttribute('data-label')) {
                btn.setAttribute('data-label', btn.textContent.trim());
            }
        });

        document.addEventListener('click', function (e) {
            var btn = e.target && e.target.closest ? e.target.closest('[data-notification-test]') : null;
            if (!btn || !form.contains(btn)) return;
            e.preventDefault();

            var platform = btn.getAttribute('data-notification-test');
            setStatus(platform, '', false);

            var payload = { platform: platform };
            if (platform === 'slack') {
                payload.slack_bot_token = fieldValue(form, 'slack_bot_token');
                payload.slack_channel = fieldValue(form, 'slack_channel');
                if (!payload.slack_bot_token || !payload.slack_channel) {
                    setStatus(platform, 'Enter Slack bot token and channel.', true);
                    return;
                }
            } else if (platform === 'discord') {
                payload.discord_bot_token = fieldValue(form, 'discord_bot_token');
                payload.discord_channel_id = fieldValue(form, 'discord_channel_id');
                if (!payload.discord_bot_token || !payload.discord_channel_id) {
                    setStatus(platform, 'Enter Discord bot token and channel ID.', true);
                    return;
                }
            } else {
                return;
            }

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
                        setStatus(platform, x.data.message || 'Test message sent.', false);
                    } else {
                        setStatus(platform, x.data.error || 'Test failed.', true);
                    }
                })
                .catch(function () {
                    setStatus(platform, 'Request failed.', true);
                })
                .finally(function () {
                    setButtonState(btn, false);
                });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initNotificationTestButtons);
    } else {
        initNotificationTestButtons();
    }
})();
