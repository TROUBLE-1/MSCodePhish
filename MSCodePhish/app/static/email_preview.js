(function () {
    function sanitizeForPreview(html) {
        var safe = html || '';
        safe = safe.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
        safe = safe.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
        safe = safe.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '');
        safe = safe.replace(/<embed\b[^>]*>/gi, '');
        safe = safe.replace(/\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '');
        safe = safe.replace(/href\s*=\s*(["'])\s*javascript:[^"']*\1/gi, 'href="#"');
        safe = safe.replace(/src\s*=\s*(["'])\s*javascript:[^"']*\1/gi, 'src=""');
        return safe;
    }

    function applyPlaceholders(html, mode) {
        var text = html || '';
        if (mode === 'post_auth') {
            return text
                .replace(/\{\{user_name\}\}/g, 'Jane Doe')
                .replace(/\{\{display_name\}\}/g, 'Jane Doe')
                .replace(/\{\{name\}\}/g, 'Jane Doe')
                .replace(/\{\{user_email\}\}/g, 'jane.doe@contoso.com')
                .replace(/\{\{user_id\}\}/g, '00000000-0000-0000-0000-000000000001')
                .replace(/\{\{target_email\}\}/g, 'jane.doe@contoso.com')
                .replace(/\{\{given_name\}\}/g, 'Jane')
                .replace(/\{\{family_name\}\}/g, 'Doe')
                .replace(/\{\{tenant_id\}\}/g, '00000000-0000-0000-0000-000000000002')
                .replace(/\{\{account_type\}\}/g, 'personal');
        }
        return text
            .replace(/\{\{user_code\}\}/g, 'ABCD-1234')
            .replace(/\{\{verification_uri\}\}/g, 'https://login.microsoft.com/device')
            .replace(/\{\{message\}\}/g, 'To sign in, use a browser to open https://microsoft.com/devicelogin and enter the code ABCD-1234.');
    }

    function initEmailPreview() {
        var overlay = document.getElementById('email-preview-overlay');
        var popup = document.getElementById('email-preview-popup');
        var frame = document.getElementById('email-preview-frame');
        var closeBtn = document.getElementById('email-preview-close');
        var titleEl = document.getElementById('email-preview-title');

        if (!overlay || !popup || !frame) {
            return;
        }

        function openPreview(textarea, mode) {
            if (!textarea) return;
            if (titleEl) {
                titleEl.textContent = mode === 'post_auth' ? 'Post-auth email preview' : 'Device code email preview';
            }
            frame.removeAttribute('src');
            frame.srcdoc = applyPlaceholders(sanitizeForPreview(textarea.value), mode);
            overlay.style.display = 'flex';
            overlay.setAttribute('aria-hidden', 'false');
        }

        function closePreview() {
            overlay.style.display = 'none';
            overlay.setAttribute('aria-hidden', 'true');
            frame.srcdoc = '';
        }

        document.addEventListener('click', function (e) {
            var btn = e.target && e.target.closest ? e.target.closest('[data-email-preview-btn]') : null;
            if (!btn) return;
            e.preventDefault();
            var selector = btn.getAttribute('data-email-preview-target');
            var mode = btn.getAttribute('data-email-preview-mode') || 'device_code';
            var textarea = selector ? document.querySelector(selector) : null;
            openPreview(textarea, mode);
        });

        if (closeBtn) {
            closeBtn.addEventListener('click', function (e) {
                e.preventDefault();
                closePreview();
            });
        }

        popup.addEventListener('click', function (e) {
            e.stopPropagation();
        });

        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) {
                closePreview();
            }
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && overlay.style.display === 'flex') {
                closePreview();
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initEmailPreview);
    } else {
        initEmailPreview();
    }
})();
