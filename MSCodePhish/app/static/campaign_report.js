(function () {
    var overlay = document.getElementById('campaign-report-overlay');
    var popup = document.getElementById('campaign-report-popup');
    var frame = document.getElementById('campaign-report-frame');
    var closeBtn = document.getElementById('campaign-report-close');
    var printBtn = document.getElementById('campaign-report-print');
    var titleEl = document.getElementById('campaign-report-title');

    if (!overlay || !popup || !frame) return;

    function showOverlay() {
        overlay.style.display = 'flex';
        overlay.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
    }

    function hideOverlay() {
        overlay.style.display = 'none';
        overlay.setAttribute('aria-hidden', 'true');
        frame.removeAttribute('src');
        document.body.style.overflow = '';
    }

    function openCampaignReport(campaignId, campaignName) {
        if (!campaignId) return;
        if (titleEl) {
            titleEl.textContent = campaignName
                ? 'Security Assessment - ' + campaignName
                : 'Security Assessment Report';
        }
        frame.src = '/campaigns/' + encodeURIComponent(campaignId) + '/report?embed=1';
        showOverlay();
    }

    window._dc_openCampaignReport = openCampaignReport;

    document.addEventListener('click', function (e) {
        var btn = e.target.closest('.campaign-report-btn');
        if (!btn) return;
        e.preventDefault();
        openCampaignReport(
            btn.getAttribute('data-campaign-id'),
            btn.getAttribute('data-campaign-name') || ''
        );
    });

    if (closeBtn) {
        closeBtn.addEventListener('click', hideOverlay);
    }

    if (printBtn) {
        printBtn.addEventListener('click', function () {
            try {
                if (frame.contentWindow) {
                    frame.contentWindow.focus();
                    frame.contentWindow.print();
                }
            } catch (err) {
                /* ignore cross-origin edge cases */
            }
        });
    }

    overlay.addEventListener('click', function (e) {
        if (e.target === overlay) {
            hideOverlay();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && overlay.style.display !== 'none' && overlay.style.display) {
            hideOverlay();
        }
    });
})();
