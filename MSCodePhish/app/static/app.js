// Styled confirm on campaign detail replaces this; other pages rely on it for delete confirmations.
if (typeof window._dc_openConfirm !== 'function') {
    window._dc_openConfirm = function (message, onConfirm) {
        if (window.confirm(message)) {
            onConfirm();
        }
    };
}

document.addEventListener('DOMContentLoaded', function () {
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
