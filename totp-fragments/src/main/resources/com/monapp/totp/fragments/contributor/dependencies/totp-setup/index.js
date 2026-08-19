(function () {

    const i18n = {};

    function _i18nRoot() {
        return fragmentElement.closest('.totp-setup-wrapper') || fragmentElement;
    }

    function _t(key) {
        if (i18n[key]) {
            return i18n[key];
        }

        const element = _i18nRoot().querySelector('[data-i18n-key="' + key + '"]');

        if (element) {
            const value = element.textContent.trim();

            if (value && value !== key && value.indexOf('[@liferay') === -1) {
                i18n[key] = value;
                return value;
            }
        }

        return key;
    }

    function _getChallenge() {
        const params = new URLSearchParams(window.location.search);
        const fromSearch = params.get('challenge');

        if (fromSearch) {
            return fromSearch;
        }

        const match = window.location.href.match(/[?&]challenge=([^&]+)/);

        return match ? decodeURIComponent(match[1]) : null;
    }

    function _hideControlMenu() {
        document.body.classList.remove('has-control-menu', 'has-staging-bar');

        document.querySelectorAll('.control-menu-container').forEach(
            function (element) {
                element.remove();
            });
    }

    _hideControlMenu();

    if (typeof MutationObserver !== 'undefined') {
        new MutationObserver(_hideControlMenu).observe(
            document.body, {childList: true, subtree: true});
    }

    function _el(name) {
        return fragmentElement.querySelector('[data-totp="' + name + '"]');
    }

    const qrContainer     = _el('qrCode');
    const secretInput     = _el('secretKey');
    const backupGrid      = _el('backupCodes');
    const btnCopy         = _el('btnCopy');
    const btnDownload     = _el('btnDownload');
    const btnConfirm      = _el('btnConfirm');
    const btnReset        = _el('btnReset');
    const alertError      = fragmentElement.querySelector('.totp-alert-error');
    const configuredBlock = fragmentElement.querySelector('.totp-already-configured');
    const setupForm       = fragmentElement.querySelector('.totp-setup-form');

    // ── Initialisation ────────────────────────────────────────────

    async function init() {
        const challenge = _getChallenge();

        try {
            const response = await Liferay.Util.fetch(
                '/o/totp/api/setup/init' +
                    (challenge ? '?challenge=' + encodeURIComponent(challenge) : ''), {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json',
                    'x-csrf-token': Liferay.authToken
                }
            });

            const contentType = response.headers.get('content-type') || '';

            if (!contentType.includes('application/json')) {
                _showError(_t('totp-error-server-totp-rest'));
                return;
            }

            const data = await response.json();

            if (data.sessionExpired) {
                _showSessionExpired();
                return;
            }

            if (!response.ok) {
                _showError(data.message || _t('totp-error-load-config'));
                return;
            }

            if (data.alreadyConfigured) {
                configuredBlock.classList.remove('d-none');
                setupForm.classList.add('d-none');
                return;
            }

            if (!data.qrCodeBase64) {
                _showError(_t('totp-error-qr-unavailable'));
                return;
            }

            const img = document.createElement('img');
            img.src = 'data:image/png;base64,' + data.qrCodeBase64;
            img.alt = _t('totp-setup-qr-alt');
            img.width = 250;
            img.height = 250;
            qrContainer.appendChild(img);

            secretInput.value = data.secret || '';

            const backupCodes = Array.isArray(data.backupCodes) ? data.backupCodes : [];

            backupCodes.forEach(function (code) {
                const col = document.createElement('div');
                col.className = 'col';
                col.innerHTML = '<span class="badge bg-light text-dark border w-100 py-2">' + code + '</span>';
                backupGrid.appendChild(col);
            });

            btnDownload._backupCodes = backupCodes;

        } catch (error) {
            console.error('TOTP setup init error:', error);
            _showError(_t('totp-error-connection'));
        }
    }

    // ── Copier la clé secrète ─────────────────────────────────────

    btnCopy.addEventListener('click', function () {
        navigator.clipboard.writeText(secretInput.value).then(function () {
            btnCopy.textContent = '✅';
            setTimeout(function () { btnCopy.textContent = '📋'; }, 2000);
        });
    });

    // ── Télécharger les codes de secours ──────────────────────────

    btnDownload.addEventListener('click', function () {
        const codes = btnDownload._backupCodes || [];
        const content = _t('totp-setup-backup-download-header') + '\n\n' + codes.join('\n');
        const blob = new Blob([content], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'backup-codes-totp.txt';
        a.click();
    });

    // ── Finaliser la session via le portlet Login (contexte portal) ──

    function _completePendingLogin(completeLoginUrl) {
        window.location.replace(completeLoginUrl);
    }

    // ── Confirmer le code TOTP ────────────────────────────────────

    btnConfirm.addEventListener('click', async function () {
        const challenge = _getChallenge();
        const code = _el('confirmCode').value.trim();

        if (!/^\d{6}$/.test(code)) {
            _showError(_t('totp-error-code-6-digits'));
            return;
        }

        btnConfirm.disabled = true;
        btnConfirm.textContent = _t('totp-verifying');

        try {
            const response = await Liferay.Util.fetch('/o/totp/api/setup/confirm', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'x-csrf-token': Liferay.authToken
                },
                body: JSON.stringify({
                    confirmCode: code,
                    challenge: challenge || ''
                })
            });

            const contentType = response.headers.get('content-type') || '';

            if (!contentType.includes('application/json')) {
                _showError(_t('totp-error-server-retry'));
                btnConfirm.disabled = false;
                btnConfirm.textContent = _t('totp-setup-activate');
                return;
            }

            const data = await response.json();

            if (data.sessionExpired) {
                _showSessionExpired();
                return;
            }

            if (data.success && data.completeLogin && data.completeLoginUrl) {
                btnConfirm.textContent = _t('totp-connecting');
                _completePendingLogin(data.completeLoginUrl);
            } else if (data.success && data.redirectUrl) {
                window.location.replace(data.redirectUrl);
            } else if (data.success) {
                window.location.replace(Liferay.ThemeDisplay.getPortalURL() + '/c/portal');
            } else {
                _showError(data.message || _t('totp-error-invalid-code'));
                btnConfirm.disabled = false;
                btnConfirm.textContent = _t('totp-setup-activate');
            }
        } catch (error) {
            _showError(_t('totp-error-connection'));
            btnConfirm.disabled = false;
            btnConfirm.textContent = _t('totp-setup-activate');
        }
    });

    // ── Reconfigurer ──────────────────────────────────────────────

    if (btnReset) {
        btnReset.addEventListener('click', async function () {
            if (!confirm(_t('totp-setup-reset-confirm'))) return;

            const challenge = _getChallenge();
            const resetUrl = challenge ?
                '/o/totp/api/setup/reset?challenge=' + encodeURIComponent(challenge) :
                '/o/totp/api/setup/reset';

            await Liferay.Util.fetch(resetUrl, {
                method: 'POST',
                credentials: 'include',
                headers: { 'x-csrf-token': Liferay.authToken }
            });
            window.location.reload();
        });
    }

    // ── Utilitaires ───────────────────────────────────────────────

    function _logoutUrl() {
        return Liferay.ThemeDisplay.getPortalURL() + '/c/portal/logout';
    }

    function _disableForm() {
        fragmentElement.querySelectorAll(
            'input, button[data-totp]'
        ).forEach(function (element) {
            element.disabled = true;
        });
    }

    function _showError(message) {
        alertError.textContent = message;
        alertError.classList.remove('d-none');
        setTimeout(function () { alertError.classList.add('d-none'); }, 8000);
    }

    function _showSessionExpired() {
        alertError.innerHTML =
            _t('totp-error-session-expired') +
            ' <a href="' + _logoutUrl() + '" class="alert-link fw-semibold">' +
            _t('totp-session-expired-logout-link') + '</a>';
        alertError.classList.remove('d-none');
        _disableForm();
    }

    init();

})();
