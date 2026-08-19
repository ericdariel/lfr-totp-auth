(function () {

    const i18n = {};

    function _i18nRoot() {
        return fragmentElement.closest('.totp-verify-wrapper') || fragmentElement;
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

    const codeInput     = _el('totpCode');
    const btnVerify     = _el('btnVerify');
    const timerBar      = _el('timerBar');
    const toggleBackup  = _el('toggleBackup');
    const backupSection = _el('backupSection');
    const backupInput   = _el('backupCode');
    const btnBackup     = _el('btnBackupVerify');
    const alertError    = fragmentElement.querySelector('.totp-verify-error');

    // ── Timer 30 secondes ─────────────────────────────────────────

    function _startTimer() {
        function tick() {
            const seconds = new Date().getSeconds();
            const remaining = 30 - (seconds % 30);
            timerBar.style.width = ((remaining / 30) * 100) + '%';
            timerBar.style.backgroundColor = remaining <= 5 ? '#dc3545' : '#0d6efd';
        }
        tick();
        setInterval(tick, 1000);
    }

    // ── Finaliser la session via le portlet Login (contexte portal) ──

    function _completePendingLogin(completeLoginUrl) {
        window.location.replace(completeLoginUrl);
    }

    // ── Vérifier le code ──────────────────────────────────────────

    async function _verifyCode(code, isBackup) {
        const challenge = _getChallenge();
        const endpoint = isBackup ? '/o/totp/api/verify/backup' : '/o/totp/api/verify/code';
        const btn = isBackup ? btnBackup : btnVerify;

        btn.disabled = true;
        btn.textContent = _t('totp-verifying');

        try {
            const response = await Liferay.Util.fetch(endpoint, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'x-csrf-token': Liferay.authToken
                },
                body: JSON.stringify({
                    code: code,
                    challenge: challenge || ''
                })
            });

            const contentType = response.headers.get('content-type') || '';

            if (!contentType.includes('application/json')) {
                _showError(_t('totp-error-server-retry'));
                btn.disabled = false;
                btn.textContent = isBackup ? _t('totp-verify-backup-button') : _t('totp-verify-button');
                if (!isBackup) {
                    _focusCodeInput();
                }
                return;
            }

            const data = await response.json();

            if (data.sessionExpired) {
                _showSessionExpired();
                return;
            }

            if (data.success && data.completeLogin && data.completeLoginUrl) {
                btn.textContent = _t('totp-connecting');
                _completePendingLogin(data.completeLoginUrl);
            } else if (data.success && data.redirectUrl) {
                window.location.replace(data.redirectUrl);
            } else if (data.success) {
                window.location.replace(Liferay.ThemeDisplay.getPortalURL() + '/c/portal');
            } else {
                _showError(isBackup
                    ? _t('totp-error-backup-invalid')
                    : (data.message || _t('totp-error-code-incorrect')));
                btn.disabled = false;
                btn.textContent = isBackup ? _t('totp-verify-backup-button') : _t('totp-verify-button');
                if (!isBackup) {
                    _focusCodeInput();
                }
            }
        } catch (error) {
            _showError(_t('totp-error-connection'));
            btn.disabled = false;
            btn.textContent = isBackup ? _t('totp-verify-backup-button') : _t('totp-verify-button');
            if (!isBackup) {
                _focusCodeInput();
            }
        }
    }

    // ── Événements ────────────────────────────────────────────────

    btnVerify.addEventListener('click', function () {
        const code = codeInput.value.trim();
        if (!/^\d{6}$/.test(code)) {
            _showError(_t('totp-error-code-exactly-6-digits'));
            _focusCodeInput();
            return;
        }
        _verifyCode(code, false);
    });

    codeInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') btnVerify.click();
    });

    toggleBackup.addEventListener('click', function (e) {
        e.preventDefault();
        backupSection.classList.toggle('d-none');
        toggleBackup.textContent = backupSection.classList.contains('d-none')
            ? _t('totp-verify-use-backup')
            : _t('totp-verify-use-authenticator');

        if (backupSection.classList.contains('d-none')) {
            _focusCodeInput();
        } else {
            backupInput.focus();
        }
    });

    btnBackup.addEventListener('click', function () {
        const code = backupInput.value.trim();
        if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/i.test(code)) {
            _showError(_t('totp-error-backup-invalid-format'));
            return;
        }
        _verifyCode(code, true);
    });

    // ── Utilitaires ───────────────────────────────────────────────

    function _logoutUrl() {
        return Liferay.ThemeDisplay.getPortalURL() + '/c/portal/logout';
    }

    function _disableForm() {
        [codeInput, btnVerify, backupInput, btnBackup].forEach(function (element) {
            if (element) {
                element.disabled = true;
            }
        });

        if (toggleBackup) {
            toggleBackup.classList.add('pe-none', 'text-muted');
        }
    }

    function _showError(message) {
        alertError.textContent = message;
        alertError.classList.remove('d-none');
        setTimeout(function () { alertError.classList.add('d-none'); }, 5000);
    }

    function _showSessionExpired() {
        alertError.innerHTML =
            _t('totp-error-session-expired') +
            ' <a href="' + _logoutUrl() + '" class="alert-link fw-semibold">' +
            _t('totp-session-expired-logout-link') + '</a>';
        alertError.classList.remove('d-none');
        _disableForm();
    }

    function _focusCodeInput() {
        if (!codeInput || !backupSection.classList.contains('d-none')) {
            return;
        }

        codeInput.focus();
    }

    _startTimer();
    _focusCodeInput();
    requestAnimationFrame(_focusCodeInput);
    setTimeout(_focusCodeInput, 100);

})();
