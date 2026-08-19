package com.monapp.totp.filter;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.servlet.BaseFilter;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.monapp.totp.service.TOTPService;
import com.monapp.totp.service.TotpRoleChecker;
import com.monapp.totp.util.TotpControlMenuUtil;
import com.monapp.totp.util.TotpPaths;
import com.monapp.totp.util.TotpPendingLoginUtil;
import com.monapp.totp.util.TotpRedirectUtil;
import com.monapp.totp.util.TotpSessionUtil;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet filter enforcing TOTP setup and verification for configured roles
 * and completing pending MFA logins.
 *
 * @author monapp
 */
@Component(
    immediate = true,
    property = {
        "dispatcher=REQUEST",
        "servlet-context-name=",
        "servlet-filter-name=TOTP Login Filter",
        "url-pattern=/*"
    },
    service = Filter.class
)
public class TOTPLoginFilter extends BaseFilter {

    @Override
    protected void processFilter(
        HttpServletRequest request, HttpServletResponse response,
        FilterChain chain) throws Exception {

        String requestURI = request.getRequestURI();

        if (TotpPaths.isCompleteLoginPath(requestURI)) {
            _completePendingLogin(request, response);

            return;
        }

        if (_isStaticAssetRequest(requestURI)) {
            chain.doFilter(request, response);
            return;
        }

        if (TotpPaths.isSetupPage(requestURI)) {
            if (!_canAccessSetupPage(request)) {
                response.sendRedirect(
                    _portal.getPortalURL(request) + "/c/portal/login");

                return;
            }

            chain.doFilter(
                TotpControlMenuUtil.wrapToHideControlMenu(request), response);
            return;
        }

        if (TotpPaths.isVerifyPage(requestURI)) {
            if (!_canAccessVerifyPage(request)) {
                if (_log.isWarnEnabled()) {
                    _log.warn(
                        "Accès totp-verify refusé : pending=" +
                            TotpPendingLoginUtil.hasPendingLogin(
                                request, _portal) +
                            ", uri=" + requestURI);
                }

                response.sendRedirect(
                    _portal.getPortalURL(request) + "/c/portal/login");

                return;
            }

            chain.doFilter(
                TotpControlMenuUtil.wrapToHideControlMenu(request), response);
            return;
        }

        User user = _portal.getUser(request);

        if (user == null || user.isGuestUser() || !_totpRoleChecker.requiresTotp(user)) {
            chain.doFilter(request, response);
            return;
        }

        if (TotpSessionUtil.isTotpVerified(request, _portal)) {
            chain.doFilter(request, response);
            return;
        }

        if (_isAllowedWithoutTotp(requestURI)) {
            chain.doFilter(request, response);
            return;
        }

        if (Validator.isNull(_totpService.getTotpSecret(user))) {
            TotpSessionUtil.preservePostLoginPath(request, _portal);

            _log.info(
                "Utilisateur sans TOTP configuré, redirection setup : " +
                    user.getEmailAddress());

            response.sendRedirect(
                request.getContextPath() + TotpPaths.SETUP_PAGE);

            return;
        }

        _log.warn(
            "Utilisateur connecté sans TOTP validé, redirection verify : " +
                user.getEmailAddress() + " (" + requestURI + ")");

        response.sendRedirect(
            request.getContextPath() + TotpPaths.VERIFY_PAGE);
    }

    /** Returns {@code true} when the setup page may be accessed. */
    private boolean _canAccessSetupPage(HttpServletRequest request)
        throws PortalException {

        if (TotpPendingLoginUtil.hasPendingLogin(request, _portal)) {
            return true;
        }

        User user = _portal.getUser(request);

        if ((user == null) || user.isGuestUser() ||
            !_totpRoleChecker.requiresTotp(user)) {

            return false;
        }

        return Validator.isNull(_totpService.getTotpSecret(user));
    }

    /** Returns {@code true} when the verify page may be accessed. */
    private boolean _canAccessVerifyPage(HttpServletRequest request)
        throws PortalException {

        if (TotpPendingLoginUtil.hasPendingLogin(request, _portal)) {
            return true;
        }

        User user = _portal.getUser(request);

        if ((user == null) || user.isGuestUser() ||
            !_totpRoleChecker.requiresTotp(user)) {
            return false;
        }

        return Validator.isNotNull(_totpService.getTotpSecret(user)) &&
            !TotpSessionUtil.isTotpVerified(request, _portal);
    }

    /** Returns {@code true} for login, logout, and TOTP-related paths. */
    private boolean _isAllowedWithoutTotp(String requestURI) {
        return requestURI.contains("/c/portal/login") ||
            requestURI.contains("/c/portal/logout") ||
            TotpPaths.isCompleteLoginPath(requestURI) ||
            TotpPaths.isRestApiPath(requestURI) ||
            TotpPaths.isSetupPage(requestURI) ||
            TotpPaths.isVerifyPage(requestURI);
    }

    /** Finalizes a pending MFA login and redirects to the last visited path. */
    private void _completePendingLogin(
            HttpServletRequest request, HttpServletResponse response)
        throws Exception {

        String challenge = ParamUtil.getString(request, "challenge");

        if (Validator.isNull(challenge)) {
            response.sendRedirect(
                _portal.getPortalURL(request) + "/c/portal/login");

            return;
        }

        try {
            TotpPendingLoginUtil.completePendingLogin(
                request, response, _portal, challenge);

            String redirectUrl = TotpRedirectUtil.getLastPathRedirectUrl(
                request, _portal);

            if (_log.isInfoEnabled()) {
                _log.info(
                    "Login MFA terminé via filtre portal, redirection LAST_PATH : " +
                        redirectUrl);
            }

            response.sendRedirect(redirectUrl);
        }
        catch (Exception exception) {
            _log.error("Erreur finalisation login MFA via filtre", exception);

            response.sendRedirect(
                _portal.getPortalURL(request) + "/c/portal/login");
        }
    }

    /** Returns {@code true} for static assets that must not trigger redirects. */
    private boolean _isStaticAssetRequest(String requestURI) {
        if (requestURI.contains("/combo") ||
            requestURI.contains("/image/") ||
            requestURI.contains("/documents/") ||
            requestURI.contains("/html/common/")) {

            return true;
        }

        if (requestURI.contains("/o/") &&
            !TotpPaths.isRestApiPath(requestURI)) {

            return true;
        }

        String lowerURI = requestURI.toLowerCase();

        return lowerURI.endsWith(".js") || lowerURI.endsWith(".css") ||
            lowerURI.endsWith(".map") || lowerURI.endsWith(".woff") ||
            lowerURI.endsWith(".woff2") || lowerURI.endsWith(".png") ||
            lowerURI.endsWith(".gif") || lowerURI.endsWith(".svg") ||
            lowerURI.endsWith(".ico");
    }

    @Reference
    private Portal _portal;

    @Reference
    private TOTPService _totpService;

    @Reference
    private TotpRoleChecker _totpRoleChecker;

    @Override
    protected Log getLog() {
        return _log;
    }

    private static final Log _log = LogFactoryUtil.getLog(TOTPLoginFilter.class);

}
