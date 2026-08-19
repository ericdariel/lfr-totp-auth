package com.monapp.totp.rest.util;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.security.permission.PermissionChecker;
import com.liferay.portal.kernel.security.permission.PermissionThreadLocal;
import com.liferay.portal.kernel.service.GroupLocalService;
import com.liferay.portal.kernel.service.RoleLocalService;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.kernel.util.WebKeys;
import com.monapp.totp.service.TotpRoleChecker;
import com.monapp.totp.util.TotpPendingLoginUtil;
import com.monapp.totp.util.TotpRedirectUtil;
import com.monapp.totp.util.TotpSessionUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * REST-layer helpers for user resolution, session flags, and redirects.
 *
 * @author monapp
 */
public class TotpRestUtil {

	private static final Log _log = LogFactoryUtil.getLog(TotpRestUtil.class);

	private TotpRestUtil() {
	}

	/**
	 * Resolves the currently authenticated non-guest user from the request.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param userLocalService user local service
	 * @return authenticated user or {@code null}
	 */
	public static User getAuthenticatedUser(
		HttpServletRequest request, Portal portal,
		UserLocalService userLocalService) {

		User user = _getUserFromRemoteUser(request, userLocalService);

		if (user != null) {
			return user;
		}

		user = _getUserFromPortalUserId(request, portal, userLocalService);

		if (user != null) {
			return user;
		}

		user = _getUserFromSession(request, portal, userLocalService);

		if (user != null) {
			return user;
		}

		user = _getUserFromPortal(request, portal);

		if (user != null) {
			return user;
		}

		user = _getUserFromPermissionChecker(userLocalService);

		if (user != null) {
			return user;
		}

		if (_log.isDebugEnabled()) {
			_log.debug(
				"Aucun utilisateur authentifié : remoteUser=" +
					request.getRemoteUser() + ", sessionId=" +
						_getSessionId(request));
		}

		return null;
	}

	/**
	 * Resolves the user for a TOTP verification request, preferring a pending
	 * login challenge when present.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param userLocalService user local service
	 * @param challenge optional MFA challenge token
	 * @return user eligible for verification or {@code null}
	 */
	public static User getUserForVerification(
		HttpServletRequest request, Portal portal,
		UserLocalService userLocalService, String challenge) {

		long pendingUserId = TotpPendingLoginUtil.resolvePendingUserId(
			request, portal, challenge);

		if (pendingUserId > 0) {
			User user = userLocalService.fetchUser(pendingUserId);

			if (_isAuthenticated(user)) {
				return user;
			}
		}

		return getAuthenticatedUser(request, portal, userLocalService);
	}

	/**
	 * Delegates to {@link TotpRedirectUtil#getPostLoginRedirectUrl}.
	 *
	 * @throws PortalException if a Liferay service call fails
	 */
	public static String getPostLoginRedirectUrl(
			HttpServletRequest request, Portal portal, User user,
			TotpRoleChecker totpRoleChecker,
			GroupLocalService groupLocalService)
		throws PortalException {

		return TotpRedirectUtil.getPostLoginRedirectUrl(
			request, portal, user, totpRoleChecker, groupLocalService);
	}

	/**
	 * Marks TOTP as verified and clears any preserved post-login path.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void markTotpVerified(
		HttpServletRequest request, Portal portal) {

		_setTotpVerified(_getPortalSession(request, portal, false));
		_setTotpVerified(request.getSession(false));

		TotpSessionUtil.clearPostLoginPath(request, portal);
	}

	/**
	 * Clears the TOTP verified flag from the portal session.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void clearTotpVerified(
		HttpServletRequest request, Portal portal) {

		HttpSession session = _getPortalSession(request, portal, false);

		if (session != null) {
			session.removeAttribute("TOTP_VERIFIED");
		}
	}

	private static void _setTotpVerified(HttpSession session) {
		if (session != null) {
			session.setAttribute("TOTP_VERIFIED", Boolean.TRUE);

			if (_log.isInfoEnabled()) {
				_log.info(
					"TOTP_VERIFIED défini sur session " + session.getId());
			}
		}
	}

	private static HttpSession _getPortalSession(
		HttpServletRequest request, Portal portal, boolean create) {

		HttpServletRequest originalRequest = portal.getOriginalServletRequest(
			request);

		if (create) {
			return originalRequest.getSession();
		}

		return originalRequest.getSession(false);
	}

	private static User _getUserFromRemoteUser(
		HttpServletRequest request, UserLocalService userLocalService) {

		String remoteUser = request.getRemoteUser();

		if (Validator.isNull(remoteUser)) {
			return null;
		}

		return _fetchAuthenticatedUser(
			userLocalService, GetterUtil.getLong(remoteUser));
	}

	private static User _getUserFromPortalUserId(
		HttpServletRequest request, Portal portal,
		UserLocalService userLocalService) {

		try {
			long userId = portal.getUserId(request);

			return _fetchAuthenticatedUser(userLocalService, userId);
		}
		catch (Exception exception) {
			return null;
		}
	}

	private static User _getUserFromSession(
		HttpServletRequest request, Portal portal,
		UserLocalService userLocalService) {

		HttpSession session = _getPortalSession(request, portal, false);

		if (session == null) {
			session = request.getSession(false);
		}

		if (session == null) {
			return null;
		}

		Object userIdObject = session.getAttribute(WebKeys.USER_ID);

		if (userIdObject == null) {
			return null;
		}

		return _fetchAuthenticatedUser(
			userLocalService, GetterUtil.getLong(userIdObject));
	}

	private static User _getUserFromPortal(
		HttpServletRequest request, Portal portal) {

		try {
			User user = portal.getUser(request);

			return _isAuthenticated(user) ? user : null;
		}
		catch (Exception exception) {
			return null;
		}
	}

	private static User _getUserFromPermissionChecker(
		UserLocalService userLocalService) {

		PermissionChecker permissionChecker =
			PermissionThreadLocal.getPermissionChecker();

		if ((permissionChecker == null) ||
			!permissionChecker.isSignedIn()) {

			return null;
		}

		return _fetchAuthenticatedUser(
			userLocalService, permissionChecker.getUserId());
	}

	private static User _fetchAuthenticatedUser(
		UserLocalService userLocalService, long userId) {

		if (userId <= 0) {
			return null;
		}

		User user = userLocalService.fetchUser(userId);

		return _isAuthenticated(user) ? user : null;
	}

	private static boolean _isAuthenticated(User user) {
		return (user != null) && !user.isGuestUser();
	}

	private static String _getSessionId(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return "null";
		}

		return session.getId();
	}
}
