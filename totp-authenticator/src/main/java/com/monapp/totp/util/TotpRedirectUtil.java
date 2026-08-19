package com.monapp.totp.util;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.Group;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.service.GroupLocalService;
import com.liferay.portal.kernel.struts.LastPath;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.kernel.util.WebKeys;
import com.monapp.totp.service.TotpRoleChecker;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Resolves post-login redirect URLs after successful TOTP verification.
 *
 * @author monapp
 */
public class TotpRedirectUtil {

	private static final Log _log = LogFactoryUtil.getLog(
		TotpRedirectUtil.class);

	private TotpRedirectUtil() {
	}

	/**
	 * Resolves the best redirect URL after MFA for the given user.
	 *
	 * <p>Priority: {@link WebKeys#LAST_PATH}, first user site, preserved TOTP
	 * path, Control Panel for users with the configured MFA role, then portal
	 * main path.</p>
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param user authenticated user
	 * @param totpRoleChecker configured MFA role checker
	 * @param groupLocalService group local service
	 * @return absolute redirect URL
	 * @throws PortalException if a Liferay service call fails
	 */
	public static String getPostLoginRedirectUrl(
			HttpServletRequest request, Portal portal, User user,
			TotpRoleChecker totpRoleChecker,
			GroupLocalService groupLocalService)
		throws PortalException {

		String sitePath = _getLastPathRedirect(request, portal);

		if (Validator.isNull(sitePath)) {
			if (_log.isInfoEnabled()) {
				_log.info("Aucun site trouvé, redirection vers le premier site de l'utilisateur");
			}

			sitePath = _resolveFirstUserSitePath(user.getUserId(),
				groupLocalService);
		}

		if (Validator.isNotNull(sitePath)) {
			String redirectUrl = _buildRedirectUrl(request, portal, sitePath);

			if (_log.isInfoEnabled()) {
				_log.info("Redirection post-login vers le site : " +
					redirectUrl);
			}

			return redirectUrl;
		}

		String preservedPath = TotpSessionUtil.getPostLoginPath(
			request, portal);

		if (Validator.isNotNull(preservedPath) &&
			!_isGenericPath(preservedPath, portal)) {

			String redirectUrl = _buildRedirectUrl(
				request, portal, preservedPath);

			if (_log.isInfoEnabled()) {
				_log.info(
					"Redirection post-login via TOTP_POST_LOGIN_PATH : " +
						redirectUrl);
			}

			return redirectUrl;
		}

		if (totpRoleChecker.requiresTotp(user)) {
			return portal.getPortalURL(request) + "/group/control_panel";
		}

		return portal.getPortalURL(request) + portal.getPathMain();
	}

	/**
	 * Returns a redirect URL based solely on {@link WebKeys#LAST_PATH}, or the
	 * portal main path when unavailable.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @return absolute redirect URL
	 */
	public static String getLastPathRedirectUrl(
		HttpServletRequest request, Portal portal) {

		String lastPath = _getLastPathRedirect(request, portal);

		if (Validator.isNotNull(lastPath)) {
			String redirectUrl = _buildRedirectUrl(request, portal, lastPath);

			if (_log.isInfoEnabled()) {
				_log.info(
					"Redirection post-login via LAST_PATH : " + redirectUrl);
			}

			return redirectUrl;
		}

		return portal.getPortalURL(request) + portal.getPathMain();
	}

	private static String _getLastPathRedirect(
		HttpServletRequest request, Portal portal) {

		for (HttpSession session : _getSessions(request, portal)) {
			if (session == null) {
				continue;
			}

			LastPath lastPath = (LastPath)session.getAttribute(
				WebKeys.LAST_PATH);

			if (lastPath == null) {
				continue;
			}

			String path = lastPath.getPath();

			if (Validator.isNotNull(path) &&
				!TotpSessionUtil.isTotpPath(path) &&
				!_isGenericPath(path, portal)) {

				if (_log.isDebugEnabled()) {
					_log.debug(
						"LAST_PATH trouvé en session " + session.getId() +
							" : " + path);
				}

				return path;
			}
		}

		return null;
	}

	private static String _resolveFirstUserSitePath(
			long userId, GroupLocalService groupLocalService)
		throws PortalException {

		List<Group> groups = groupLocalService.getUserSitesGroups(
			userId, false);

		for (Group group : groups) {
			if (group.isActive() && group.hasPrivateLayouts() &&
				!group.isGuest() && group.getChildren(true).isEmpty()) {

				return "/group" + group.getFriendlyURL();
			}
		}

		return null;
	}

	private static String _buildRedirectUrl(
		HttpServletRequest request, Portal portal, String path) {

		String escapedPath = portal.escapeRedirect(path);

		if (escapedPath.startsWith("http://") ||
			escapedPath.startsWith("https://")) {

			return escapedPath;
		}

		return portal.getPortalURL(request) + escapedPath;
	}

	private static boolean _isGenericPath(String path, Portal portal) {
		if (Validator.isNull(path)) {
			return true;
		}

		if (path.equals("/c/portal") || path.startsWith("/c/portal/login")) {
			return true;
		}

		if (path.equals("/web/guest") || path.startsWith("/web/guest/home")) {
			return true;
		}

		String pathMain = portal.getPathMain();

		return path.equals(pathMain);
	}

	private static HttpSession[] _getSessions(
		HttpServletRequest request, Portal portal) {

		return new HttpSession[] {
			TotpSessionUtil.getPortalSession(request, portal, false),
			request.getSession(false)
		};
	}

}
