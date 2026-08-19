package com.monapp.totp.util;

import com.liferay.portal.kernel.struts.LastPath;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.kernel.util.WebKeys;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Helpers for TOTP-related HTTP session attributes.
 *
 * @author monapp
 */
public class TotpSessionUtil {

	/** Session attribute indicating TOTP was verified for the current session. */
	public static final String TOTP_VERIFIED = "TOTP_VERIFIED";

	/** Session attribute storing a preserved post-login redirect path. */
	public static final String TOTP_POST_LOGIN_PATH = "TOTP_POST_LOGIN_PATH";

	private TotpSessionUtil() {
	}

	/**
	 * Copies {@link WebKeys#LAST_PATH} into {@link #TOTP_POST_LOGIN_PATH} when
	 * not already set and the path is not TOTP-specific.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void preservePostLoginPath(
		HttpServletRequest request, Portal portal) {

		for (HttpSession session : _getSessions(request, portal)) {
			if (session == null) {
				continue;
			}

			if (session.getAttribute(TOTP_POST_LOGIN_PATH) != null) {
				return;
			}

			LastPath lastPath = (LastPath)session.getAttribute(
				WebKeys.LAST_PATH);

			if (lastPath == null) {
				continue;
			}

			String path = lastPath.getPath();

			if (Validator.isNotNull(path) && !isTotpPath(path)) {
				session.setAttribute(TOTP_POST_LOGIN_PATH, path);
			}
		}
	}

	/**
	 * Returns the preserved post-login path, if any.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @return redirect path or {@code null}
	 */
	public static String getPostLoginPath(
		HttpServletRequest request, Portal portal) {

		for (HttpSession session : _getSessions(request, portal)) {
			if (session == null) {
				continue;
			}

			String path = (String)session.getAttribute(TOTP_POST_LOGIN_PATH);

			if (Validator.isNotNull(path)) {
				return path;
			}
		}

		return null;
	}

	/**
	 * Removes the preserved post-login path from all relevant sessions.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void clearPostLoginPath(
		HttpServletRequest request, Portal portal) {

		for (HttpSession session : _getSessions(request, portal)) {
			if (session != null) {
				session.removeAttribute(TOTP_POST_LOGIN_PATH);
			}
		}
	}

	/**
	 * Delegates to {@link TotpPaths#isTotpPath(String)}.
	 *
	 * @param path request path
	 */
	public static boolean isTotpPath(String path) {
		return TotpPaths.isTotpPath(path);
	}

	/**
	 * Returns the portal HTTP session from the original servlet request.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param create whether to create the session if absent
	 * @return portal session, or {@code null} when not creating and absent
	 */
	public static HttpSession getPortalSession(
		HttpServletRequest request, Portal portal, boolean create) {

		HttpServletRequest originalRequest = portal.getOriginalServletRequest(
			request);

		if (create) {
			return originalRequest.getSession();
		}

		return originalRequest.getSession(false);
	}

	/**
	 * Marks TOTP as verified on both the portal and wrapper sessions.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void markTotpVerified(
		HttpServletRequest request, Portal portal) {

		_setTotpVerified(_getSession(request, portal, false));
		_setTotpVerified(request.getSession(false));
	}

	/**
	 * Returns {@code true} if TOTP was verified on any relevant session.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static boolean isTotpVerified(
		HttpServletRequest request, Portal portal) {

		if (_isTotpVerified(_getSession(request, portal, false))) {
			return true;
		}

		return _isTotpVerified(request.getSession(false));
	}

	/**
	 * Clears the TOTP verified flag from all relevant sessions.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void clearTotpVerified(
		HttpServletRequest request, Portal portal) {

		_clearTotpVerified(_getSession(request, portal, false));
		_clearTotpVerified(request.getSession(false));
	}

	private static HttpSession[] _getSessions(
		HttpServletRequest request, Portal portal) {

		return new HttpSession[] {
			getPortalSession(request, portal, false),
			request.getSession(false)
		};
	}

	private static HttpSession _getSession(
		HttpServletRequest request, Portal portal, boolean create) {

		HttpServletRequest originalRequest = portal.getOriginalServletRequest(
			request);

		if (create) {
			return originalRequest.getSession();
		}

		return originalRequest.getSession(false);
	}

	private static void _setTotpVerified(HttpSession session) {
		if (session != null) {
			session.setAttribute(TOTP_VERIFIED, Boolean.TRUE);
		}
	}

	private static boolean _isTotpVerified(HttpSession session) {
		return (session != null) &&
			Boolean.TRUE.equals(session.getAttribute(TOTP_VERIFIED));
	}

	private static void _clearTotpVerified(HttpSession session) {
		if (session != null) {
			session.removeAttribute(TOTP_VERIFIED);
		}
	}

}
