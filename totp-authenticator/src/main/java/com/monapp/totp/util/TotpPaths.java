package com.monapp.totp.util;

import com.liferay.portal.kernel.util.URLCodec;

/**
 * Canonical URL paths and helpers for TOTP-related portal routes.
 *
 * @author monapp
 */
public final class TotpPaths {

	/** Friendly URL of the TOTP verification fragment page. */
	public static final String VERIFY_PAGE = "/web/guest/totp-verify";

	/** Friendly URL of the TOTP setup fragment page. */
	public static final String SETUP_PAGE = "/web/guest/totp-setup";

	/** Servlet path used by {@code TOTPLoginFilter} to finalize MFA login. */
	public static final String COMPLETE_LOGIN_PATH =
		"/c/portal/totp-complete-login";

	/** Base path of the JAX-RS application exposed by {@code totp-rest}. */
	public static final String REST_API_PREFIX = "/o/totp/api";

	private TotpPaths() {
	}

	/**
	 * Builds the URL that completes a pending MFA login for the given challenge.
	 *
	 * @param portalURL absolute portal URL (scheme, host, context)
	 * @param challenge pending-login challenge token
	 * @return complete-login URL with encoded challenge query parameter
	 */
	public static String getCompleteLoginUrl(
		String portalURL, String challenge) {

		return portalURL + COMPLETE_LOGIN_PATH + "?" +
			TotpPendingLoginUtil.CHALLENGE_PARAM + "=" +
				URLCodec.encodeURL(challenge);
	}

	/**
	 * Returns {@code true} if the request path targets the MFA login completion
	 * servlet endpoint.
	 *
	 * @param path request URI or path fragment
	 */
	public static boolean isCompleteLoginPath(String path) {
		if ((path == null) || path.isEmpty()) {
			return false;
		}

		return path.contains(COMPLETE_LOGIN_PATH);
	}

	/**
	 * Returns {@code true} if the request path targets the TOTP REST API.
	 *
	 * @param path request URI or path fragment
	 */
	public static boolean isRestApiPath(String path) {
		if ((path == null) || path.isEmpty()) {
			return false;
		}

		return path.contains(REST_API_PREFIX);
	}

	/**
	 * Returns {@code true} if the path targets the TOTP verify fragment page.
	 *
	 * @param path request URI or path fragment
	 */
	public static boolean isVerifyPage(String path) {
		if ((path == null) || path.isEmpty()) {
			return false;
		}

		return path.contains("/totp-verify");
	}

	/**
	 * Returns {@code true} if the path targets the TOTP setup fragment page.
	 *
	 * @param path request URI or path fragment
	 */
	public static boolean isSetupPage(String path) {
		if ((path == null) || path.isEmpty()) {
			return false;
		}

		return path.contains("/totp-setup");
	}

	/**
	 * Returns {@code true} if the path belongs to any TOTP-specific route that
	 * should be excluded from post-login redirect preservation.
	 *
	 * @param path request URI or path fragment
	 */
	public static boolean isTotpPath(String path) {
		return isVerifyPage(path) || isSetupPage(path) ||
			isRestApiPath(path) || isCompleteLoginPath(path);
	}

}
