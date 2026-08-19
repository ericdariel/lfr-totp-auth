package com.monapp.totp.util;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.kernel.util.WebKeys;
import com.liferay.portal.security.auth.session.AuthenticatedSessionManagerUtil;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Stores and resolves pending administrator logins between password validation
 * (step 1) and TOTP verification (step 2).
 *
 * <p>Credentials are held in memory keyed by a challenge UUID and mirrored in
 * the HTTP session. Challenges expire after ten minutes.</p>
 *
 * @author monapp
 */
public class TotpPendingLoginUtil {

	/** Session attribute for the pending user ID. */
	public static final String TOTP_PENDING_USER_ID = "TOTP_PENDING_USER_ID";

	/** Session attribute for the pending login identifier. */
	public static final String TOTP_PENDING_LOGIN = "TOTP_PENDING_LOGIN";

	/** Session attribute for the pending password. */
	public static final String TOTP_PENDING_PASSWORD = "TOTP_PENDING_PASSWORD";

	/** Session attribute for the remember-me flag. */
	public static final String TOTP_PENDING_REMEMBER_ME = "TOTP_PENDING_REMEMBER_ME";

	/** Session attribute for the pending authentication type. */
	public static final String TOTP_PENDING_AUTH_TYPE = "TOTP_PENDING_AUTH_TYPE";

	/** Query parameter and cache key for the MFA challenge token. */
	public static final String CHALLENGE_PARAM = "challenge";

	private static final long CHALLENGE_TTL_MS = 10 * 60 * 1000L;

	private static final Log _log = LogFactoryUtil.getLog(
		TotpPendingLoginUtil.class);

	private static final ConcurrentHashMap<String, PendingLoginEntry>
		_challengeCache = new ConcurrentHashMap<>();

	private TotpPendingLoginUtil() {
	}

	/**
	 * Stores pending login credentials and returns a new challenge token.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param userId resolved user ID
	 * @param login login identifier
	 * @param password plain-text password
	 * @param rememberMe remember-me flag
	 * @param authType authentication type
	 * @param redirect optional post-login redirect path
	 * @return challenge UUID
	 */
	public static String storePendingLogin(
		HttpServletRequest request, Portal portal, long userId, String login,
		String password, boolean rememberMe, String authType, String redirect) {

		String challenge = UUID.randomUUID().toString();

		_challengeCache.put(
			challenge,
			new PendingLoginEntry(
				userId, login, password, rememberMe, authType,
				System.currentTimeMillis()));

		for (HttpSession session : _getSessions(request, portal, true)) {
			_setPendingAttributes(
				session, userId, login, password, rememberMe, authType,
				redirect);
		}

		TotpSessionUtil.clearTotpVerified(request, portal);

		if (_log.isInfoEnabled()) {
			HttpSession session = TotpSessionUtil.getPortalSession(
				request, portal, false);

			_log.info(
				"Session TOTP en attente stockée : userId=" + userId +
					", sessionId=" +
						((session != null) ? session.getId() : "null") +
							", challenge=" + challenge);
		}

		return challenge;
	}

	/**
	 * Returns {@code true} when a pending login exists in session or cache.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static boolean hasPendingLogin(
		HttpServletRequest request, Portal portal) {

		if (getPendingUserId(request, portal) > 0) {
			return true;
		}

		return getPendingUserId(
			request.getParameter(CHALLENGE_PARAM)) > 0;
	}

	/**
	 * Returns the pending user ID from session attributes.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @return user ID or {@code 0}
	 */
	public static long getPendingUserId(
		HttpServletRequest request, Portal portal) {

		for (HttpSession session : _getSessions(request, portal, false)) {
			if (session == null) {
				continue;
			}

			long userId = GetterUtil.getLong(
				session.getAttribute(TOTP_PENDING_USER_ID));

			if (userId > 0) {
				return userId;
			}
		}

		return 0;
	}

	/**
	 * Returns the pending user ID for a challenge token.
	 *
	 * @param challenge challenge UUID
	 * @return user ID or {@code 0} when invalid or expired
	 */
	public static long getPendingUserId(String challenge) {
		PendingLoginEntry entry = _getValidEntry(challenge);

		if (entry != null) {
			return entry.userId;
		}

		return 0;
	}

	/**
	 * Resolves the pending user ID from the challenge or session.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param challenge optional challenge query parameter
	 * @return user ID or {@code 0}
	 */
	public static long resolvePendingUserId(
		HttpServletRequest request, Portal portal, String challenge) {

		if (Validator.isNotNull(challenge)) {
			long userId = getPendingUserId(challenge);

			if (userId > 0) {
				return userId;
			}
		}

		return getPendingUserId(request, portal);
	}

	/**
	 * Stores temporary TOTP setup data on the challenge entry.
	 *
	 * @param challenge challenge UUID
	 * @param tempSecret generated secret pending confirmation
	 * @param backupCodes generated backup codes pending confirmation
	 */
	public static void storeSetupTempData(
		String challenge, String tempSecret, List<String> backupCodes) {

		PendingLoginEntry entry = _getValidEntry(challenge);

		if (entry != null) {
			entry.tempSecret = tempSecret;
			entry.backupCodes = backupCodes;
		}
	}

	/**
	 * Returns the temporary setup secret for a challenge.
	 *
	 * @param challenge challenge UUID
	 * @return secret or {@code null}
	 */
	public static String getSetupTempSecret(String challenge) {
		PendingLoginEntry entry = _getValidEntry(challenge);

		if (entry != null) {
			return entry.tempSecret;
		}

		return null;
	}

	/**
	 * Returns the temporary backup codes for a challenge.
	 *
	 * @param challenge challenge UUID
	 * @return backup codes or {@code null}
	 */
	public static List<String> getSetupBackupCodes(String challenge) {
		PendingLoginEntry entry = _getValidEntry(challenge);

		if (entry != null) {
			return entry.backupCodes;
		}

		return null;
	}

	/**
	 * Marks a challenge as TOTP-verified, allowing login completion.
	 *
	 * @param challenge challenge UUID
	 */
	public static void markChallengeVerified(String challenge) {
		PendingLoginEntry entry = _getValidEntry(challenge);

		if (entry != null) {
			entry.totpVerified = true;

			if (_log.isInfoEnabled()) {
				_log.info("Challenge TOTP validé : " + challenge);
			}
		}
	}

	/**
	 * Creates the portal session from a verified pending login challenge.
	 *
	 * @param request current servlet request
	 * @param response current servlet response
	 * @param portal portal utility
	 * @param challenge verified challenge UUID
	 * @throws Exception if the challenge is invalid or login fails
	 */
	public static void completePendingLogin(
			HttpServletRequest request, HttpServletResponse response,
			Portal portal, String challenge)
		throws Exception {

		PendingLoginEntry entry = _getVerifiedEntry(challenge);

		if (entry == null) {
			throw new IllegalStateException(
				"Challenge TOTP invalide, expiré ou non validé.");
		}

		clearPendingLogin(request, portal, challenge);

		HttpServletRequest originalRequest = portal.getOriginalServletRequest(
			request);

		_clearLastPath(originalRequest, portal);

		AuthenticatedSessionManagerUtil.login(
			originalRequest, response, entry.login, entry.password,
			entry.rememberMe, entry.authType);

		TotpSessionUtil.markTotpVerified(originalRequest, portal);
	}

	/**
	 * Clears pending login data from all sessions.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 */
	public static void clearPendingLogin(
		HttpServletRequest request, Portal portal) {

		clearPendingLogin(request, portal, null);
	}

	/**
	 * Clears pending login data from sessions and optionally removes a challenge
	 * from the in-memory cache.
	 *
	 * @param request current servlet request
	 * @param portal portal utility
	 * @param challenge optional challenge to evict from cache
	 */
	public static void clearPendingLogin(
		HttpServletRequest request, Portal portal, String challenge) {

		for (HttpSession session : _getSessions(request, portal, false)) {
			if (session == null) {
				continue;
			}

			session.removeAttribute(TOTP_PENDING_USER_ID);
			session.removeAttribute(TOTP_PENDING_LOGIN);
			session.removeAttribute(TOTP_PENDING_PASSWORD);
			session.removeAttribute(TOTP_PENDING_REMEMBER_ME);
			session.removeAttribute(TOTP_PENDING_AUTH_TYPE);
		}

		if (Validator.isNotNull(challenge)) {
			_challengeCache.remove(challenge);
		}
	}

	private static PendingLoginEntry _getVerifiedEntry(String challenge) {
		PendingLoginEntry entry = _getValidEntry(challenge);

		if ((entry != null) && entry.totpVerified) {
			return entry;
		}

		return null;
	}

	private static PendingLoginEntry _getValidEntry(String challenge) {
		if (Validator.isNull(challenge)) {
			return null;
		}

		PendingLoginEntry entry = _challengeCache.get(challenge);

		if (entry == null) {
			return null;
		}

		if ((System.currentTimeMillis() - entry.createdAt) > CHALLENGE_TTL_MS) {
			_challengeCache.remove(challenge);

			return null;
		}

		return entry;
	}

	private static void _setPendingAttributes(
		HttpSession session, long userId, String login, String password,
		boolean rememberMe, String authType, String redirect) {

		if (session == null) {
			return;
		}

		session.setAttribute(TOTP_PENDING_USER_ID, userId);
		session.setAttribute(TOTP_PENDING_LOGIN, login);
		session.setAttribute(TOTP_PENDING_PASSWORD, password);
		session.setAttribute(TOTP_PENDING_REMEMBER_ME, rememberMe);
		session.setAttribute(TOTP_PENDING_AUTH_TYPE, authType);

		if (Validator.isNotNull(redirect)) {
			session.setAttribute(TotpSessionUtil.TOTP_POST_LOGIN_PATH, redirect);
		}
	}

	private static void _clearLastPath(
		HttpServletRequest request, Portal portal) {

		for (HttpSession session : _getSessions(request, portal, false)) {
			if (session != null) {
				session.removeAttribute(WebKeys.LAST_PATH);
			}
		}
	}

	private static HttpSession[] _getSessions(
		HttpServletRequest request, Portal portal, boolean create) {

		HttpSession portalSession = TotpSessionUtil.getPortalSession(
			request, portal, create);
		HttpSession requestSession = create ?
			request.getSession() : request.getSession(false);

		if ((portalSession != null) &&
			portalSession.equals(requestSession)) {

			return new HttpSession[] {portalSession};
		}

		return new HttpSession[] {portalSession, requestSession};
	}

	/** In-memory pending login state keyed by challenge UUID. */
	private static class PendingLoginEntry {

		private PendingLoginEntry(
			long userId, String login, String password, boolean rememberMe,
			String authType, long createdAt) {

			this.userId = userId;
			this.login = login;
			this.password = password;
			this.rememberMe = rememberMe;
			this.authType = authType;
			this.createdAt = createdAt;
		}

		private final long userId;
		private final String login;
		private final String password;
		private final boolean rememberMe;
		private final String authType;
		private final long createdAt;
		private boolean totpVerified;
		private String tempSecret;
		private List<String> backupCodes;

	}

}
