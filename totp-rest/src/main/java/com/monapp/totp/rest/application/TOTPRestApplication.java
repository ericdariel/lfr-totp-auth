package com.monapp.totp.rest.application;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.json.JSONArray;
import com.liferay.portal.kernel.json.JSONFactoryUtil;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.json.JSONUtil;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.service.GroupLocalService;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.monapp.totp.rest.util.TotpRestUtil;
import com.monapp.totp.service.TOTPService;
import com.monapp.totp.service.TotpRoleChecker;
import com.monapp.totp.util.TotpPaths;
import com.monapp.totp.util.TotpPendingLoginUtil;
import com.monapp.totp.util.TotpSessionUtil;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.JaxrsWhiteboardConstants;

/**
 * JAX-RS application exposing TOTP setup and verification endpoints at
 * {@code /o/totp/api}.
 *
 * @author monapp
 */
@Component(
	immediate = true,
	property = {
		JaxrsWhiteboardConstants.JAX_RS_APPLICATION_BASE + "=/totp/api",
		JaxrsWhiteboardConstants.JAX_RS_NAME + "=TOTP.Rest.Application",
		"auth.verifier.PortalSessionAuthVerifier.urls.includes=/totp/api/*",
		"auth.verifier.guest.allowed=true",
		"liferay.access.control.disable=true",
		"liferay.oauth2=false",
		"oauth2.scope.checker.type=none"
	},
	service = Application.class
)
public class TOTPRestApplication extends Application {

	@Override
	public Set<Object> getSingletons() {
		return Collections.<Object>singleton(this);
	}

	/**
	 * Health check endpoint.
	 *
	 * @return plain-text {@code ok} response
	 */
	@GET
	@Path("/ping")
	@Produces(MediaType.TEXT_PLAIN)
	public Response ping() {
		return Response.ok("ok").build();
	}

	/**
	 * Initializes TOTP setup: generates secret, QR code, and backup codes.
	 *
	 * @param request servlet request
	 * @param challenge optional pending-login challenge
	 * @return JSON with QR data or {@code alreadyConfigured} flag
	 */
	@GET
	@Path("/setup/init")
	@Produces(MediaType.APPLICATION_JSON)
	public Response setupInit(
		@Context HttpServletRequest request,
		@QueryParam("challenge") String challenge) {

		_log.info("GET /o/totp/api/setup/init");

		try {
			User user = TotpRestUtil.getUserForVerification(
				request, _portal, _userLocalService, challenge);

			if (user == null) {
				return _unauthorized(
					"Session expirée. Veuillez vous reconnecter.");
			}

			if (!_totpRoleChecker.requiresTotp(user)) {
				return _forbidden();
			}

			if (Validator.isNotNull(_totpService.getTotpSecret(user))) {
				return Response.ok(
					JSONUtil.put("alreadyConfigured", true).toString()
				).build();
			}

			String secret = _totpService.generateSecret();
			String otpAuthUrl = _totpService.generateOtpAuthUrl(
				"MonAppLiferay", user.getEmailAddress(), secret);
			String qrCodeBase64 = _totpService.generateQRCodeBase64(
				otpAuthUrl);
			List<String> backupCodes = _totpService.generateBackupCodes();

			if (Validator.isNotNull(challenge)) {
				TotpPendingLoginUtil.storeSetupTempData(
					challenge, secret, backupCodes);
			}
			else {
				HttpSession session = TotpSessionUtil.getPortalSession(
					request, _portal, true);

				session.setAttribute("TOTP_TEMP_SECRET", secret);
				session.setAttribute("TOTP_BACKUP_CODES", backupCodes);
			}

			JSONArray backupCodesJson = JSONFactoryUtil.createJSONArray();

			for (String code : backupCodes) {
				backupCodesJson.put(code);
			}

			return Response.ok(
				JSONUtil.put("alreadyConfigured", false)
					.put("qrCodeBase64", qrCodeBase64)
					.put("secret", secret)
					.put("backupCodes", backupCodesJson)
					.toString()
			).build();
		}
		catch (Exception exception) {
			_log.error("Erreur init setup TOTP", exception);

			return _serverError("Erreur lors de l'initialisation");
		}
	}

	/**
	 * Confirms TOTP setup by validating a six-digit code and persisting the
	 * secret and backup codes.
	 *
	 * @param request servlet request
	 * @param body JSON body with {@code confirmCode} and optional
	 *        {@code challenge}
	 * @return JSON success payload with redirect or complete-login URL
	 */
	@POST
	@Path("/setup/confirm")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response setupConfirm(
		@Context HttpServletRequest request, String body) {

		try {
			JSONObject bodyJson = JSONFactoryUtil.createJSONObject(body);
			String challenge = bodyJson.getString("challenge");

			User user = TotpRestUtil.getUserForVerification(
				request, _portal, _userLocalService, challenge);

			if (user == null) {
				return _unauthorized(
					"Session expirée. Veuillez vous reconnecter.");
			}

			if (!_totpRoleChecker.requiresTotp(user)) {
				return _forbidden();
			}

			String tempSecret = _getTempSecret(request, challenge);

			if (Validator.isNull(tempSecret)) {
				return _sessionExpiredBadRequest(
					"Session expirée. Veuillez recommencer.");
			}

			String confirmCodeStr = bodyJson.getString("confirmCode");

			if (Validator.isNull(confirmCodeStr) ||
				!confirmCodeStr.matches("\\d{6}")) {

				return _badRequest("Code invalide.");
			}

			if (!_totpService.verifyCode(
					tempSecret, Integer.parseInt(confirmCodeStr))) {

				return Response.status(Response.Status.UNAUTHORIZED)
					.entity(
						JSONUtil.put("success", false)
							.put("message", "Code incorrect")
							.toString())
					.build();
			}

			_totpService.saveTotpSecret(user, tempSecret);

			List<String> backupCodes = _getBackupCodes(request, challenge);

			if (backupCodes != null) {
				_totpService.saveBackupCodes(user, backupCodes);
			}

			_clearTempData(request, challenge);

			if (TotpPendingLoginUtil.resolvePendingUserId(
					request, _portal, challenge) > 0) {

				TotpPendingLoginUtil.markChallengeVerified(challenge);

				if (_log.isInfoEnabled()) {
					_log.info(
						"TOTP configuré pour " + user.getEmailAddress() +
							", finalisation login");
				}

				return Response.ok(
					JSONUtil.put("success", true)
						.put("completeLogin", true)
						.put(
							"completeLoginUrl",
							TotpPaths.getCompleteLoginUrl(
								_portal.getPortalURL(request), challenge))
						.toString()
				).build();
			}

			TotpRestUtil.markTotpVerified(request, _portal);

			return Response.ok(
				JSONUtil.put("success", true)
					.put("redirectUrl", TotpRestUtil.getPostLoginRedirectUrl(
						request, _portal, user, _totpRoleChecker,
						_groupLocalService))
					.toString()
			).build();
		}
		catch (Exception exception) {
			_log.error("Erreur confirmation TOTP", exception);

			return _serverError("Erreur lors de la confirmation");
		}
	}

	/**
	 * Resets TOTP configuration for the current administrator.
	 *
	 * @param request servlet request
	 * @param challenge optional pending-login challenge
	 * @return JSON {@code success} flag
	 */
	@POST
	@Path("/setup/reset")
	@Produces(MediaType.APPLICATION_JSON)
	public Response setupReset(
		@Context HttpServletRequest request,
		@QueryParam("challenge") String challenge) {

		try {
			User user = TotpRestUtil.getUserForVerification(
				request, _portal, _userLocalService, challenge);

			if (user == null) {
				return _unauthorized("Non authentifié");
			}

			if (!_totpRoleChecker.requiresTotp(user)) {
				return _forbidden();
			}

			_totpService.deleteTotpSecret(user);
			_totpService.deleteBackupCodes(user);
			_clearTempData(request, challenge);
			TotpRestUtil.clearTotpVerified(request, _portal);

			return Response.ok(JSONUtil.put("success", true).toString()).build();
		}
		catch (Exception exception) {
			_log.error("Erreur reset TOTP", exception);

			return _serverError("Erreur lors de la réinitialisation");
		}
	}

	/**
	 * Verifies a six-digit TOTP code (step 2 of login or session refresh).
	 *
	 * @param request servlet request
	 * @param body JSON body with {@code code} and optional {@code challenge}
	 * @return JSON success payload with redirect or complete-login URL
	 */
	@POST
	@Path("/verify/code")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response verifyCode(
		@Context HttpServletRequest request, String body) {

		_log.info("POST /o/totp/api/verify/code");

		try {
			JSONObject bodyJson = JSONFactoryUtil.createJSONObject(body);
			String challenge = bodyJson.getString("challenge");

			User user = TotpRestUtil.getUserForVerification(
				request, _portal, _userLocalService, challenge);

			if (user == null) {
				return _unauthorized(
					"Session expirée. Veuillez vous reconnecter.");
			}

			String codeStr = bodyJson.getString("code");

			if (Validator.isNull(codeStr) || !codeStr.matches("\\d{6}")) {
				return _badRequest("Le code doit contenir 6 chiffres.");
			}

			String secret = _totpService.getTotpSecret(user);

			if (Validator.isNull(secret)) {
				return _badRequest("TOTP non configuré.");
			}

			if (!_totpService.verifyCode(secret, Integer.parseInt(codeStr))) {
				return Response.status(Response.Status.UNAUTHORIZED)
					.entity(
						JSONUtil.put("success", false)
							.put("message", "Code incorrect")
							.toString())
					.build();
			}

			if (TotpPendingLoginUtil.resolvePendingUserId(
					request, _portal, challenge) > 0) {

				TotpPendingLoginUtil.markChallengeVerified(challenge);

				return Response.ok(
					JSONUtil.put("success", true)
						.put("completeLogin", true)
						.put(
							"completeLoginUrl",
							TotpPaths.getCompleteLoginUrl(
								_portal.getPortalURL(request), challenge))
						.toString()
				).build();
			}

			TotpRestUtil.markTotpVerified(request, _portal);

			return Response.ok(
				JSONUtil.put("success", true)
					.put("redirectUrl", TotpRestUtil.getPostLoginRedirectUrl(
						request, _portal, user, _totpRoleChecker,
						_groupLocalService))
					.toString()
			).build();
		}
		catch (Exception exception) {
			_log.error("Erreur vérification TOTP", exception);

			return _serverError("Erreur lors de la vérification");
		}
	}

	/**
	 * Verifies a single-use backup recovery code.
	 *
	 * @param request servlet request
	 * @param body JSON body with {@code code} and optional {@code challenge}
	 * @return JSON success payload with redirect or complete-login URL
	 */
	@POST
	@Path("/verify/backup")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response verifyBackup(
		@Context HttpServletRequest request, String body) {

		try {
			JSONObject bodyJson = JSONFactoryUtil.createJSONObject(body);
			String challenge = bodyJson.getString("challenge");

			User user = TotpRestUtil.getUserForVerification(
				request, _portal, _userLocalService, challenge);

			if (user == null) {
				return _unauthorized(
					"Session expirée. Veuillez vous reconnecter.");
			}

			String code = bodyJson.getString("code");

			if (Validator.isNull(code)) {
				return _badRequest("Backup code is required.");
			}

			if (!_totpService.verifyBackupCode(user, code)) {
				return Response.status(Response.Status.UNAUTHORIZED)
					.entity(
						JSONUtil.put("success", false)
							.put("message",
								"Code de secours invalide ou déjà utilisé")
							.toString())
					.build();
			}

			if (TotpPendingLoginUtil.resolvePendingUserId(
					request, _portal, challenge) > 0) {

				TotpPendingLoginUtil.markChallengeVerified(challenge);

				return Response.ok(
					JSONUtil.put("success", true)
						.put("completeLogin", true)
						.put(
							"completeLoginUrl",
							TotpPaths.getCompleteLoginUrl(
								_portal.getPortalURL(request), challenge))
						.toString()
				).build();
			}

			TotpRestUtil.markTotpVerified(request, _portal);

			return Response.ok(
				JSONUtil.put("success", true)
					.put("redirectUrl", TotpRestUtil.getPostLoginRedirectUrl(
						request, _portal, user, _totpRoleChecker,
						_groupLocalService))
					.toString()
			).build();
		}
		catch (Exception exception) {
			_log.error("Erreur vérification code secours TOTP", exception);

			return _serverError("Erreur lors de la vérification");
		}
	}

	private String _getTempSecret(
		HttpServletRequest request, String challenge) {

		if (Validator.isNotNull(challenge)) {
			return TotpPendingLoginUtil.getSetupTempSecret(challenge);
		}

		HttpSession session = TotpSessionUtil.getPortalSession(
			request, _portal, false);

		if (session == null) {
			return null;
		}

		return (String)session.getAttribute("TOTP_TEMP_SECRET");
	}

	private List<String> _getBackupCodes(
		HttpServletRequest request, String challenge) {

		if (Validator.isNotNull(challenge)) {
			return TotpPendingLoginUtil.getSetupBackupCodes(challenge);
		}

		HttpSession session = TotpSessionUtil.getPortalSession(
			request, _portal, false);

		if (session == null) {
			return null;
		}

		return (List<String>)session.getAttribute("TOTP_BACKUP_CODES");
	}

	private void _clearTempData(
		HttpServletRequest request, String challenge) {

		if (Validator.isNotNull(challenge)) {
			TotpPendingLoginUtil.storeSetupTempData(challenge, null, null);

			return;
		}

		HttpSession session = TotpSessionUtil.getPortalSession(
			request, _portal, false);

		if (session != null) {
			session.removeAttribute("TOTP_TEMP_SECRET");
			session.removeAttribute("TOTP_BACKUP_CODES");
		}
	}

	private Response _unauthorized(String message) {
		return Response.status(Response.Status.UNAUTHORIZED)
			.entity(
				JSONUtil.put("message", message)
					.put("sessionExpired", true)
					.toString())
			.build();
	}

	private Response _sessionExpiredBadRequest(String message) {
		return Response.status(Response.Status.BAD_REQUEST)
			.entity(
				JSONUtil.put("message", message)
					.put("sessionExpired", true)
					.toString())
			.build();
	}

	private Response _forbidden() {
		return Response.status(Response.Status.FORBIDDEN)
			.entity(JSONUtil.put("message", "Accès refusé").toString()).build();
	}

	private Response _badRequest(String message) {
		return Response.status(Response.Status.BAD_REQUEST)
			.entity(JSONUtil.put("message", message).toString()).build();
	}

	private Response _serverError(String message) {
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
			.entity(JSONUtil.put("message", message).toString()).build();
	}

	private static final Log _log = LogFactoryUtil.getLog(
		TOTPRestApplication.class);

	@Reference
	private TOTPService _totpService;

	@Reference
	private TotpRoleChecker _totpRoleChecker;

	@Reference
	private Portal _portal;

	@Reference
	private UserLocalService _userLocalService;

	@Reference
	private GroupLocalService _groupLocalService;

}
