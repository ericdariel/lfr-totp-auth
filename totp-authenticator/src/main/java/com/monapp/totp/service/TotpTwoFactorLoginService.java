package com.monapp.totp.service;

import com.liferay.portal.kernel.theme.ThemeDisplay;

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * OSGi service that implements step 1 of the MFA login flow for users in the
 * configured role.
 *
 * <p>When MFA applies, credentials are validated without creating a portal
 * session and the user is redirected to setup or verify.</p>
 *
 * @author monapp
 */
public interface TotpTwoFactorLoginService {

	/**
	 * Attempts to start the TOTP challenge for a login when the user belongs to
	 * the configured MFA role.
	 *
	 * <p>Returns {@code true} when MFA handling took over the request (password
	 * validated, pending login stored, redirect sent). Returns {@code false}
	 * when the default login flow should continue.</p>
	 *
	 * @param httpServletRequest original servlet request
	 * @param actionRequest portlet action request
	 * @param actionResponse portlet action response
	 * @param themeDisplay current theme display
	 * @param login user login identifier (email, screen name, or ID)
	 * @param password plain-text password
	 * @param rememberMe whether remember-me is requested
	 * @param authType company authentication type ({@code ea}, {@code sn}, or
	 *        {@code id})
	 * @return {@code true} if MFA redirect was performed
	 * @throws Exception if password validation fails with {@code AuthException}
	 */
	boolean tryStartTotpChallenge(
			HttpServletRequest httpServletRequest, ActionRequest actionRequest,
			ActionResponse actionResponse, ThemeDisplay themeDisplay,
			String login, String password, boolean rememberMe, String authType)
		throws Exception;

}
