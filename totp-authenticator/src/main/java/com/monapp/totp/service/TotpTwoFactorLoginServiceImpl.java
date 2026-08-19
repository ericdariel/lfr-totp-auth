package com.monapp.totp.service;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.Company;
import com.liferay.portal.kernel.model.CompanyConstants;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.security.auth.Authenticator;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.theme.ThemeDisplay;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.monapp.totp.util.TotpPaths;
import com.monapp.totp.util.TotpPendingLoginUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * Default implementation of {@link TotpTwoFactorLoginService}.
 *
 * @author monapp
 * @see TotpTwoFactorLoginService
 */
@Component(immediate = true, service = TotpTwoFactorLoginService.class)
public class TotpTwoFactorLoginServiceImpl
	implements TotpTwoFactorLoginService {

	@Override
	public boolean tryStartTotpChallenge(
			HttpServletRequest httpServletRequest, ActionRequest actionRequest,
			ActionResponse actionResponse, ThemeDisplay themeDisplay,
			String login, String password, boolean rememberMe, String authType)
		throws Exception {

		if (Validator.isNull(login) || Validator.isNull(password)) {
			return false;
		}

		Company company = themeDisplay.getCompany();

		if (Validator.isNull(authType)) {
			authType = company.getAuthType();
		}

		User user = _resolveUser(company.getCompanyId(), login, authType);

		if (!_requiresTotpChallenge(user.getUserId())) {
			if (_log.isDebugEnabled()) {
				_log.debug(
					"Pas de MFA pour " + user.getEmailAddress());
			}

			return false;
		}

		if (!_isPasswordValid(
				company.getCompanyId(), login, password, authType)) {

			throw new com.liferay.portal.kernel.security.auth.AuthException();
		}

		String redirect = ParamUtil.getString(actionRequest, "redirect");

		String challenge = TotpPendingLoginUtil.storePendingLogin(
			httpServletRequest, _portal, user.getUserId(), login, password,
			rememberMe, authType, redirect);

		boolean setupRequired = Validator.isNull(
			_totpService.getTotpSecret(user));

		if (_log.isInfoEnabled()) {
			_log.info(
				"Étape 1 validée, MFA requis pour " +
					user.getEmailAddress() + " (session non créée, " +
					(setupRequired ? "setup" : "verify") + ")");
		}

		String targetPage = setupRequired ?
			TotpPaths.SETUP_PAGE : TotpPaths.VERIFY_PAGE;

		String verifyUrl =
			_portal.getPortalURL(httpServletRequest) + targetPage +
				"?" + TotpPendingLoginUtil.CHALLENGE_PARAM + "=" + challenge;

		HttpServletResponse httpServletResponse =
			_portal.getHttpServletResponse(actionResponse);

		httpServletResponse.sendRedirect(verifyUrl);

		return true;
	}

	/**
	 * Returns {@code true} when the user belongs to the configured MFA role.
	 */
	private boolean _requiresTotpChallenge(long userId)
		throws PortalException {

		return _totpRoleChecker.requiresTotp(userId);
	}

	private boolean _isPasswordValid(
			long companyId, String login, String password, String authType)
		throws PortalException {

		Map<String, String[]> headerMap = Collections.emptyMap();
		Map<String, String[]> parameterMap = Collections.emptyMap();
		Map<String, Object> results = new HashMap<>();

		int authResult;

		if (CompanyConstants.AUTH_TYPE_EA.equals(authType)) {
			authResult = _userLocalService.authenticateByEmailAddress(
				companyId, login, password, headerMap, parameterMap, results);
		}
		else if (CompanyConstants.AUTH_TYPE_SN.equals(authType)) {
			authResult = _userLocalService.authenticateByScreenName(
				companyId, login, password, headerMap, parameterMap, results);
		}
		else {
			authResult = _userLocalService.authenticateByUserId(
				companyId, GetterUtil.getLong(login), password, headerMap,
				parameterMap, results);
		}

		return authResult == Authenticator.SUCCESS;
	}

	private User _resolveUser(long companyId, String login, String authType)
		throws PortalException {

		if (CompanyConstants.AUTH_TYPE_EA.equals(authType)) {
			return _userLocalService.getUserByEmailAddress(companyId, login);
		}

		if (CompanyConstants.AUTH_TYPE_SN.equals(authType)) {
			return _userLocalService.getUserByScreenName(companyId, login);
		}

		return _userLocalService.getUser(GetterUtil.getLong(login));
	}

	private static final Log _log = LogFactoryUtil.getLog(
		TotpTwoFactorLoginServiceImpl.class);

	@Reference
	private Portal _portal;

	@Reference
	private TOTPService _totpService;

	@Reference
	private TotpRoleChecker _totpRoleChecker;

	@Reference
	private UserLocalService _userLocalService;

}
