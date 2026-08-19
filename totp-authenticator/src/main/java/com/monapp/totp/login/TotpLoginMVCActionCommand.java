package com.monapp.totp.login;

import com.liferay.login.web.constants.LoginPortletKeys;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.portlet.PortletPreferencesFactoryUtil;
import com.liferay.portal.kernel.portlet.bridges.mvc.BaseMVCActionCommand;
import com.liferay.portal.kernel.portlet.bridges.mvc.MVCActionCommand;
import com.liferay.portal.kernel.theme.ThemeDisplay;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.WebKeys;
import com.monapp.totp.service.TotpTwoFactorLoginService;

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.portlet.PortletPreferences;
import javax.servlet.http.HttpServletRequest;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * MVC action command registered with higher ranking than the default login
 * command to intercept administrator MFA logins.
 *
 * <p>When MFA does not apply, delegates to the LNE custom login command.</p>
 *
 * @author monapp
 */
@Component(
	immediate = true,
	property = {
		"javax.portlet.name=" + LoginPortletKeys.CREATE_ACCOUNT,
		"javax.portlet.name=" + LoginPortletKeys.FAST_LOGIN,
		"javax.portlet.name=" + LoginPortletKeys.FORGOT_PASSWORD,
		"javax.portlet.name=" + LoginPortletKeys.LOGIN,
		"mvc.command.name=/login/login",
		"service.ranking:Integer=400"
	},
	service = MVCActionCommand.class
)
public class TotpLoginMVCActionCommand extends BaseMVCActionCommand {

	@Override
	protected void doProcessAction(
			ActionRequest actionRequest, ActionResponse actionResponse)
		throws Exception {

		ThemeDisplay themeDisplay = (ThemeDisplay)actionRequest.getAttribute(
			WebKeys.THEME_DISPLAY);

		if (!themeDisplay.isSignedIn()) {
			HttpServletRequest httpServletRequest =
				_portal.getOriginalServletRequest(
					_portal.getHttpServletRequest(actionRequest));

			String login = ParamUtil.getString(actionRequest, "login");
			String password = actionRequest.getActionParameters().getValue(
				"password");
			boolean rememberMe = ParamUtil.getBoolean(
				actionRequest, "rememberMe");

			PortletPreferences portletPreferences =
				PortletPreferencesFactoryUtil.getStrictPortletSetup(
					themeDisplay.getLayout(),
					_portal.getPortletId(actionRequest));

			String authType = portletPreferences.getValue("authType", null);

			if (_totpTwoFactorLoginService.tryStartTotpChallenge(
					httpServletRequest, actionRequest, actionResponse,
					themeDisplay, login, password, rememberMe, authType)) {

				if (_log.isInfoEnabled()) {
					_log.info("MFA démarré pour " + login);
				}

				return;
			}
		}

		_loginMVCActionCommand.processAction(actionRequest, actionResponse);
	}

	private static final Log _log = LogFactoryUtil.getLog(
		TotpLoginMVCActionCommand.class);

	@Reference(
		target = "(component.name=lne.hook.liferay.LneCustomLoginMVCActionCommand)"
	)
	private MVCActionCommand _loginMVCActionCommand;

	@Reference
	private TotpTwoFactorLoginService _totpTwoFactorLoginService;

	@Reference
	private Portal _portal;

}
