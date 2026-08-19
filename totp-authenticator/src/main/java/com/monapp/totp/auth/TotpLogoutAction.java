package com.monapp.totp.auth;

import com.liferay.portal.kernel.events.ActionException;
import com.liferay.portal.kernel.events.LifecycleAction;
import com.liferay.portal.kernel.events.LifecycleEvent;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.PropsKeys;
import com.monapp.totp.util.TotpPendingLoginUtil;
import com.monapp.totp.util.TotpSessionUtil;

import javax.servlet.http.HttpServletRequest;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * Pre-logout lifecycle hook that clears TOTP session state and pending MFA
 * login data.
 *
 * @author monapp
 */
@Component(
	immediate = true,
	property = {
		"key=" + PropsKeys.LOGOUT_EVENTS_PRE
	},
	service = LifecycleAction.class
)
public class TotpLogoutAction implements LifecycleAction {

	@Override
	public void processLifecycleEvent(LifecycleEvent lifecycleEvent)
		throws ActionException {

		HttpServletRequest request = lifecycleEvent.getRequest();

		TotpSessionUtil.clearTotpVerified(request, _portal);
		TotpPendingLoginUtil.clearPendingLogin(request, _portal);
	}

	@Reference
	private Portal _portal;

}
