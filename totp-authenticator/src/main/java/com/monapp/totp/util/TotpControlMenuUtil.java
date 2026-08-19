package com.monapp.totp.util;

import com.liferay.portal.kernel.theme.ThemeDisplay;
import com.liferay.portal.kernel.util.WebKeys;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Hides the Liferay control menu (administration toolbar) on TOTP pages.
 *
 * @author monapp
 */
public class TotpControlMenuUtil {

	public static final String HIDE_CONTROL_MENU =
		"com.monapp.totp.HIDE_CONTROL_MENU";

	private TotpControlMenuUtil() {
	}

	/**
	 * Wraps the request so {@link ThemeDisplay#isShowControlMenu()} is disabled
	 * when TOTP pages are rendered.
	 *
	 * @param request original servlet request
	 * @return wrapped request for TOTP setup/verify rendering
	 */
	public static HttpServletRequest wrapToHideControlMenu(
		HttpServletRequest request) {

		request.setAttribute(HIDE_CONTROL_MENU, Boolean.TRUE);

		return new HttpServletRequestWrapper(request) {

			@Override
			public Object getAttribute(String name) {
				Object value = super.getAttribute(name);

				if (WebKeys.THEME_DISPLAY.equals(name) &&
					(value instanceof ThemeDisplay)) {

					ThemeDisplay themeDisplay = (ThemeDisplay)value;

					themeDisplay.setShowControlMenu(false);
				}

				return value;
			}
		};
	}

}
