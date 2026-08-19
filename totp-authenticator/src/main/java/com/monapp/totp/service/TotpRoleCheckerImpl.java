package com.monapp.totp.service;

import com.liferay.portal.kernel.exception.NoSuchRoleException;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.Role;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.model.role.RoleConstants;
import com.liferay.portal.configuration.metatype.bnd.util.ConfigurableUtil;
import com.liferay.portal.kernel.service.RoleLocalService;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.util.Validator;
import com.monapp.totp.configuration.TotpConfiguration;

import java.util.Map;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;

/**
 * Default {@link TotpRoleChecker} backed by {@link TotpConfiguration}.
 *
 * @author monapp
 */
@Component(
	configurationPid = "com.monapp.totp.configuration.TotpConfiguration",
	immediate = true,
	service = TotpRoleChecker.class
)
public class TotpRoleCheckerImpl implements TotpRoleChecker {

	@Activate
	@Modified
	protected void activate(Map<String, Object> properties) {
		_configuration = ConfigurableUtil.createConfigurable(
			TotpConfiguration.class, properties);
	}

	@Override
	public String getRequiredRoleName() {
		String roleName = _configuration.requiredRoleName();

		if (Validator.isNull(roleName)) {
			return RoleConstants.ADMINISTRATOR;
		}

		return roleName.trim();
	}

	@Override
	public boolean requiresTotp(User user) throws PortalException {
		if ((user == null) || user.isGuestUser()) {
			return false;
		}

		return requiresTotp(user.getUserId());
	}

	@Override
	public boolean requiresTotp(long userId) throws PortalException {
		if (userId <= 0) {
			return false;
		}

		User user = _userLocalService.fetchUser(userId);

		if ((user == null) || user.isGuestUser()) {
			return false;
		}

		try {
			Role role = _roleLocalService.getRole(
				user.getCompanyId(), getRequiredRoleName());

			return _userLocalService.hasRoleUser(role.getRoleId(), userId);
		}
		catch (NoSuchRoleException noSuchRoleException) {
			if (_log.isWarnEnabled()) {
				_log.warn(
					"Configured TOTP role not found: " +
						getRequiredRoleName());
			}

			return false;
		}
	}

	private static final Log _log = LogFactoryUtil.getLog(
		TotpRoleCheckerImpl.class);

	private volatile TotpConfiguration _configuration;

	@Reference
	private RoleLocalService _roleLocalService;

	@Reference
	private UserLocalService _userLocalService;

}
