package com.monapp.totp.configuration;

import aQute.bnd.annotation.metatype.Meta;

import com.liferay.portal.configuration.metatype.annotations.ExtendedObjectClassDefinition;
import com.liferay.portal.kernel.model.role.RoleConstants;

/**
 * System-scoped configuration for TOTP enforcement.
 *
 * @author monapp
 */
@ExtendedObjectClassDefinition(
	category = "security",
	scope = ExtendedObjectClassDefinition.Scope.SYSTEM
)
@Meta.OCD(
	id = "com.monapp.totp.configuration.TotpConfiguration",
	localization = "content/Language",
	name = "totp-configuration-name"
)
public interface TotpConfiguration {

	/**
	 * Regular role name whose members must use TOTP (for example
	 * {@code Administrator}).
	 */
	@Meta.AD(
		deflt = RoleConstants.ADMINISTRATOR,
		description = "totp-configuration-required-role-description",
		name = "totp-configuration-required-role-name",
		required = false
	)
	public String requiredRoleName();

}
