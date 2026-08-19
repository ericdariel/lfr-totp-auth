package com.monapp.totp.service;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.model.User;

/**
 * Determines whether a user must configure and verify TOTP based on system
 * configuration.
 *
 * @author monapp
 */
public interface TotpRoleChecker {

	/**
	 * Returns the configured regular role name (never {@code null} or blank).
	 */
	public String getRequiredRoleName();

	/**
	 * Returns {@code true} when the user belongs to the configured role.
	 *
	 * @param user user to inspect
	 */
	public boolean requiresTotp(User user) throws PortalException;

	/**
	 * Returns {@code true} when the user belongs to the configured role.
	 *
	 * @param userId user primary key
	 */
	public boolean requiresTotp(long userId) throws PortalException;

}
