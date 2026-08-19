package com.monapp.totp.fragments.contributor;

import com.liferay.fragment.contributor.BaseFragmentCollectionContributor;
import com.liferay.fragment.contributor.FragmentCollectionContributor;

import javax.servlet.ServletContext;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * Registers the {@code totp} fragment collection containing setup and verify
 * page fragments.
 *
 * @author monapp
 */
@Component(
	property = "fragment.collection.key=totp",
	service = FragmentCollectionContributor.class
)
public class TOTPFragmentCollectionContributor
	extends BaseFragmentCollectionContributor {

	@Override
	public String getFragmentCollectionKey() {
		return "totp";
	}

	@Override
	public ServletContext getServletContext() {
		return _servletContext;
	}

	@Reference(
		target = "(osgi.web.symbolicname=com.monapp.totp.fragments)"
	)
	private ServletContext _servletContext;

}
