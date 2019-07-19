package ge.vakho.spring_boot_skidentity_demo.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class SkIDAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Object principal;

	public SkIDAuthenticationToken(Object principal) {
		super(null);
		this.principal = principal;
		super.setAuthenticated(true);
	}

	public SkIDAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		super.setAuthenticated(true);
	}	

	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		throw new IllegalStateException("Credentials shouldn't be retrieved for SkIDentity authentication!");
	}
}