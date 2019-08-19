package ge.vakho.spring_boot_skidentity_demo.authentication;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import de.skidentity.cc.saml.auth.SAMLHelper;
import de.skidentity.common.ISO3166CountryCode;
import de.skidentity.common.attributes.AttributeExtractor;

public class SkIDDetails implements UserDetails {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	
	private Set<GrantedAuthority> authorities;

	private String username;
	private String firstName;
	private String lastName;
	private X500Principal issuer;
	private ISO3166CountryCode country;

	public SkIDDetails(HttpSession session, Collection<? extends GrantedAuthority> authorities) {
		SAMLHelper helper = new SAMLHelper(session);
		AttributeExtractor extractor = helper.getAttributeExtractor();
		username = extractor.getEIdentifier();
		if (((username == null) || "".equals(username))) {
			throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
		}

		firstName = extractor.getFirstName();
		lastName = extractor.getLastName();
		country = extractor.getCountry();
		issuer = extractor.getIDIssuer();

		this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
	}

	private static SortedSet<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
		Assert.notNull(authorities, "Cannot pass a null GrantedAuthority collection");
		// Ensure array iteration order is predictable (as per
		// UserDetails.getAuthorities() contract and SEC-717)
		SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(new AuthorityComparator());

		for (GrantedAuthority grantedAuthority : authorities) {
			Assert.notNull(grantedAuthority, "GrantedAuthority list cannot contain any null elements");
			sortedAuthorities.add(grantedAuthority);
		}

		return sortedAuthorities;
	}

	private static class AuthorityComparator implements Comparator<GrantedAuthority>, Serializable {
		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		public int compare(GrantedAuthority g1, GrantedAuthority g2) {
			// Neither should ever be null as each entry is checked before adding it to
			// the set.
			// If the authority is null, it is a custom authority and should precede
			// others.
			if (g2.getAuthority() == null) {
				return -1;
			}

			if (g1.getAuthority() == null) {
				return 1;
			}

			return g1.getAuthority().compareTo(g2.getAuthority());
		}
	}
	
	public X500Principal getIssuer() {
		return issuer;
	}

	public String getFirstName() {
		return firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public ISO3166CountryCode getCountry() {
		return country;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public String getPassword() {
		return null; // No password present!
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}