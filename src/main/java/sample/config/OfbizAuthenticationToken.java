package sample.config;

import java.util.Arrays;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class OfbizAuthenticationToken extends AbstractAuthenticationToken {

	private String name;

	public OfbizAuthenticationToken(String name) {
		super(Arrays.asList(new SimpleGrantedAuthority("hello")));
		this.name = name;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return name;
	}

}
