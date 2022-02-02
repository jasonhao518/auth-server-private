package sample.config;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * TODO
 * This class is mostly a straight copy from {@code org.springframework.security.oauth2.server.authorization.authentication.JwtUtils}.
 * It should be consolidated when we introduce a token generator abstraction.
 *
 * Utility methods used by the {@link AuthenticationProvider}'s when issuing {@link Jwt}'s.
 *
 * @author Ovidiu Popa
 * @since 0.2.1
 */
final class JwtUtils {

	private JwtUtils() {
	}

	static JoseHeader.Builder headers() {
		return JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);
	}

	static JwtClaimsSet.Builder accessTokenClaims(RegisteredClient registeredClient,
			String issuer, String subject, Set<String> authorizedScopes) {

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
		if (StringUtils.hasText(issuer)) {
			claimsBuilder.issuer(issuer);
		}
		claimsBuilder
				.subject(subject)
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.notBefore(issuedAt);
		if (!CollectionUtils.isEmpty(authorizedScopes)) {
			claimsBuilder.claim(OAuth2ParameterNames.SCOPE, authorizedScopes);
		}
		// @formatter:on

		return claimsBuilder;
	}
	
	static JwtClaimsSet.Builder idTokenClaims(RegisteredClient registeredClient,
			String issuer, String subject, String nonce) {

		Instant issuedAt = Instant.now();
		// TODO Allow configuration for ID Token time-to-live
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);

		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
		if (StringUtils.hasText(issuer)) {
			claimsBuilder.issuer(issuer);
		}
		claimsBuilder
				.subject(subject)
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.claim(IdTokenClaimNames.AZP, registeredClient.getClientId());
		if (StringUtils.hasText(nonce)) {
			claimsBuilder.claim(IdTokenClaimNames.NONCE, nonce);
		}
		// TODO Add 'auth_time' claim
		// @formatter:on

		return claimsBuilder;
	}

}
