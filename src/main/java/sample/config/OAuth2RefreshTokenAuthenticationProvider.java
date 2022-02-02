package sample.config;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.SerializationUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @since 0.0.3
 * @see OAuth2RefreshTokenAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.5">Section 1.5 Refresh Token Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6 Refreshing an Access Token</a>
 */
public final class OAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
//	private final ObjectMapper mapper;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;

	/**
	 * Constructs an {@code OAuth2RefreshTokenAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2RefreshTokenAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			JwtEncoder jwtEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
//		this.mapper = new ObjectMapper();
//		mapper.registerModule(new JavaTimeModule());
	}

	/**
	 * Sets the {@link OAuth2TokenCustomizer} that customizes the
	 * {@link JwtEncodingContext.Builder#headers(Consumer) headers} and/or
	 * {@link JwtEncodingContext.Builder#claims(Consumer) claims} for the generated {@link Jwt}.
	 *
	 * @param jwtCustomizer the {@link OAuth2TokenCustomizer} that customizes the headers and/or claims for the generated {@code Jwt}
	 */
	public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	/**
	 * Sets the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}.
	 *
	 * @param refreshTokenGenerator the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}
	 */
	public void setRefreshTokenGenerator(Supplier<String> refreshTokenGenerator) {
		Assert.notNull(refreshTokenGenerator, "refreshTokenGenerator cannot be null");
		this.refreshTokenGenerator = refreshTokenGenerator;
	}

	@Deprecated
	protected void setProviderSettings(ProviderSettings providerSettings) {
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
				(OAuth2RefreshTokenAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (!refreshToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked [...].
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// As per https://tools.ietf.org/html/rfc6749#section-6
		// The requested scope MUST NOT include any scope not originally granted by the resource owner,
		// and if omitted is treated as equal to the scope originally granted by the resource owner.
		Set<String> scopes = refreshTokenAuthentication.getScopes();
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);
		if (!authorizedScopes.containsAll(scopes)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}
		if (scopes.isEmpty()) {
			scopes = authorizedScopes;
		}

		String issuer = ProviderContextHolder.getProviderContext().getIssuer();

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, authorization.getPrincipalName(), scopes);

		OfbizAuthenticationToken principal = null;
		try {
			String data = authorization.getAttribute(Principal.class.getName());
			principal = (OfbizAuthenticationToken) SerializationUtils.deserialize(Base64Utils.decodeFromString(data));

		}catch(Exception e) {
			e.printStackTrace();
		}
		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(principal)
				.authorization(authorization)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(refreshTokenAuthentication)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JoseHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().subject((String) principal.getPrincipal()).build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), scopes);

		TokenSettings tokenSettings = registeredClient.getTokenSettings();

		OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
		if (!tokenSettings.isReuseRefreshTokens()) {
			currentRefreshToken = generateRefreshToken(tokenSettings.getRefreshTokenTimeToLive());
		}

		Jwt jwtIdToken = null;
		if (authorizedScopes.contains(OidcScopes.OPENID)) {
			headersBuilder = JwtUtils.headers();
			claimsBuilder = JwtUtils.idTokenClaims(
					registeredClient, issuer, authorization.getPrincipalName(), null);

			// @formatter:off
			context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
					.registeredClient(registeredClient)
					.principal(principal)
					.authorization(authorization)
					.authorizedScopes(authorizedScopes)
					.tokenType(ID_TOKEN_TOKEN_TYPE)
					.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
					.authorizationGrant(refreshTokenAuthentication)
					.build();
			// @formatter:on

			this.jwtCustomizer.customize(context);

			headers = context.getHeaders().build();
			claims = context.getClaims().build();
			jwtIdToken = this.jwtEncoder.encode(headers, claims);
		}

		OidcIdToken idToken;
		if (jwtIdToken != null) {
			idToken = new OidcIdToken(jwtIdToken.getTokenValue(), jwtIdToken.getIssuedAt(),
					jwtIdToken.getExpiresAt(), jwtIdToken.getClaims());
		} else {
			idToken = null;
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(accessToken,
						(metadata) -> {
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims());
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
						})
				.refreshToken(currentRefreshToken);
		if (idToken != null) {
			authorizationBuilder
					.token(idToken,
							(metadata) ->
									metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		authorization = authorizationBuilder.build();
		// @formatter:on

		this.authorizationService.save(authorization);

		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (idToken != null) {
			additionalParameters = new HashMap<>();
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);
		return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
	}
	
	static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}
}
