package sample.config;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.SerializationUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Client Credentials Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2ClientCredentialsAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.4">Section 4.4 Client Credentials Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.4.2">Section 4.4.2 Access Token Request</a>
 */
public final class OAuth2ClientCredentialsAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
//	private final ObjectMapper mapper;
	private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2ClientCredentialsAuthenticationProvider(OAuth2AuthorizationService authorizationService,
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

	@Deprecated
	protected void setProviderSettings(ProviderSettings providerSettings) {
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

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication =
				(OAuth2ClientCredentialsAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(clientCredentialsAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		Set<String> authorizedScopes = registeredClient.getScopes();		// Default to configured scopes
		if (!CollectionUtils.isEmpty(clientCredentialsAuthentication.getScopes())) {
			for (String requestedScope : clientCredentialsAuthentication.getScopes()) {
				if (!registeredClient.getScopes().contains(requestedScope)) {
					throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
				}
			}
			authorizedScopes = new LinkedHashSet<>(clientCredentialsAuthentication.getScopes());
		}

		String issuer = ProviderContextHolder.getProviderContext().getIssuer();

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, clientPrincipal.getName(), authorizedScopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrant(clientCredentialsAuthentication)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JoseHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), authorizedScopes);
		
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
				// Do not issue refresh token to public client
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
			refreshToken = generateRefreshToken(registeredClient.getTokenSettings().getRefreshTokenTimeToLive());
		}
		
		Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
		.principalName(clientPrincipal.getName())
		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
		.token(accessToken,
				(metadata) ->
						metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims()))
		.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);
		try {
			byte[] data = SerializationUtils.serialize(clientPrincipal);
			builder.attribute(Principal.class.getName(), Base64Utils.encodeToString(data));
		}catch(Exception e) {
			e.printStackTrace();
		}
		if(refreshToken!=null) {
			builder.refreshToken(refreshToken);
		}
		// @formatter:off
		OAuth2Authorization authorization = 
				builder.build();
		// @formatter:on
		
		

		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken,refreshToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);
		return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
	}
}