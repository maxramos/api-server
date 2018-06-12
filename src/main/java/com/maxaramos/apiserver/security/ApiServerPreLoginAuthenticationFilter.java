package com.maxaramos.apiserver.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class ApiServerPreLoginAuthenticationFilter extends OncePerRequestFilter {

	public static final String DEFAULT_LOGIN_REQUEST_BASE_URI = "/login/oauth2/code";
	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
	private static final String STATE_ATTR_NAME = "state";
	private final AntPathRequestMatcher loginRequestMatcher;
	private final ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	public ApiServerPreLoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		loginRequestMatcher = new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_BASE_URI + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (isLoginRequest(request, response)) {
			processPreLogin(request, response);
		}

		filterChain.doFilter(request, response);
	}

	private boolean isLoginRequest(HttpServletRequest request, HttpServletResponse response) {
		return loginRequestMatcher.matches(request);
	}

	private void processPreLogin(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String registrationId = loginRequestMatcher.extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
		ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);

		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
		}

		String redirectUriStr = expandRedirectUri(request, clientRegistration);
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
		String state = request.getParameter(STATE_ATTR_NAME);

		OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.authorizationCode();
		OAuth2AuthorizationRequest authorizationRequest = builder
				.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(state)
				.additionalParameters(additionalParameters)
				.build();

		authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
	}

	private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		int port = request.getServerPort();

		if ("http".equals(request.getScheme()) && port == 80 || "https".equals(request.getScheme()) && port == 443) {
			port = -1;		// Removes the port in UriComponentsBuilder
		}

		String baseUrl = UriComponentsBuilder.newInstance()
			.scheme(request.getScheme())
			.host(request.getServerName())
			.port(port)
			.path(request.getContextPath())
			.build()
			.toUriString();

		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("baseUrl", baseUrl);
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
			.buildAndExpand(uriVariables)
			.toUriString();
	}

}
