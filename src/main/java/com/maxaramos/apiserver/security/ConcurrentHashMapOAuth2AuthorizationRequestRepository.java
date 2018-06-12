package com.maxaramos.apiserver.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public final class ConcurrentHashMapOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	private static final String STATE_ATTR_NAME = "state";
	private Map<String, OAuth2AuthorizationRequest> map = new ConcurrentHashMap<>();

	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		String state = request.getParameter(STATE_ATTR_NAME);
		return map.get(state);
	}

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");

		if (authorizationRequest == null) {
			removeAuthorizationRequest(request);
			return;
		}

		map.putIfAbsent(authorizationRequest.getState(), authorizationRequest);
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);

		if (authorizationRequest != null) {
			String state = request.getParameter(STATE_ATTR_NAME);
			map.remove(state);
		}

		return authorizationRequest;
	}
}
