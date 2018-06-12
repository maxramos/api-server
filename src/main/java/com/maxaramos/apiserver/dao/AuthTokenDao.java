package com.maxaramos.apiserver.dao;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import com.maxaramos.apiserver.model.security.AuthToken;

@Repository
public class AuthTokenDao {

	private Map<String, AuthToken> map = new ConcurrentHashMap<>();

	public AuthToken generate(UserDetails user) {
		Instant expiry = Instant.now();
		AuthToken authToken = new AuthToken(Long.toString(expiry.toEpochMilli()), user, expiry);
		map.put(authToken.getTokenId(), authToken);
		return authToken;
	}

	public boolean isExpired(String tokenId) {
		return map.get(tokenId).getExpiry().isAfter(Instant.now());
	}

	public void refreshExpiry(String tokenId) {
		map.get(tokenId).setExpiry(AuthToken.calculateExpiry(30));
	}

}
