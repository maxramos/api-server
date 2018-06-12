package com.maxaramos.apiserver.model.security;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import org.springframework.security.core.userdetails.UserDetails;

public class AuthToken {

	private String tokenId;
	private UserDetails user;
	private Instant expiry;

	public AuthToken() {
		super();
	}

	public AuthToken(String tokenId, UserDetails user, Instant expiry) {
		this.tokenId = tokenId;
		this.user = user;
		this.expiry = expiry;
	}

	public static Instant calculateExpiry(int timeout) {
		return LocalDateTime.now(ZoneOffset.UTC).plus(timeout, ChronoUnit.MINUTES).toInstant(ZoneOffset.UTC);
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public UserDetails getUser() {
		return user;
	}

	public void setUser(UserDetails user) {
		this.user = user;
	}

	public Instant getExpiry() {
		return expiry;
	}

	public void setExpiry(Instant expiry) {
		this.expiry = expiry;
	}

}
