package com.maxaramos.apiserver.dao;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository
public class UserDao {

	private Map<String, UserDetails> map = new ConcurrentHashMap<>();

	@Value("${spring.security.user.name}")
	private String username;

	@Value("${spring.security.user.password}")
	private String password;

	@Value("${spring.security.user.roles}")
	private String[] roles;

	@PostConstruct
	void init() {
		@SuppressWarnings("deprecation")
		UserBuilder userBuilder = User.withDefaultPasswordEncoder();
		map.put(username, userBuilder.username(username).password(password).roles(roles).build());
	}

	public UserDetails findByUsername(String username) {
		return map.get(username);
	}

}
