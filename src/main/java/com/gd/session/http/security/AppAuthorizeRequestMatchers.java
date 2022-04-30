package com.gd.session.http.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

/**
 * This helper class using for adding url permission to HttpSecurity.
 * Method calling from AppSecurityConfig.
 */
@Component
public class AppAuthorizeRequestMatchers 
{

	public static final String SESSION_LOGIN = "/session/login/**";
	public static final String SESSION_REFRESH = "/session/refresh/**";
	public static final String SESSION_ADD = "/session/add/**";
	public static final String SESSION_GET = "/session/get/**";
	public static final String EDIT = "EDIT";
	public static final String VIEW = "VIEW";

	/**
	 * Method for adding each matchers with url and role.
	 * If you need to add new url or role that need to add here.
	 *
	 * @param http
	 * @return
	 * @throws Exception
	 */
	protected HttpSecurity addPermissionsToUrls(HttpSecurity http) throws Exception
	{
		http.authorizeRequests().antMatchers(SESSION_LOGIN,SESSION_REFRESH).permitAll();
		http.authorizeRequests().antMatchers(SESSION_ADD).hasAnyAuthority(EDIT);
		http.authorizeRequests().antMatchers(SESSION_GET).hasAnyAuthority(EDIT, VIEW);
		http.authorizeRequests().anyRequest().authenticated();
		return http;
	}
}
