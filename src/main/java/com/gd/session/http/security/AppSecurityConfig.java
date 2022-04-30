package com.gd.session.http.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.RequiredArgsConstructor;

@Configuration @EnableWebSecurity @RequiredArgsConstructor
public class AppSecurityConfig extends WebSecurityConfigurerAdapter
{

	//This path need to change accordingly to application path.
	public static final String SESSION_LOGIN = "/session/login";

	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	AppAuthorizeRequestMatchers appAuthorizeRequestMatchers;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception 
	{
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception 
	{
		AppAuthenticationFilter appAuthenticationFilter = new AppAuthenticationFilter(authenticationManager());
		appAuthenticationFilter.setFilterProcessesUrl(SESSION_LOGIN);
		
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		appAuthorizeRequestMatchers.addPermissionsToUrls(http);
		http.addFilter(appAuthenticationFilter);
		http.addFilterBefore(new AppAuthorizationFilter(), AppAuthenticationFilter.class);
		
	}
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
 
}
