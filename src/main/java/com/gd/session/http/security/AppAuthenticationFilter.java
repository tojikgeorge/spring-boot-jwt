package com.gd.session.http.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
public class AppAuthenticationFilter extends UsernamePasswordAuthenticationFilter 
{
	public static final String USERNAME = "username";
	public static final String PASSWORD = "password";
	public static final String ACCESS_TOKEN = "access_token";
	public static final String REFRESH_TOKEN = "refresh_token";
	private final AuthenticationManager authenticationManager;

	public AppAuthenticationFilter(AuthenticationManager authenticationManager) 
	{
		this.authenticationManager = authenticationManager;
	}
    
	@Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException 
	{
    	String username = request.getParameter(USERNAME);
    	String password = request.getParameter(PASSWORD);
		log.info("Login with username : {}",username);
    	UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
    	return authenticationManager.authenticate(authenticationToken);
    }
    
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
    		Authentication authResult) throws IOException, ServletException 
    {
    	User userDetails = (User) authResult.getPrincipal();
		log.info("Creating tokens for user  {}",userDetails.getUsername());
    	String access_token = JwtTokenHelper.getInstance().getAccessToken(userDetails.getUsername(), userDetails.getAuthorities(), request.getRequestURL().toString());
    	String refresh_token=JwtTokenHelper.getInstance().getRefreshToken(userDetails.getUsername(), request.getRequestURL().toString());
    	response.setHeader(ACCESS_TOKEN, access_token);
    	response.setHeader(REFRESH_TOKEN, refresh_token);
		log.info("Tokens added to response for user {}",userDetails.getUsername());
    	chain.doFilter(request, response);
    }
    
}
