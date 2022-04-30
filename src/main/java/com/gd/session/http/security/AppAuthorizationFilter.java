package com.gd.session.http.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import static java.util.Arrays.stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

@Slf4j
public class AppAuthorizationFilter extends OncePerRequestFilter 
{

	public static final String AUTHORIZATION = "Authorization";
	public static final String BEARER_ = "Bearer ";
	public static final String ERROR = "error";
	//Below two paths need to change accordingly to application path.
	public static final String SESSION_LOGIN = "/session/login";
	public static final String SESSION_REFRESH = "/session/refresh";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
	{
		if(request.getServletPath().equals(SESSION_LOGIN) || request.getServletPath().equals(SESSION_REFRESH))
		{
			filterChain.doFilter(request, response);
		}
		else
		{
			String authorizationHeader = request.getHeader(AUTHORIZATION);
			if(authorizationHeader != null && authorizationHeader.startsWith(BEARER_))
			{
				try
				{
					String token = authorizationHeader.substring(BEARER_.length());
					JwtTokenHelper jwtTokenHelper = JwtTokenHelper.getInstance();
					String userid = jwtTokenHelper.getUserid(token);
					String [] roles =jwtTokenHelper.getRoles(token);
					Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
					stream(roles).forEach(role -> {
						authorities.add(new SimpleGrantedAuthority(role));
					});
					
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userid,null,authorities);
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					filterChain.doFilter(request, response);
				}
				catch(Exception e)
				{
					response.setHeader(ERROR,e.getMessage());
					response.setStatus(403);
					log.error("Error in authorization process : {}",e.getMessage());
				}
			}
			else
			{
				filterChain.doFilter(request, response);
			}
		}

	}

}
