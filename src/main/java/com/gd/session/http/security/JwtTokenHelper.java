package com.gd.session.http.security;

import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

/**
 * This helper class for handling all JWT token related process.
 */
@Slf4j
public class JwtTokenHelper 
{
	private static final String secretKey = "HkotYi_74j3#";
	public static final String ROLES = "roles";
	Algorithm algorithm;
	private static final int accessTimeOut = 10*60*50;
	private static final int refreshTimeOut = 30*60*1000;
	
	private JwtTokenHelper()
	{
		algorithm = Algorithm.HMAC256(secretKey.getBytes());
	}
	
	public static JwtTokenHelper getInstance()
	{
		return new JwtTokenHelper();
	}

	public String getAccessToken(final String userid, final Collection<GrantedAuthority> grantedAuthority, final String requestUrl)
	{
		log.info("Token creating with userid {}",userid);
		return JWT.create()
    			.withSubject(userid)
    			.withExpiresAt(new Date(System.currentTimeMillis() + accessTimeOut))
    			.withIssuer(requestUrl)
    			.withClaim(ROLES, grantedAuthority.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
    			.sign(algorithm);   	
	}
	
	public String getRefreshToken(final String userid, final String requestUrl)
	{
		log.info("Access token creating with userid {}",userid);
		return JWT.create()
    			.withSubject(userid)
    			.withExpiresAt(new Date(System.currentTimeMillis() + refreshTimeOut))
    			.withIssuer(requestUrl)
    			.sign(algorithm);
	}

	public String[] getRoles(final String token)
	{
		log.info("Collecting roles from token");
		return getDecodedJWT(token).getClaim(ROLES).asArray(String.class);
	}

	public String getUserid(final String token)
	{
		log.info("Collecting userid from token");
		return getDecodedJWT(token).getSubject();
	}

	private DecodedJWT getDecodedJWT(final String token)
	{
		JWTVerifier jwtVerifier = JWT.require(algorithm).build();
		return jwtVerifier.verify(token);
	}
}
