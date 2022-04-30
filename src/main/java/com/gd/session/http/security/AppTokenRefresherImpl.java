package com.gd.session.http.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.web.context.annotation.RequestScope;

import javax.servlet.http.HttpServletRequest;

import static java.util.Arrays.stream;

/**
 *  This class using for handling refresh token and then generate new refresh and access token if its valid one.
 *  From the refresh token taking userid and then checking the userid with database and collecting corresponding roles. *
 *
 */
@Service @RequestScope @Slf4j
public class AppTokenRefresherImpl implements AppTokenRefresher
{
    public static final String BEARER_ = "Bearer ";
    public static final String AUTHORIZATION = "Authorization";

    @Autowired
    AppUserDetails appUserDetails;

    /**
     * This method accepting serverlet request and then returning access and refresh token as array after validating
     * existing refresh token.
     *
     * If refresh token is missing, will throw {@link IllegalAccessException}.
     *
     * @param request
     * @return
     * @throws IllegalAccessException
     */
    @Override
    public String[] attainNewToken(HttpServletRequest request) throws IllegalAccessException
    {
        String refreshToken = request.getHeader(AUTHORIZATION);
        log.info("Collecting information from refresh token.");
        if(refreshToken != null && refreshToken.startsWith(BEARER_))
        {
            try
            {
                String token = refreshToken.substring(BEARER_.length());
                JwtTokenHelper jwtTokenHelper = JwtTokenHelper.getInstance();
                String userid = jwtTokenHelper.getUserid(token);
                log.info("Creating new tokens for user : {}",userid);
                //Collecting user roles from database.
                User userDetails = (User) appUserDetails.loadUserByUsername(userid);
                String []tokens ={"",""};
                tokens[0] = jwtTokenHelper.getAccessToken(userDetails.getUsername(),userDetails.getAuthorities(),request.getRequestURL().toString());
                tokens[1] = jwtTokenHelper.getRefreshToken(userDetails.getUsername(),request.getRequestURL().toString());
                return tokens;
            }
            catch(Exception e)
            {
                log.error("Error when validating refresh token {} ",e.getMessage());
                throw e;
            }
        }
        else
        {
            log.error("Refresh token is missing !");
            throw new IllegalAccessException("Refresh token is missing !");
        }
    }
}
