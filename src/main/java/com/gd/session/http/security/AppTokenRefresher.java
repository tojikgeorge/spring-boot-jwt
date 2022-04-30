package com.gd.session.http.security;

import javax.servlet.http.HttpServletRequest;

public interface AppTokenRefresher
{
    String[] attainNewToken(final HttpServletRequest refreshToken) throws IllegalAccessException;
}
