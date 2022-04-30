package com.gd.session.http.security;

import java.util.ArrayList;
import java.util.Collection;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @AllArgsConstructor @NoArgsConstructor
public class AppUser 
{
	private String name;
	private String userName;
	private String password;
	private Collection<AppRole> userRoles = new ArrayList<>();

}
