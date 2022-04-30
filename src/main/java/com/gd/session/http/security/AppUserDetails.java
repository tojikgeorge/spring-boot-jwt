package com.gd.session.http.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.annotation.RequestScope;

/**
 * This service class using for collecting user credentials from database and after compare the credentials
 * adding user and roles into Spring class User.
 *
 * In the same class can implement Repository interface for taking credentials from database.
 *
 * Here implementing {@link UserDetailsService} and overriding loadUserByUsername and this method will execute by
 * spring {@link org.springframework.security.authentication.AuthenticationManager}.
 */
@Service @RequestScope @Slf4j
public class AppUserDetails implements UserDetailsService 
{

	@Autowired
	PasswordEncoder encoder;
	/**
	 * Method overided from spring
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException 
	{
		//Dummy user creation instead of database call
		AppUser user = prepareUser();
		if(null == user.getUserName())
		{
			log.error("User does not exists");
			throw new UsernameNotFoundException(username);
		}
		
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getUserRoles().forEach( role -> {
			authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
		});
		
		return 	new User(user.getUserName(),user.getPassword(),authorities);
	}

	// This is a sample method for creating dummy userid and roles. Here can implement real code for accessing
	// details from database.
	private AppUser prepareUser()
	{
		AppUser user = new AppUser();
		user.setName("Test");
		user.setUserName("test");
		user.setPassword(encoder.encode("test123"));
		
		List<AppRole> roleList = new ArrayList<>();
		AppRole role = new AppRole();
		role.setRoleName("VIEW");
		roleList.add(role);
		
		role = new AppRole();
		role.setRoleName("EDIT");
		roleList.add(role);
		
		user.setUserRoles(roleList);
		return user;
	}

}
