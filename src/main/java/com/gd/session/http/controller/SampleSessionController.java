package com.gd.session.http.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.gd.session.http.security.AppTokenRefresher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/session/")
public class SampleSessionController 
{

	public static final String REFRESH_TOKEN = "refresh_token";
	@Autowired
	AppTokenRefresher appTokenRefresher;

	@PostMapping("/login")
	public String login(HttpServletRequest request)
	{
		HttpSession session = request.getSession();
		session.setAttribute("log","Logged ! \n");
		return "OK";
	}
	
	@PostMapping("/add")
	public void addData(HttpServletRequest request, @RequestParam String data)
	{
		HttpSession session = request.getSession();
		if (null == session.getAttribute("data"))
		{
			session.setAttribute("data",request.getParameter("data")+"\n");
		}
		else
		{
			session.setAttribute("data",session.getAttribute("data") +"  "+request.getParameter("data")+"\n");
		}
	}
	
	@GetMapping("/get")
	public String  getData(HttpServletRequest request)
	{
		HttpSession session = request.getSession();
		return session.getAttribute("log") +"  "+session.getAttribute("data");
	}
	
	@GetMapping("/logout")
	public void  logout(HttpServletRequest request)
	{
		HttpSession session = request.getSession();
		session.invalidate();
	}

	@GetMapping("/refresh")
	public void  refresh(HttpServletRequest request, HttpServletResponse response) throws IllegalAccessException
	{
			String[] tokens = appTokenRefresher.attainNewToken(request);
			response.setHeader("access_token", tokens[0]);
			response.setHeader("refresh_token",tokens[1]);
	}
}
