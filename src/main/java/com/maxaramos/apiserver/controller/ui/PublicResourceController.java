package com.maxaramos.apiserver.controller.ui;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/public")
public class PublicResourceController {

	@GetMapping("token")
	public String token(HttpServletRequest request, Model model) {
		try {
			model.addAttribute("token", URLEncoder.encode(request.getParameter("token"), StandardCharsets.UTF_8.toString()));
			return "token";
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

}
