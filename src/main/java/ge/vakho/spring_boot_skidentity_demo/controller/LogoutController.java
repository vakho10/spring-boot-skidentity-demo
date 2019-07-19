package ge.vakho.spring_boot_skidentity_demo.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import de.skidentity.cc.saml.auth.SAMLHelper;

@Controller
public class LogoutController {

	@GetMapping("/logout")
	public String action(HttpServletRequest request) {
		SAMLHelper.sessionCleaner(request.getSession(false)); // Clear session
		
		// Clear authentication
		SecurityContext context = SecurityContextHolder.getContext();
		context.setAuthentication(null);

		SecurityContextHolder.clearContext(); // Clear context
		return "redirect:/";
	}

}