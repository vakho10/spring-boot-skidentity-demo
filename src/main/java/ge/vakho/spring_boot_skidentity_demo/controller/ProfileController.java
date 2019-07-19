package ge.vakho.spring_boot_skidentity_demo.controller;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import ge.vakho.spring_boot_skidentity_demo.authentication.SkIDDetails;

@Controller
public class ProfileController {

	@GetMapping("/profile")
	public String index(Authentication authentication, Model model) throws IOException {
		SkIDDetails skidDetails = (SkIDDetails) authentication.getPrincipal();
		model.addAttribute("user", skidDetails);
		return "profile";
	}


}