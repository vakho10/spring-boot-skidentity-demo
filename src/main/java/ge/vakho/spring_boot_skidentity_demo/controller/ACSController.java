package ge.vakho.spring_boot_skidentity_demo.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import de.skidentity.cc.saml.auth.LoginStatus;
import de.skidentity.cc.saml.config.SkIDentityConfig;
import de.skidentity.cc.saml.error.ErrorHandlerApplier;
import de.skidentity.cc.saml.error.SamlResponseException;
import de.skidentity.cc.saml.response.AttributeConverter;
import de.skidentity.cc.saml.response.NameIdExtractor;
import de.skidentity.cc.saml.response.SAMLResponseManager;
import ge.vakho.spring_boot_skidentity_demo.authentication.SkIDAuthenticationToken;
import ge.vakho.spring_boot_skidentity_demo.authentication.SkIDDetails;

@Controller
public class ACSController {

	private static final Logger LOGGER = LoggerFactory.getLogger(ACSController.class);

	@Autowired
	private SkIDentityConfig config;
	
	@RequestMapping("/saml/acs")
	private String action(HttpServletRequest request, HttpServletResponse response) throws IOException {
		if ((request.getParameter("SAMLResponse") == null) || (request.getParameter("SAMLResponse").trim().isEmpty())) {
			LOGGER.error("The request parameter SAMLResponse is missing");
			throw new RuntimeException("Invalid arguments");
		}
		SAMLResponseManager responseManager = new SAMLResponseManager(this.config);
		Response samlResponse = responseManager.getResponseFromRequest(request);
		try {
			String statusCode = samlResponse.getStatus().getStatusCode().getValue();
			if (!statusCode.equals("urn:oasis:names:tc:SAML:2.0:status:Success")) {
				if (statusCode.equals("urn:oasis:names:tc:SAML:2.0:status:Responder")) {
					request.getSession().setAttribute("SAMLResponse", samlResponse);
					String msg = "User cancelled authentication";
					throw new SamlResponseException(msg);
				}
				throw new SamlResponseException(statusCode);
			}
			LOGGER.info("Successfully received a SAML Response.");

			request.getSession().setAttribute("SAMLResponse", samlResponse);
			NameIdExtractor.storeNameIdInHttpSession(request.getSession(), samlResponse);
			AttributeConverter.storeAttributesInHttpSession(request.getSession(), samlResponse);

			Assertion assertion = responseManager.getAssertionFromResponse(samlResponse);
			try {
				responseManager.verifyAssertionSignature(assertion);
			} catch (SecurityException | SignatureException ex) {
				throw new RuntimeException(ex);
			}
			request.getSession().setAttribute("LoginStatus", LoginStatus.success);

			// Programmatically set an authenticated user in Spring Security and Spring MVC
			{
				final List<GrantedAuthority> grantedAuths = new ArrayList<>();
				grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
				final UserDetails principal = new SkIDDetails(request.getSession(), grantedAuths);
				final Authentication auth = new SkIDAuthenticationToken(principal, grantedAuths);
			    SecurityContext sc = SecurityContextHolder.getContext();
			    sc.setAuthentication(auth);
			    request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, sc);
			}
			
			String redirectURL = (String) request.getSession().getAttribute("originalRequestAddress");
			LOGGER.info("Send redirect to originalRequestAddress: {}", redirectURL);
			response.sendRedirect(redirectURL);
		} catch (SamlResponseException ex) {
			request.getSession().setAttribute("LoginStatus", LoginStatus.failed);
			LOGGER.error("Authentication failed: {} (major: {}, minor: {})",
					new Object[] { ex.getMessage(), ex.getMajor(), ex.getMinor() });

			ErrorHandlerApplier eha = new ErrorHandlerApplier(this.config);
			eha.showError(ex, response);
		} catch (IOException ex) {
			LOGGER.error("Cannot redirect response: {})", ex.getMessage());
			throw new RuntimeException("Cannot redirect response");
		}
		return null;
	}

}