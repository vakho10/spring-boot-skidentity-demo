package ge.vakho.spring_boot_skidentity_demo.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import de.skidentity.cc.saml.auth.LoginStatus;
import de.skidentity.cc.saml.auth.SAMLHelper;
import de.skidentity.cc.saml.config.SkIDentityConfig;
import de.skidentity.cc.saml.error.ErrorHandlerApplier;
import de.skidentity.cc.saml.error.SamlResponseException;
import de.skidentity.cc.saml.request.AuthnRequestFactory;
import de.skidentity.cc.saml.request.AuthnRequestManager;

@Controller
public class LoginController {

	private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

	@Autowired
	private SkIDentityConfig config;

	@GetMapping("/saml/login")
	public String action(HttpServletRequest request, HttpServletResponse response) throws IOException {
		try {
			if (request.getSession().getAttribute("LoginStatus") == LoginStatus.success) {
				LOGGER.info("The user is already authenticated");
				if (!empty(request.getParameter("forceAuth"))) {
					if (Boolean.parseBoolean(request.getParameter("forceAuth"))) {
						SAMLHelper.sessionCleaner(request.getSession(false));
					}
				} else {
					String loggedInURL = request.getParameter("alreadyLoggedInRedirectURL");
					if (!empty(loggedInURL)) {
						LOGGER.info("Request parameter was set, redirecting to {}", loggedInURL);
						response.sendRedirect(loggedInURL);
						return null;
					}
					response.setStatus(403);
					String msg = "The user is already logged in. Set the request parameter 'forceAuth' to true to force re-authentication";
					throw new SamlResponseException(msg);
				}
			}
			String redirectURL = request.getHeader("referer");
			if (!empty(request.getParameter("redirect"))) {
				redirectURL = request.getParameter("redirect");
			}
			String entityID = this.config.getEntityID();
			if (!empty(request.getParameter("entityID"))) {
				entityID = request.getParameter("entityID");
				LOGGER.debug("Overwriting entityID of the config with {}", entityID);
			}
			if ((empty(redirectURL)) || (empty(entityID))) {
				String msg = "Missing values for redirectURL or entityID.";
				throw new SamlResponseException(msg);
			}
			LOGGER.info("Setting redirect URL to {}", redirectURL);
			request.getSession().setAttribute("originalRequestAddress", redirectURL);

			AuthnRequestFactory factory = new AuthnRequestFactory();
			AuthnRequestManager samlAuthnReq = factory.getAuthnRequestManager(this.config);

			AuthnRequest authnRequest = samlAuthnReq.build(entityID);
			samlAuthnReq.send(response, authnRequest, this.config);
		} catch (SamlResponseException ex) {
			request.getSession().setAttribute("LoginStatus", LoginStatus.failed);
			LOGGER.error("Sending AuthnRequest failed: {} (major: {}, minor: {})",
					new Object[] { ex.getMessage(), ex.getMajor(), ex.getMinor() });

			ErrorHandlerApplier eha = new ErrorHandlerApplier(this.config);
			eha.showError(ex, response);
		}
		return null;
	}

	private boolean empty(String s) {
		return (s == null) || (s.trim().isEmpty());
	}

}