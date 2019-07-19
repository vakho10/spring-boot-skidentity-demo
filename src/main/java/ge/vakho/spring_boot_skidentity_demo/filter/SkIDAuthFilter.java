package ge.vakho.spring_boot_skidentity_demo.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.skidentity.cc.saml.auth.LoginStatus;
import de.skidentity.cc.saml.auth.SkIDentityFilter;

public class SkIDAuthFilter implements Filter {

	private static final Logger LOGGER = LoggerFactory.getLogger(SkIDentityFilter.class);

	@Override
	public void doFilter(ServletRequest request, //
			ServletResponse response, //
			FilterChain chain) throws IOException, ServletException {
		
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;

		LoginStatus loginStatus = (LoginStatus) httpServletRequest.getSession().getAttribute("LoginStatus");
		LOGGER.debug("Login Status is: {}", loginStatus);
		if (loginStatus == LoginStatus.success) {
			chain.doFilter(request, response);
		} else {
			String redirectUrl = getRedirectURL(httpServletRequest);

			final String urlPattern = "/saml/login";

			String url = String.format("%s%s?redirect=%s",
					new Object[] { httpServletRequest.getContextPath(), urlPattern, redirectUrl });

			LOGGER.debug("Redirect URL: {}", url);
			httpServletResponse.sendRedirect(url);
		}
	}

	private static String getRedirectURL(HttpServletRequest httpReq) {
		StringBuffer redirectUrl = new StringBuffer("");
		if ((httpReq.getHeader("Skid-Redirect-URL") != null) && (!httpReq.getHeader("Skid-Redirect-URL").isEmpty())) {
			redirectUrl.append(httpReq.getHeader("Skid-Redirect-URL"));
		} else {
			redirectUrl = httpReq.getRequestURL();
		}
		String query = httpReq.getQueryString();
		if (query != null) {
			redirectUrl.append("?").append(query);
		}
		return redirectUrl.toString();
	}

}