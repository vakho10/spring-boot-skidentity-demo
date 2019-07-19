package ge.vakho.spring_boot_skidentity_demo.configuration;

import org.opensaml.core.config.InitializationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import de.skidentity.cc.saml.config.SkIDentityConfig;
import de.skidentity.cc.saml.config.SkIDentityConfigProvider;
import ge.vakho.spring_boot_skidentity_demo.filter.SkIDAuthFilter;

@Configuration
public class SkIDAuthConfig {

	@Value("${skidentity.config.path}")
	private String skidentityConfigPath;
	
	@Bean
	public SkIDentityConfig skIDentityConfig() throws InitializationException {
		SkIDentityConfigProvider provider = new SkIDentityConfigProvider(skidentityConfigPath);
		return provider.load();
	}
	
	@Bean
	public FilterRegistrationBean<SkIDAuthFilter> skIDentityFilter() {
		FilterRegistrationBean<SkIDAuthFilter> skidentityFilter = new FilterRegistrationBean<>();
		skidentityFilter.setFilter(new SkIDAuthFilter());
		skidentityFilter.addUrlPatterns("/profile/*");
		return skidentityFilter;
	}

}