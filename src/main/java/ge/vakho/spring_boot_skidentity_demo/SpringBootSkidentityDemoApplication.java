package ge.vakho.spring_boot_skidentity_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = { UserDetailsServiceAutoConfiguration.class })
public class SpringBootSkidentityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootSkidentityDemoApplication.class, args);
	}

}
