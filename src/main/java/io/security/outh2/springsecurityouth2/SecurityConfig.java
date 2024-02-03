package io.security.outh2.springsecurityouth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated());// 어떠한 요청이라도 인증필요
        http.formLogin((formLogin) -> formLogin
                .loginPage("/login")
                .defaultSuccessUrl("/articles"))
                ;
         http.with(new CustomSecurityConfigurer(), (conf) -> conf
                        .setFlag(false));

        return http.build();
    }
}
