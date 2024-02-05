package io.security.outh2.springsecurityouth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());// 어떠한 요청이라도 인증필요
        http.formLogin(withDefaults());
//         http.with(new CustomSecurityConfigurer(), (conf) -> conf
//                        .setFlag(false));

        return http.build();
    }
    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());// 어떠한 요청이라도 인증필요
        http.httpBasic(withDefaults());
        return http.build();
    }
}
