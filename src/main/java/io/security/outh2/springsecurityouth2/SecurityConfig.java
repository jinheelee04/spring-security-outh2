package io.security.outh2.springsecurityouth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());// 어떠한 요청이라도 인증필요
//        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        http.httpBasic((basic) -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션을 사용하지 않음, 접근할 때마다 인증 받아야함
  /*      http.exceptionHandling((exception) -> exception.authenticationEntryPoint(new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                System.out.println("custom entrypoint");
            }
        }));*/
//         http.with(new CustomSecurityConfigurer(), (conf) -> conf
//                        .setFlag(false));

        return http.build();
    }
//    @Bean
//    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());// 어떠한 요청이라도 인증필요
//        http.httpBasic(withDefaults());
//        return http.build();
//    }
}
