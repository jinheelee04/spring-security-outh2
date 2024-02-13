package io.security.cors2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
        http.cors((cors)->cors.configurationSource(corsConfigurationSource()));
        return http.build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // 허용되는 origin (프로토콜+호스트+포트)
//        configuration.addAllowedOrigin("http://localhost:8082"); // 허용되는 origin (프로토콜+호스트+포트)
        configuration.addAllowedMethod("*"); // 허용되는 메소트
        configuration.addAllowedHeader("*"); // 허용되는 헤더
//        configuration.setAllowCredentials(true); // 자격인증정보(세션ID or 쿠키 or 토큰) 사용 여부
        configuration.setMaxAge(3600L); // 해당 preflight request가 브라우저에 캐시될 수 있는 시간(초 단위)
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
