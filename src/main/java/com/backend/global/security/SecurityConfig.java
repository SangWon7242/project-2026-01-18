package com.backend.global.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import com.backend.global.app.AppConfig;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain baseSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authorize -> authorize
            // 웹 페이지 및 정적 리소스에 대한 접근 허용
            .requestMatchers("/", "/index", "/home", "/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico").permitAll()
            // API 관련 규칙 (기존 유지)
            .requestMatchers(HttpMethod.GET, "/api/*/posts/{id:\\d+}").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/*/posts").permitAll()
            .requestMatchers("/api/*/**").authenticated()
            // 위에 명시되지 않은 다른 모든 요청 허용 (Thymeleaf 페이지 등)
            .anyRequest().permitAll())
        .headers(headers -> headers
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .cors(cors -> cors.configurationSource(corsConfigurationSource()));

    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // 허용할 오리진 설정
    configuration.setAllowedOrigins(List.of(AppConfig.getSiteFrontUrl()));

    // 허용할 HTTP 메서드 설정
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));

    // 자격 증명 허용 설정
    configuration.setAllowCredentials(true);

    // 허용할 헤더 설정
    configuration.setAllowedHeaders(List.of("*"));

    // CORS 설정을 소스에 등록
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", configuration);

    return source;
  }
}
