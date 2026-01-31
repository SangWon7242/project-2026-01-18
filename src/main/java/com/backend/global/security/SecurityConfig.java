package com.backend.global.security;

import com.backend.global.security.service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import com.backend.global.app.AppConfig;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Lazy
  @Autowired
  private OAuth2UserService OAuth2UserService;

  @Bean
  public SecurityFilterChain baseSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/", "/index", "/home", "/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/*/posts/{id:\\d+}").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/*/posts").permitAll()
            .requestMatchers("/api/*/**").authenticated()
            .anyRequest().permitAll())
        .headers(headers -> headers
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(form -> form
                .loginPage("/member/login") //
                .loginProcessingUrl("/member/login")
                .defaultSuccessUrl("/member/loginsuccess")
                .failureUrl("/member/loginfail")
                .permitAll()
        ).oauth2Login(oauth2 -> oauth2
                    .loginPage("/member/login")
                    .defaultSuccessUrl("/member/loginsuccess")
                    .userInfoEndpoint(userInfo -> userInfo.userService(OAuth2UserService))
                    .permitAll()
        ).logout(logout -> logout
                .logoutUrl("/member/logout")
                .logoutSuccessUrl("/")
                .permitAll()
        ).cors(cors -> cors.configurationSource(corsConfigurationSource()));

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

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  AuthenticationManager authenticationManager(
          AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }
}
