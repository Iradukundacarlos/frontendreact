package dev.kiki.donation.config;

import dev.kiki.donation.auth.jwt.JwtFilter;
import dev.kiki.donation.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final JwtFilter jwtFilter;
        private final AccessDeniedHandler accessDeniedHandler;
        private final CorsConfigurationSource corsConfigurationSource;

        String[] WHITELIST_URLS = {
                        "/api/auth/**",
                        "/v2/api-docs",
                        "/v3/api-docs",
                        "/v3/api-docs/**",
                        "/swagger-resources",
                        "/swagger-resources/**",
                        "/configuration/ui",
                        "/configuration/security",
                        "/swagger-ui/**",
                        "/webjars/**",
                        "/swagger-ui.html"
        };

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                                .csrf(AbstractHttpConfigurer::disable)
                                .authorizeHttpRequests(
                                                customizer -> customizer
                                                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                                                .requestMatchers(WHITELIST_URLS).permitAll()
                                                                .requestMatchers(HttpMethod.GET, "/api/users/export")
                                                                .hasAuthority(Role.ROLE_ADMIN.name())
                                                                .requestMatchers(HttpMethod.DELETE, "/api/users/userId")
                                                                .hasAuthority(Role.ROLE_ADMIN.name())
                                                                .requestMatchers(HttpMethod.POST, "/api/notifications")
                                                                .hasAuthority(Role.ROLE_ADMIN.name())
                                                                .anyRequest()
                                                                .authenticated())
                                .sessionManagement(
                                                customizer -> customizer
                                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .exceptionHandling(exceptionHandling -> exceptionHandling
                                                .accessDeniedHandler(accessDeniedHandler))
                                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

}
