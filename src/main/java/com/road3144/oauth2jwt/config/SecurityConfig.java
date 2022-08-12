package com.road3144.oauth2jwt.config;

import com.road3144.oauth2jwt.config.jwt.JwtAuthenticationFilter;
import com.road3144.oauth2jwt.config.jwt.JwtAuthorizationFilter;
import com.road3144.oauth2jwt.config.jwt.JwtTokenProvider;
import com.road3144.oauth2jwt.config.oauth.PrincipalOauth2UserService;
import com.road3144.oauth2jwt.config.oauth.handler.OAuth2AuthenticationSuccessHandler;
import com.road3144.oauth2jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    CorsConfig corsConfig;
    @Autowired
    UserRepository userRepository;
    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;
    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    @Autowired
    private AppProperties appProperties;
    @Autowired
    private JwtTokenProvider tokenProvider;
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()
                .oauth2Login()
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
                .and()
                .defaultSuccessUrl("/")
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .and()
                .httpBasic().disable()
                .apply(new MyCustomDsl())
                .and()
                .authorizeRequests(authorize -> authorize
                        .antMatchers("/api/v1/user")
                        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/manager")
                        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/admin")
                        .access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll()

                ).build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity>{
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository, appProperties, tokenProvider));
        }
    }
}
