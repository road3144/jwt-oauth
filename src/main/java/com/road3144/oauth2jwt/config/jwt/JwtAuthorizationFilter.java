package com.road3144.oauth2jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.road3144.oauth2jwt.config.AppProperties;
import com.road3144.oauth2jwt.config.auth.PrincipalDetails;
import com.road3144.oauth2jwt.model.User;
import com.road3144.oauth2jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private final UserRepository userRepository;

    private final AppProperties appProperties;

    private final JwtTokenProvider tokenProvider;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository,
                                  AppProperties appProperties, JwtTokenProvider tokenProvider) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.appProperties = appProperties;
        this.tokenProvider = tokenProvider;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주고 요청이 됨");
        String jwtHeader = request.getHeader("Authorization");

        // 헤더가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = tokenProvider.getUsernameFromToken(jwtToken);
        //서명이 잘 됨
        if (username != null) {
            User user = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(user);
            // jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            // 강제로 시큐리티 셋션에 접근하여 authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println(principalDetails.getUser());
        }
        chain.doFilter(request, response);
    }
}
