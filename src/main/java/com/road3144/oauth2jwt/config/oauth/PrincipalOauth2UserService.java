package com.road3144.oauth2jwt.config.oauth;

import com.road3144.oauth2jwt.config.auth.PrincipalDetails;
import com.road3144.oauth2jwt.config.oauth.provider.GoogleUserInfo;
import com.road3144.oauth2jwt.config.oauth.provider.InstagramUserInfo;
import com.road3144.oauth2jwt.config.oauth.provider.KakaoUserInfo;
import com.road3144.oauth2jwt.config.oauth.provider.OAuth2UserInfo;
import com.road3144.oauth2jwt.model.User;
import com.road3144.oauth2jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("PrincipalOauth2UserService loadUser 실행");
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("attributes : " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo= null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("instagram")) {
            System.out.println("인스타그램 로그인 요청");
            oAuth2UserInfo = new InstagramUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("kakao")) {
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new KakaoUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }else {
            System.out.println("지원 안하는 형식입니다");
            return null;
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String email = oAuth2UserInfo.getEmail();
        String roles = "ROLE_USER";

        User user =  userRepository.findByUsername(username);

        //강제 회원 가입
        if (user == null) {
            user = User.builder()
                    .username(username)
                    .email(email)
                    .roles(roles)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        } else {
            System.out.println("이미 한적이 있습니다. 로그인 합니다.");
        }
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
