package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
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


//    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private UserRepository userRepository;

    @Autowired
    public PrincipalOauth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("getAccessToken : " + userRequest.getAccessToken().getTokenValue());
        System.out.println("getAttributes : " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        // 회원가입 진행
        // provider
//        String provider = userRequest.getClientRegistration().getClientId();
        String checkProvider = userRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo oAuth2UserInfo = null;
        if(checkProvider.equals("google")) {

            System.out.println("구글 로그인 요청");

            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());

        } else if (checkProvider.equals("facebook")) {

            System.out.println("페이스북 로그인 요청");

            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());

        } else {
            System.out.println("우리는 구글과 페이스북만 지원해요~");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();// providerId
        String username = provider + "_" + providerId;// username
        String password = bCryptPasswordEncoder.encode("겟인데어");// password
        String email = oAuth2UserInfo.getEmail();// email
        String role = "ROLE_USER";// role

        // 회원가입 되어있는지 확인
        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null) {

            System.out.println("로그인이 최초입니다.");

            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(userEntity);
        } else {
            System.out.println("로그인을 이미 한 적이 있습니다.");
        }


//        return super.loadUser(userRequest);
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
