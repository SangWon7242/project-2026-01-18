package com.backend.global.security.service;

import com.backend.domain.memeber.entity.Member;
import com.backend.domain.memeber.repository.MemberRepository;
import com.backend.domain.memeber.service.MemberService;
import com.backend.global.security.dto.MemberContext;
import com.backend.global.security.exception.OAuthTypeMatchNotFoundException;
import com.backend.domain.memeber.exception.MemberNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserService extends DefaultOAuth2UserService {

  private final MemberRepository memberRepository;

  @Override
  @Transactional
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    OAuth2User oAuth2User = super.loadUser(userRequest);

    String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
    Map<String, Object> attributes = oAuth2User.getAttributes();

    String oauthId = oAuth2User.getName();
    String oauthType = userRequest.getClientRegistration().getRegistrationId().toUpperCase();

    log.info("OAuth2 로그인 요청: type={}, id={}, attributes={}", oauthType, oauthId, attributes);


    switch (oauthType) {
      case "KAKAO" -> {
        return kakaologin(oauthType, oauthId, attributes, userNameAttributeName);
      }
      default -> throw new OAuthTypeMatchNotFoundException();
    }
  }


  private OAuth2User kakaologin(String oauthType, String oauthId, Map attributes, String userNameAttributeName) {

    String email = "%s@kakao.com".formatted(oauthId);
    String username = "%s_%s".formatted(oauthType, oauthId);

    Map attributesKakaoAcount = (Map) attributes.get("kakao_account");
    if ((boolean) attributesKakaoAcount.get("has_email")) {
      email = (String) attributesKakaoAcount.get("email");
    }

    Member member = memberRepository.findByEmail(email).orElse(null);


    if (member == null) {
      member = Member.builder()
              .email(email)
              .username(username)
              .password("")
              .build();

      memberRepository.save(member);
    }

    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority("member"));
    return new MemberContext(member, authorities, attributes, userNameAttributeName);
  }

  private boolean isNew(String oAuthType, String oAuthId) {
    throw new UnsupportedOperationException("use emailKey-based lookup instead");
  }
}
