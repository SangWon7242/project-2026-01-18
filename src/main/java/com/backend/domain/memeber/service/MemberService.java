package com.backend.domain.memeber.service;

import com.backend.domain.memeber.entity.Member;
import com.backend.domain.memeber.form.MemberJoinForm;
import com.backend.domain.memeber.repository.MemberRepository;
import com.backend.global.security.dto.MemberContext;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public Member getMemberByEmail(String email) {
        return memberRepository.findByEmail(email).orElse(null);
    }

    public Member join(MemberJoinForm memberJoinForm) {

        String passwordClearText = memberJoinForm.getPassword();
        String password = passwordEncoder.encode(passwordClearText);

        Member member = Member.builder()
                .username(memberJoinForm.getEmail())
                .email(memberJoinForm.getEmail())
                .password(password)
                .build();

        memberRepository.save(member);

        return member;
    }

    public Member getMemberById(Long id) {
        return memberRepository.findById(id).orElse(null);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // 사용자 조회
        Member member = memberRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("email not found: " + email));


        // 권한 설정
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("member"));

        return new MemberContext(member, authorities);
    }

    public Member join(String username, String password, String email) {
        Member member = Member.builder()
                .username(username)
                .password(password)
                .email(email)
                .build();

        memberRepository.save(member);

        return member;
    }

    // SELECT COUNT(*) FROM `member`;
    public long count() {
        return memberRepository.count();
    }

    public void modify(Member member) {
        memberRepository.save(member);
    }
}
