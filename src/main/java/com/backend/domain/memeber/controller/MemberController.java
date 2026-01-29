package com.backend.domain.memeber.controller;

import com.backend.domain.memeber.entity.Member;
import com.backend.domain.memeber.from.MemberJoinForm;
import com.backend.domain.memeber.service.MemberService;
import com.backend.global.security.dto.MemberContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.security.Principal;
import java.util.concurrent.TimeUnit;

@Controller
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {
    private final MemberService memberService;

    @GetMapping("/join")
    public String showJoin() {
        return "member/join";
    }

    @PostMapping("/join")
    public String join(MemberJoinForm memberJoinForm, HttpServletRequest req) {
        String email = memberJoinForm.getEmail();
        String password = memberJoinForm.getPassword();

        Member oldMember = memberService.getMemberByEmail(email);

        if (oldMember != null) {
            return "redirect:/?errorMsg=Already exists email";
        }

        Member member = memberService.join(memberJoinForm);

        try {
            req.login(email, password); // 로그인 처리
            System.out.println("로그인 성공");
        } catch (ServletException e) {
            throw new RuntimeException(e);
        }

        return "redirect:/";
    }

    @GetMapping("/login")
    public String login() {
        return "member/login";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/profile")
    public String showProfile() {
        return "member/profile";
    }

    @GetMapping("/profile/{id}")
    public ResponseEntity<Object> showProfileImg(@PathVariable("id") Long id) {
        return ResponseEntity
                .status(HttpStatus.FOUND)
                .cacheControl(CacheControl
                        .maxAge(1, TimeUnit.HOURS)
                        .cachePublic()
                        .immutable())
                .build();
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/modify")
    public String showModify() {
        return "member/modify";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/modify")
    public String Modify(@AuthenticationPrincipal MemberContext memberContext, @RequestParam("username") String  username) {
        Member member = memberService.getMemberById(memberContext.getId());

        member.setUsername(username);

        memberService.modify(member);

        return "redirect:/member/profile";
    }
}