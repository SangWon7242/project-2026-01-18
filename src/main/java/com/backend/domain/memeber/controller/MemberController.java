package com.backend.domain.memeber.controller;

import com.backend.domain.memeber.entity.Member;
import com.backend.domain.memeber.form.MemberJoinForm;
import com.backend.domain.memeber.service.MemberService;
import com.backend.global.security.dto.MemberContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

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

    @GetMapping("/loginsuccess")
    public String loginsuccess() { return "member/loginsuccess";}

    @GetMapping("/loginfail")
    public String loginfail() { return "member/loginfail";}

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/profile")
    public String showProfile() {
        return "member/profile";
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