package lecture.springbootsecurity.security;
// 1. 세션 기반 인증 방식
// == 로그인 성공 -> session 에 userId 저장
// == 로그인 여부 판단할 때 -> session 에 userId 유무
// == 존재하면, 로그인한 유저. 없으면, 로그인 안 한 유저

// 2. JWT token 기반 인증 방식

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class CustomAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            HttpSession session = request.getSession();
            log.warn("session id: {}", session.getId());
            Object userId = session.getAttribute("userId");

            if (userId != null) {
                // 1. 사용자 정보를 담는 토큰 생성
                Authentication authentication = new UsernamePasswordAuthenticationToken(String.valueOf(userId), null, AuthorityUtils.NO_AUTHORITIES);

                // 2. SecurityContextHolder 에 authentication 정보 set
                // 클라이언트 요청 -> 응답 사이에 일시적으로 auth 정보를 저장하는 공간
                SecurityContextHolder.getContext().setAuthentication(authentication);
                // SecurityContextHolder.getContext().getAuthentication().getPrincipal(); // => 저장한 인가된 유저 토큰이 담긴 authentication 이 나옴
            }
        } catch (Exception err) {
            log.error("filter error {}", err.getMessage());
        }

        // 다음 필터가 이어서 실행되도록 아래 코드가 마지막에 꼭 실행되어야 함
        filterChain.doFilter(request, response);
    }
}
