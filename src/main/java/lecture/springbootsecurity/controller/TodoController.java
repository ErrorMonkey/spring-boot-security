package lecture.springbootsecurity.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/todo")
public class TodoController {
    @GetMapping("")
    public String getTodo(@AuthenticationPrincipal String userId) {
        // @AuthenticationPrincipal: SecurityContextHolder.getContext().getAuthentication().getPrincipal(); // => authentication 이 나옴
        // 값을 자동으로 userId 에 할당해주는 역할

        return "GET /todo by user id: " + userId;
    }
}
