package lecture.springbootsecurity.controller;

import jakarta.servlet.http.HttpSession;
import lecture.springbootsecurity.dto.UserDto;
import lecture.springbootsecurity.entity.UserEntity;
import lecture.springbootsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j // 로그 관련 메소드를 편리하게 사용할 수 있는 롬복의 어노테이션
public class UserController {
    @Autowired
    UserService userService;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @GetMapping("")
    public String getAuth() {
        return "GET /auth";
    }

    @PostMapping("/signup")
    // ? : 와일드 카드 (어떤 값을 body 에 담을 지 모름)
    public ResponseEntity<?> registerUser(@RequestBody UserDto userDto) {
        try {
            UserEntity user = UserEntity.builder()
                    .email(userDto.getEmail())
                    .username(userDto.getUsername())
                    .password(passwordEncoder.encode(userDto.getPassword()))
                    .build();

            UserEntity responseUser = userService.create(user);

            UserDto responseUserDto = UserDto.builder()
                    .email(responseUser.getEmail())
                    .username(responseUser.getUsername())
                    .id(responseUser.getId())
                    .build();

            return ResponseEntity.ok().body(responseUserDto);
        } catch (Exception err) {
            return ResponseEntity.badRequest().body(err.getMessage());
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> loginUser(HttpSession session, @RequestBody  UserDto userDto) {
        try {
            UserEntity user = userService.login(userDto.getEmail(), userDto.getPassword());
            if (user == null) {
                throw new RuntimeException("login failed");
            }

            UserDto responseUserDto = UserDto.builder()
                    .email(user.getEmail()).username(user.getUsername())
                    .id(user.getId()).build();

            // log.info();
            // log.error();
             log.warn("session id: {}", session.getId());
            session.setAttribute("userId", user.getId());

            return ResponseEntity.badRequest().body(responseUserDto);

        } catch (Exception err) {
            return ResponseEntity.badRequest().body(err.getMessage());
        }
    }
}
