package lecture.springbootsecurity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Builder
@NoArgsConstructor //
@AllArgsConstructor //
@Getter
@Table(name="user")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // auto_increment
    @Column(name = "id", nullable = false)
    private long id;

    @Column(name = "username", length = 20, nullable = false)
    private String username;

    @Column(name = "email", length = 100, nullable = false)
    private String email;

    @Column(name = "password", nullable = false)
    private String password;
}
