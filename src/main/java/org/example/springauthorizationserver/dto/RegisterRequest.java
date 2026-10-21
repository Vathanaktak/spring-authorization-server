package org.example.springauthorizationserver.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequest {
    private String username;
    private String password;
    private String email;
    private String givenName;
    private String familyName;
    private String phoneNumber;
}
