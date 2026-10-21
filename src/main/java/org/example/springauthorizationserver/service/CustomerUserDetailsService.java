package org.example.springauthorizationserver.service;

import lombok.RequiredArgsConstructor;
import org.example.springauthorizationserver.entity.Customer;
import org.example.springauthorizationserver.repository.CustomerRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomerUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer = customerRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found in PostgreSQL: " + username));

        boolean enabled = !"INACTIVE".equalsIgnoreCase(customer.getStatus());

        String role = customer.getRole();
        if (role == null || role.isBlank()) {
            role = "USER";
        }
        if (role.startsWith("ROLE_")) {
            role = role.substring(5);
        }

        return User.builder()
                .username(customer.getUsername())
                .password(customer.getPassword())
                .roles(role)
                .disabled(!enabled)
                .build();
    }
}
