package org.example.springauthorizationserver.service;

import lombok.RequiredArgsConstructor;
import org.example.springauthorizationserver.dto.RegisterRequest;
import org.example.springauthorizationserver.entity.Customer;
import org.example.springauthorizationserver.repository.CustomerRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    public List<Customer> getAllCustomers() {
        return customerRepository.findAll();
    }

    public Optional<Customer> getCustomerById(UUID id) {
        return customerRepository.findById(id);
    }

    public Optional<Customer> getCustomerByUsername(String username) {
        return customerRepository.findByUsername(username);
    }

    public Customer save(Customer customer) {
        return customerRepository.save(customer);
    }

    public Customer register(RegisterRequest request) {
        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email is required");
        }

        String username = request.getUsername().trim();
        String email = request.getEmail().trim();

        if (customerRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username '" + username + "' is already taken");
        }
        if (customerRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email '" + email + "' is already registered");
        }

        // Hash password with BCrypt via delegating password encoder
        String hashedPassword = passwordEncoder.encode(request.getPassword().trim());

        Customer customer = Customer.builder()
                .username(username)
                .password(hashedPassword)
                .email(email)
                .givenName(request.getGivenName())
                .familyName(request.getFamilyName())
                .phoneNumber(request.getPhoneNumber())
                .status("ACTIVE")
                .role("ROLE_USER")
                .build();

        return customerRepository.save(customer);
    }
}
