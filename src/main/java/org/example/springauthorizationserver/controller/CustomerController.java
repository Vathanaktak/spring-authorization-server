package org.example.springauthorizationserver.controller;

import lombok.RequiredArgsConstructor;
import org.example.springauthorizationserver.entity.Customer;
import org.example.springauthorizationserver.service.CustomerService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/customers")
@RequiredArgsConstructor
public class CustomerController {

    private final CustomerService customerService;

    /**
     * Step 8 & 9: Customer Service verifies JWT and checks required scope ('read')
     */
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<List<Customer>> getAllCustomers() {
        return ResponseEntity.ok(customerService.getAllCustomers());
    }

    @GetMapping("/me")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<?> getCurrentCustomer(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getSubject();
        return customerService.getCustomerByUsername(username)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.ok(Map.of(
                        "username", username,
                        "issuer", jwt.getIssuer().toString(),
                        "scopes", jwt.getClaimAsStringList("scope"),
                        "message", "Authenticated customer from JWT token"
                )));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<Customer> getCustomerById(@PathVariable UUID id) {
        return customerService.getCustomerById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_write')")
    public ResponseEntity<Customer> createCustomer(@RequestBody Customer customer) {
        Customer saved = customerService.save(customer);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }
}
