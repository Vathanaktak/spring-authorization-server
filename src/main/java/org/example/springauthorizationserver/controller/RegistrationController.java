package org.example.springauthorizationserver.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.springauthorizationserver.dto.RegisterRequest;
import org.example.springauthorizationserver.entity.Customer;
import org.example.springauthorizationserver.service.CustomerService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@Controller
@RequestMapping("/register")
@RequiredArgsConstructor
public class RegistrationController {

    private final CustomerService customerService;

    /**
     * Renders a responsive web sign-up page
     */
    @GetMapping
    @ResponseBody
    public ResponseEntity<String> showRegistrationPage(@RequestParam(name = "error", required = false) String error) {
        String errorBox = (error != null)
                ? "<div class=\"alert alert-danger\">" + escapeHtml(error) + "</div>"
                : "";

        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Sign Up - Create Account</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                            background: #f0f2f5;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            min-height: 100vh;
                            margin: 0;
                            padding: 20px;
                        }
                        .register-card {
                            background: white;
                            padding: 36px;
                            border-radius: 12px;
                            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                            width: 100%;
                            max-width: 440px;
                        }
                        h2 {
                            margin-top: 0;
                            margin-bottom: 8px;
                            color: #1a73e8;
                            font-size: 24px;
                            text-align: center;
                        }
                        .subtitle {
                            color: #666;
                            font-size: 14px;
                            text-align: center;
                            margin-bottom: 24px;
                        }
                        .form-group {
                            margin-bottom: 16px;
                        }
                        label {
                            display: block;
                            font-size: 13px;
                            font-weight: 600;
                            margin-bottom: 6px;
                            color: #333;
                        }
                        input {
                            width: 100%;
                            padding: 10px 12px;
                            border: 1px solid #ced4da;
                            border-radius: 6px;
                            font-size: 14px;
                            box-sizing: border-box;
                        }
                        input:focus {
                            outline: none;
                            border-color: #1a73e8;
                            box-shadow: 0 0 0 3px rgba(26,115,232,0.15);
                        }
                        .btn-submit {
                            width: 100%;
                            background: #1a73e8;
                            color: white;
                            padding: 12px;
                            border: none;
                            border-radius: 6px;
                            font-size: 15px;
                            font-weight: 600;
                            cursor: pointer;
                            margin-top: 10px;
                        }
                        .btn-submit:hover {
                            background: #1557b0;
                        }
                        .alert-danger {
                            background: #f8d7da;
                            color: #721c24;
                            border: 1px solid #f5c6cb;
                            padding: 10px 14px;
                            border-radius: 6px;
                            font-size: 13px;
                            margin-bottom: 16px;
                        }
                        .footer {
                            text-align: center;
                            margin-top: 20px;
                            font-size: 14px;
                            color: #666;
                        }
                        .footer a {
                            color: #1a73e8;
                            text-decoration: none;
                            font-weight: 600;
                        }
                    </style>
                </head>
                <body>
                    <div class="register-card">
                        <h2>Create Account</h2>
                        <p class="subtitle">Register in PostgreSQL to authenticate with OAuth2</p>

                        {{errorBox}}

                        <form method="post" action="/register">
                            <div class="form-group">
                                <label for="username">Username *</label>
                                <input type="text" id="username" name="username" required placeholder="Choose a username">
                            </div>
                            <div class="form-group">
                                <label for="password">Password * (Will be hashed with BCrypt)</label>
                                <input type="password" id="password" name="password" required placeholder="Create a strong password">
                            </div>
                            <div class="form-group">
                                <label for="email">Email *</label>
                                <input type="email" id="email" name="email" required placeholder="name@example.com">
                            </div>
                            <div class="form-group">
                                <label for="givenName">Given Name</label>
                                <input type="text" id="givenName" name="givenName" placeholder="e.g. John">
                            </div>
                            <div class="form-group">
                                <label for="familyName">Family Name</label>
                                <input type="text" id="familyName" name="familyName" placeholder="e.g. Doe">
                            </div>
                            <div class="form-group">
                                <label for="phoneNumber">Phone Number</label>
                                <input type="text" id="phoneNumber" name="phoneNumber" placeholder="e.g. 012345678">
                            </div>
                            <button type="submit" class="btn-submit">Sign Up</button>
                        </form>

                        <div class="footer">
                            Already have an account? <a href="/login">Sign in</a>
                        </div>
                    </div>
                </body>
                </html>
                """.replace("{{errorBox}}", errorBox);

        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    /**
     * Browser Form Submission handler (application/x-www-form-urlencoded)
     */
    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public ResponseEntity<String> handleFormRegistration(RegisterRequest request) {
        try {
            Customer saved = customerService.register(request);
            String successHtml = """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <title>Registration Successful</title>
                        <style>
                            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                            .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); text-align: center; max-width: 440px; }
                            h2 { color: #28a745; margin-top: 0; }
                            p { color: #555; font-size: 15px; }
                            .btn { display: inline-block; background: #1a73e8; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; margin-top: 16px; }
                        </style>
                    </head>
                    <body>
                        <div class="card">
                            <h2>&#10004; Account Created!</h2>
                            <p>User <strong>{{username}}</strong> was successfully registered with BCrypt password hashing in PostgreSQL.</p>
                            <a href="/login" class="btn">Proceed to Sign In</a>
                            <br/><br/>
                            <a href="/client/login" style="color: #666; font-size: 13px;">Or test OAuth2 Flow</a>
                        </div>
                    </body>
                    </html>
                    """.replace("{{username}}", escapeHtml(saved.getUsername()));

            return ResponseEntity.status(HttpStatus.CREATED).contentType(MediaType.TEXT_HTML).body(successHtml);
        } catch (IllegalArgumentException ex) {
            return showRegistrationPage(ex.getMessage());
        }
    }

    /**
     * REST API Endpoint for JSON clients (cURL, Postman, SPAs)
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> handleJsonRegistration(@RequestBody RegisterRequest request) {
        try {
            Customer saved = customerService.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "User registered successfully",
                    "id", saved.getId(),
                    "username", saved.getUsername(),
                    "email", saved.getEmail(),
                    "status", saved.getStatus(),
                    "role", saved.getRole()
            ));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Bad Request",
                    "message", ex.getMessage()
            ));
        }
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
