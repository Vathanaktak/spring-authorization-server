package org.example.springauthorizationserver.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final JwtEncoder jwtEncoder;

    @GetMapping("/")
    @ResponseBody
    public ResponseEntity<String> home(Authentication authentication) {
        boolean isAuthenticated = authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getName());

        String content;
        if (isAuthenticated) {
            String username = escapeHtml(authentication.getName());
            String roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(", "));

            // Generate a valid JWT token signed by our Authorization Server RSA key
            Instant now = Instant.now();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("http://localhost:9000")
                    .issuedAt(now)
                    .expiresAt(now.plus(2, ChronoUnit.HOURS))
                    .subject(authentication.getName())
                    .claim("scope", List.of("openid", "profile", "read", "write"))
                    .claim("client_id", "oidc-client")
                    .claim("roles", roles)
                    .build();

            String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

            content = """
                    <div class="user-badge">&#9989; Signed in as <strong>{{username}}</strong></div>
                    <p style="color: #555; margin-top: 10px; font-size: 14px;"><strong>Roles:</strong> <code>{{roles}}</code> &nbsp;|&nbsp; <strong>Status:</strong> ACTIVE</p>

                    <div class="token-container">
                        <div class="token-header">
                            <span style="font-weight: 600; color: #1a73e8;">&#128273; Access Token (JWT for Postman testing)</span>
                            <button type="button" class="btn-copy" onclick="copyToken()">&#128203; Copy Token</button>
                        </div>
                        <textarea id="tokenBox" readonly rows="4">{{token}}</textarea>
                        <div id="copyAlert" style="display: none; color: #137333; font-weight: 600; font-size: 13px; margin-top: 6px;">&#10004; Token copied to clipboard!</div>
                    </div>

                    <div class="postman-guide">
                        <strong>How to test in Postman:</strong>
                        <ol style="padding-left: 20px; margin: 8px 0; font-size: 13px; color: #444;">
                            <li>Set HTTP Method to <code>GET</code></li>
                            <li>URL: <code>http://localhost:9000/api/customers</code> (or <code>/api/customers/me</code>)</li>
                            <li>Go to <strong>Authorization</strong> tab &rarr; select <strong>Bearer Token</strong></li>
                            <li>Paste the token above &rarr; Click <strong>Send</strong>!</li>
                        </ol>
                    </div>

                    <div style="margin-top: 24px;">
                        <a href="/client/start-login" class="btn btn-primary">&#9654; Test Full OAuth2 Flow</a>
                        <a href="/logout" class="btn btn-secondary">Sign Out</a>
                    </div>
                    """
                    .replace("{{username}}", username)
                    .replace("{{roles}}", escapeHtml(roles))
                    .replace("{{token}}", token);
        } else {
            content = """
                    <p style="color: #555; font-size: 15px;">Welcome to the Spring Authorization Server and Resource Server platform.</p>
                    <div style="margin-top: 24px;">
                        <a href="/login" class="btn btn-primary">Sign In</a>
                        <a href="/register" class="btn btn-secondary">Create Account</a>
                        <a href="/client/login" class="btn btn-outline">OAuth2 Demo Client</a>
                    </div>
                    """;
        }

        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Spring Authorization Server</title>
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
                        .home-card {
                            background: white;
                            padding: 36px;
                            border-radius: 12px;
                            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                            width: 100%;
                            max-width: 620px;
                            text-align: center;
                        }
                        h1 {
                            margin-top: 0;
                            color: #1a73e8;
                            font-size: 24px;
                        }
                        .user-badge {
                            display: inline-block;
                            background: #e6f4ea;
                            color: #137333;
                            padding: 8px 16px;
                            border-radius: 20px;
                            font-size: 15px;
                        }
                        .token-container {
                            background: #f8f9fa;
                            border: 1px solid #dee2e6;
                            border-radius: 8px;
                            padding: 14px;
                            margin: 20px 0 14px 0;
                            text-align: left;
                        }
                        .token-header {
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                            margin-bottom: 8px;
                            font-size: 13px;
                        }
                        textarea {
                            width: 100%;
                            background: #212529;
                            color: #38d39f;
                            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
                            font-size: 12px;
                            padding: 10px;
                            border-radius: 6px;
                            border: 1px solid #495057;
                            resize: vertical;
                            box-sizing: border-box;
                        }
                        .btn-copy {
                            background: #1a73e8;
                            color: white;
                            border: none;
                            padding: 6px 14px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 12px;
                            font-weight: 600;
                        }
                        .btn-copy:hover {
                            background: #1557b0;
                        }
                        .postman-guide {
                            background: #fff8e1;
                            border-left: 4px solid #ffb300;
                            padding: 12px 16px;
                            text-align: left;
                            border-radius: 4px;
                            margin-top: 14px;
                        }
                        .btn {
                            display: inline-block;
                            padding: 10px 20px;
                            border-radius: 6px;
                            text-decoration: none;
                            font-weight: 600;
                            font-size: 14px;
                            margin: 6px;
                        }
                        .btn-primary { background: #1a73e8; color: white; }
                        .btn-primary:hover { background: #1557b0; }
                        .btn-secondary { background: #5f6368; color: white; }
                        .btn-secondary:hover { background: #494c50; }
                        .btn-outline { border: 1px solid #1a73e8; color: #1a73e8; background: transparent; }
                        .btn-outline:hover { background: #e8f0fe; }
                        .endpoints {
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #eee;
                            text-align: left;
                            font-size: 13px;
                            color: #666;
                        }
                        .endpoints code { color: #d93025; }
                    </style>
                    <script>
                        function copyToken() {
                            const copyText = document.getElementById("tokenBox");
                            copyText.select();
                            copyText.setSelectionRange(0, 99999);
                            navigator.clipboard.writeText(copyText.value).then(() => {
                                const alert = document.getElementById("copyAlert");
                                alert.style.display = "block";
                                setTimeout(() => { alert.style.display = "none"; }, 3000);
                            });
                        }
                    </script>
                </head>
                <body>
                    <div class="home-card">
                        <h1>Spring Authorization Server</h1>
                        {{content}}
                        
                        <div class="endpoints">
                            <strong>Platform Endpoints:</strong>
                            <ul style="padding-left: 20px; margin: 8px 0;">
                                <li>OAuth2 Discovery: <a href="/.well-known/openid-configuration"><code>/.well-known/openid-configuration</code></a></li>
                                <li>Customer Service API: <code>/api/customers</code> (Requires JWT)</li>
                                <li>Client Demo: <a href="/client/login"><code>/client/login</code></a></li>
                                <li>Sign Up: <a href="/register"><code>/register</code></a></li>
                            </ul>
                        </div>
                    </div>
                </body>
                </html>
                """
                .replace("{{content}}", content);

        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
