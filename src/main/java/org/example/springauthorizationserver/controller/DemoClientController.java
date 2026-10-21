package org.example.springauthorizationserver.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Controller
public class DemoClientController {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    private static final String CLIENT_ID = "oidc-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "http://localhost:9000/client/callback";

    /**
     * Step 1: User lands on Client application and sees Login option.
     */
    @GetMapping("/client/login")
    @ResponseBody
    public ResponseEntity<String> renderClientLoginPage() {
        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>OAuth2 / OIDC Client Application</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 40px; }
                        .card { max-width: 700px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 32px; }
                        h1 { color: #1a73e8; margin-top: 0; }
                        .flow-list { background: #f8f9fa; border-radius: 8px; padding: 16px 24px; margin: 20px 0; }
                        .flow-list li { margin: 8px 0; color: #444; }
                        .btn { display: inline-block; background: #1a73e8; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px; margin-top: 10px; }
                        .btn:hover { background: #1557b0; }
                        .credentials { background: #e8f0fe; border-left: 4px solid #1a73e8; padding: 12px 16px; margin: 16px 0; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <h1>OAuth2 PKCE Demonstration Client</h1>
                        <p>This page simulates <strong>Step 1</strong> of the OAuth2 Authorization Code Flow with PKCE.</p>
                        
                        <div class="credentials">
                            <strong>PostgreSQL User Credentials for Step 3 & 4:</strong><br/>
                            &bull; Username: <code>user1</code> &nbsp;|&nbsp; Password: <code>password</code><br/>
                            &bull; Username: <code>johndoe</code> &nbsp;|&nbsp; Password: <code>password</code>
                        </div>

                        <ol class="flow-list">
                            <li><strong>Step 1:</strong> User clicks the Login button below.</li>
                            <li><strong>Step 2:</strong> Client redirects to Authorization Server (<code>/oauth2/authorize</code>) with PKCE.</li>
                            <li><strong>Step 3:</strong> Authorization Server shows Login & Consent page.</li>
                            <li><strong>Step 4:</strong> Authorization Server authenticates against <strong>PostgreSQL</strong> & records authorization.</li>
                            <li><strong>Step 5:</strong> Authorization Server redirects back to Client with Authorization Code.</li>
                            <li><strong>Step 6:</strong> Client exchanges Authorization Code + <code>code_verifier</code> at <code>/oauth2/token</code>.</li>
                            <li><strong>Step 7:</strong> Authorization Server returns JWT Access Token.</li>
                            <li><strong>Step 8:</strong> Client calls Customer Service API with <code>Bearer {access_token}</code>.</li>
                            <li><strong>Step 9:</strong> Customer Service verifies JWT & scope and returns data.</li>
                        </ol>

                        <a href="/client/start-login" class="btn">Login with OAuth2 (Start Step 1 & 2)</a>
                    </div>
                </body>
                </html>
                """;
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    /**
     * Step 2: Client prepares PKCE challenge and redirects to Authorization Server /oauth2/authorize
     */
    @GetMapping("/client/start-login")
    public String startLogin(HttpServletRequest request) {
        HttpSession session = request.getSession(true);

        String codeVerifier = generateRandomString(64);
        String codeChallenge = generateCodeChallenge(codeVerifier);
        String state = UUID.randomUUID().toString();

        session.setAttribute("oauth2_code_verifier", codeVerifier);
        session.setAttribute("oauth2_state", state);

        String authUrl = String.format(
                "/oauth2/authorize?response_type=code&client_id=%s&scope=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
                URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8),
                URLEncoder.encode("openid profile read", StandardCharsets.UTF_8),
                URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8),
                URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8)
        );

        return "redirect:" + authUrl;
    }

    /**
     * Steps 5 -> 6 -> 7 -> 8 -> 9:
     * - Receives authorization code from Authorization Server (Step 5)
     * - Exchanges code + code_verifier for JWT at /oauth2/token (Steps 6 & 7)
     * - Calls Customer Service API with access token (Step 8)
     * - Renders verified Customer Service response (Step 9)
     */
    @GetMapping("/client/callback")
    @ResponseBody
    public ResponseEntity<String> handleCallback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            HttpServletRequest request) {

        if (error != null) {
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(
                    "<h3>OAuth2 Error</h3><p><strong>" + error + "</strong>: " + errorDescription + "</p>"
            );
        }

        HttpSession session = request.getSession(false);
        String codeVerifier = (session != null) ? (String) session.getAttribute("oauth2_code_verifier") : null;

        if (code == null || codeVerifier == null) {
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(
                    "<h3>Missing code or code_verifier session!</h3><p><a href='/client/login'>Restart login flow</a></p>"
            );
        }

        try {
            // Step 6: Client -> Authorization Server /oauth2/token
            String tokenRequestBody = String.format(
                    "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
                    URLEncoder.encode(code, StandardCharsets.UTF_8),
                    URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8),
                    URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8),
                    URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8)
            );

            String basicAuth = Base64.getEncoder().encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));

            HttpRequest tokenRequest = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:9000/oauth2/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + basicAuth)
                    .POST(HttpRequest.BodyPublishers.ofString(tokenRequestBody))
                    .build();

            HttpResponse<String> tokenResponse = httpClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());

            // Step 7: Authorization Server returns Access Token (JWT)
            JsonNode tokenJson = objectMapper.readTree(tokenResponse.body());
            String accessToken = tokenJson.has("access_token") ? tokenJson.get("access_token").asText() : null;

            if (accessToken == null) {
                return ResponseEntity.status(500).contentType(MediaType.TEXT_HTML).body(
                        "<h3>Token Request Failed</h3><pre>" + tokenResponse.body() + "</pre>"
                );
            }

            // Step 8: Client -> Customer Service API with Authorization: Bearer {access_token}
            HttpRequest customerRequest = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:9000/api/customers"))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            // Step 9: Customer Service verifies JWT & scope and returns Customer data
            HttpResponse<String> customerResponse = httpClient.send(customerRequest, HttpResponse.BodyHandlers.ofString());

            String prettyCustomerJson = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(objectMapper.readTree(customerResponse.body()));

            String html = """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <title>OAuth2 Flow Completed Successfully</title>
                        <style>
                            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #eef2f6; margin: 0; padding: 30px; }
                            .card { max-width: 900px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.1); padding: 32px; }
                            h1 { color: #1e7e34; margin-top: 0; }
                            .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 13px; font-weight: 600; background: #d4edda; color: #155724; }
                            .step-box { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 16px; margin: 16px 0; }
                            .step-box h3 { margin-top: 0; color: #0d6efd; font-size: 16px; }
                            pre { background: #212529; color: #38d39f; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 13px; max-height: 250px; }
                            .btn { display: inline-block; background: #0d6efd; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: 500; }
                        </style>
                    </head>
                    <body>
                        <div class="card">
                            <h1>&#10004; OAuth2 & Customer Service Flow Completed! <span class="badge">9 of 9 Steps Successful</span></h1>
                            
                            <div class="step-box">
                                <h3>Step 5: Authorization Code Received from PostgreSQL-backed Auth Server</h3>
                                <code>%s</code>
                            </div>

                            <div class="step-box">
                                <h3>Step 6 & 7: Access Token (JWT) Issued from /oauth2/token</h3>
                                <pre>%s</pre>
                            </div>

                            <div class="step-box">
                                <h3>Step 8 & 9: Customer Service API Response (/api/customers)</h3>
                                <p><em>Verified via OAuth2 Resource Server filter chain with <code>SCOPE_read</code> claim</em></p>
                                <pre>%s</pre>
                            </div>

                            <a href="/client/login" class="btn">Test Again</a>
                        </div>
                    </body>
                    </html>
                    """.formatted(
                    escapeHtml(code),
                    escapeHtml(accessToken),
                    escapeHtml(prettyCustomerJson)
            );

            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);

        } catch (Exception ex) {
            log.error("Error completing OAuth2 client flow", ex);
            return ResponseEntity.status(500).contentType(MediaType.TEXT_HTML).body(
                    "<h3>Internal Error</h3><pre>" + ex.getMessage() + "</pre>"
            );
        }
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String generateRandomString(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).substring(0, length);
    }

    private static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to calculate SHA-256 code challenge", e);
        }
    }
}
