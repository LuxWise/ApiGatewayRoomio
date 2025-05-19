package com.ApiGateway.filters;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;

@Component("JwtAuthFilter")
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Value("${jwt.secret}")
    private String secret;

    private static final String BEARER_PREFIX = "Bearer ";

    public JwtAuthFilter() {
        super(Config.class);
        System.out.println("✅ JwtAuthFilter registrado en el contexto");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            System.out.println("➡️ JwtAuthFilter interceptó: " + request.getPath());

            if (isPublicRoute(request)) {
                return chain.filter(exchange);
            }

            String token = extractToken(request.getHeaders());
            if (token == null) {
                return unauthorizedResponse(exchange, "Token no proporcionado");
            }

            try {
                Claims claims = validateAndGetClaims(token);
                ServerHttpRequest modifiedRequest = addHeaders(exchange, claims);

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                return unauthorizedResponse(exchange, "Token inválido");
            }
        };
    }

    private boolean isPublicRoute(ServerHttpRequest request) {
        String path = request.getPath().toString();
        String method = request.getMethod().toString();

        if (path.startsWith("/api/auth") || path.contains("/public")) {
            return true;
        }

        if ("GET".equals(method)) {
            return path.equals("/api/hotel") ||
                    path.equals("/api/hotel/rooms");
        }

        return false;
    }
    private String extractToken(HttpHeaders headers) {
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private Claims validateAndGetClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(java.util.Base64.getDecoder().decode(secret));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private ServerHttpRequest addHeaders(ServerWebExchange exchange, Claims claims) {
        return exchange.getRequest().mutate()
                .header("X-User-ID", claims.getSubject())
                .header("X-User-Roles", claims.get("roles", String.class))
                .build();
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        byte[] bytes = ("{\"error\": \"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }

    public static class Config {}
}