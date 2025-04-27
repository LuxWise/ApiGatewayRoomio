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
import javax.crypto.SecretKey;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Value("${jwt.secret}")
    private String secret;

    private static final String BEARER_PREFIX = "Bearer ";

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Excluir rutas públicas
            if (isPublicRoute(request)) {
                return chain.filter(exchange);
            }

            // 2. Extraer y validar token
            String token = extractToken(request.getHeaders());
            if (token == null) {
                return unauthorizedResponse(exchange, "Token no proporcionado");
            }

            try {
                // 3. Validar y extraer claims
                Claims claims = validateAndGetClaims(token);

                // 4. Agregar headers para downstream services
                ServerHttpRequest modifiedRequest = addHeaders(exchange, claims);

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                return unauthorizedResponse(exchange, "Token inválido");
            }
        };
    }

    private boolean isPublicRoute(ServerHttpRequest request) {
        String path = request.getPath().toString();
        return path.startsWith("/api/auth") || path.contains("/public");
    }

    private String extractToken(HttpHeaders headers) {
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private Claims validateAndGetClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
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