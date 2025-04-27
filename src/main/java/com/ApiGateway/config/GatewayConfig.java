package com.ApiGateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("auth_route", r -> r
                        .path("/api/auth/**")
                        .filters(f -> f.rewritePath("/api/auth/(?<segment>.*)", "/auth/${segment}"))
                        .uri("http://auth-service:8081"))

                // Ruta para Hotel Service
                .route("hotel_route", r -> r
                        .path("/api/hotels/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri("http://hotel-service:8082"))

                .build();
    }
}