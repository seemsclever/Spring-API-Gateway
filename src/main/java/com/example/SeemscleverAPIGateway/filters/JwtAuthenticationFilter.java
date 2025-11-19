package com.example.SeemscleverAPIGateway.filters;

import com.example.SeemscleverAPIGateway.utils.JwtUtil;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange,@NonNull WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        System.out.println("\n🔹 Incoming request: " + path);

        // Пропускаем public маршруты
        if (path.startsWith("/public")) {
            System.out.println("✅ Public endpoint, skipping auth check");
            return chain.filter(exchange);
        }

        // Проверяем наличие заголовка Authorization
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            System.out.println("❌ No Authorization header found");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        if (!authHeader.startsWith("Bearer ")) {
            System.out.println("❌ Authorization header does not start with Bearer: " + authHeader);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        System.out.println("🔸 Extracted token: " + token);

        // Валидация токена
        boolean isValid = jwtUtil.validateToken(token);
        System.out.println("🔍 Token validation result: " + isValid);
        if (!isValid) {
            System.out.println("❌ Token validation failed");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Извлекаем userId
        Long userId = jwtUtil.getUserIdFromToken(token);
        System.out.println("👤 Extracted userId from token: " + userId);

        if (userId == null) {
            System.out.println("❌ userId claim missing in token");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Добавляем userId в заголовки
        ServerWebExchange modifiedExchange = exchange.mutate()
                .request(builder -> builder.header("X-User-Id", String.valueOf(userId)))
                .build();

        System.out.println("✅ Auth passed, forwarding request to downstream service\n");

        // Передаём запрос дальше
        return chain.filter(modifiedExchange)
                .contextWrite(ReactiveSecurityContextHolder.clearContext());
    }
}
