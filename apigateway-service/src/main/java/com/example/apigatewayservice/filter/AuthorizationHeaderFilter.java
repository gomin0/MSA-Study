package com.example.apigatewayservice.filter;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    Environment env;

    public AuthorizationHeaderFilter(Environment env){
        super(Config.class);
        this.env = env;
    }

    public static class Config{

    }


    //토큰 검증 로직 필터 login -> token -> users (with token) -> header (include token)
    @Override
    public GatewayFilter apply(Config config) {

        return ( (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 헤더에 인증 정보가 없는 경우 에러 반환
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "No Authorization Header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0); // 토큰 값
            String jwt = authorizationHeader.replace("Bearer", ""); // Bearer token


            // JWT 토큰 인증된 토큰 인지
            if(!isJwtValid(jwt)){
                return onError(exchange, "Token Is not Valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }

    // JWT 정상적인지 확인
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
        String subject = null;
        try{
            subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt).getBody()
                    .getSubject(); // 문자열 추출
        }
        catch(Exception ex){
            returnValue = false;
        }

        if(subject == null || subject.isEmpty()){
            returnValue = false;
        }

        return returnValue;
    }

    // 에러 처리 담당
    // Mono(단일), Flux(다중) -> Spring WebFlux -> 데이터 처리 비동기 방식
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse(); // servlet 대신 사용
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();
    }

}