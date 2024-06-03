package com.boot.apprds.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

@Log4j2
@Configuration
public class CustomSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)throws Exception{

        log.info("----------configure------------");

        return http.build();
    }


//  WebSecurityCustomizer : 보안 필터 체인을 구성하는 대신, 보안 설정에서 특정 요청을 완전히 무시하도록 설정하는 역할. 보안 필터 체인에 전혀 포함되지 않으며, 보안 검사를 받지 않습니다.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){

        log.info("---------web configure ---------");

        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
//web.ignoring() : (특정 요청을 보안 필터 체인에서 제외하도록 설정) 지정된 경로에 대한 요청이 보안 필터 체인을 통과하지 않고 무시됩니다.
// requestMatchers : 무시할 요청 매처를 지정
// PathRequest.toStaticResources().atCommonLocations() : 일반적으로 사용되는 정적 리소스 경로를 포함합니다
    }


}