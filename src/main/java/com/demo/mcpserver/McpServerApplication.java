package com.demo.mcpserver;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.scheduler.Schedulers;

import java.util.function.Function;

@SpringBootApplication
public class McpServerApplication {

    static {
        Function<Runnable, Runnable> decorator =
                runnable -> {
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    return () -> {
                        try {
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            runnable.run();
                        } finally {
                            SecurityContextHolder.clearContext();
                        }
                    };
                };
        Schedulers.onScheduleHook("McpBoundedElasticHook", decorator);
    }

    public static void main(String[] args) {
        SpringApplication.run(McpServerApplication.class, args);
    }

    @Bean
    public ToolCallbackProvider weatherTools(OpenMeteoService openMeteoService) {
        return MethodToolCallbackProvider.builder()
                .toolObjects(openMeteoService)
                .build();
    }

}