package com.demo.mcpserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class OpenMeteoService {

    private final RestClient restClient;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public OpenMeteoService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder
                .baseUrl("https://api.open-meteo.com/v1")
                .build();
    }

    @McpTool(description = "根据经纬度获取天气预报")
    public String getWeatherForecastByLocation(
            @McpToolParam(description = "纬度，例如：39.9042") String latitude,
            @McpToolParam(description = "经度，例如：116.4074") String longitude) {
        logger.info("Authentication: {}", SecurityContextHolder.getContext().getAuthentication());
        logger.info("getWeatherForecastByLocation({}, {})", latitude, longitude);
        try {
            String response = restClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/forecast")
                            .queryParam("latitude", latitude)
                            .queryParam("longitude", longitude)
                            .queryParam("current", "temperature_2m,wind_speed_10m")
                            .queryParam("timezone", "auto")
                            .build())
                    .retrieve().body(String.class);
            return "当前位置（纬度：" + latitude + "，经度：" + longitude + "）的天气信息：\n" + response;
        } catch (Exception e) {
            return "获取天气信息失败：" + e.getMessage();
        }
    }

    @McpTool(description = "根据经纬度获取空气质量信息")
    public String getAirQuality(
            @McpToolParam(description = "纬度，例如：39.9042") String latitude,
            @McpToolParam(description = "经度，例如：116.4074") String longitude) {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof BearerTokenAuthentication auth) {
            logger.info("Authentication: {} {}", auth.getName(), auth.getAuthorities());
        }
        logger.info("getAirQuality({}, {})", latitude, longitude);
        // TODO
        return "当前位置（纬度：" + latitude + "，经度：" + longitude + "）的空气质量：\n" +
                "- PM2.5: 15 μg/m³ (优)\n" +
                "- PM10: 28 μg/m³ (良)\n" +
                "- 空气质量指数(AQI): 42 (优)\n" +
                "- 主要污染物: 无";
    }
}