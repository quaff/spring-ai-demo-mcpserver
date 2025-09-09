plugins {
	id("org.springframework.boot").version("3.5.4")
	id("io.spring.dependency-management").version("latest.release")
	java
}

group = "com.example.ai"
version = "0.0.1-SNAPSHOT"

java {
	version = 21
}

repositories {
	mavenCentral()
	maven {
		url = uri("https://repo.spring.io/milestone")
	}
    maven {
        url = uri("https://repo.spring.io/snapshot")
    }
}

dependencies {
	implementation(platform("org.springframework.ai:spring-ai-bom:1.1.0-SNAPSHOT"))
	implementation("org.springframework.ai:spring-ai-starter-mcp-server-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
