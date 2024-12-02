package dev.kiki.donation.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                contact = @Contact(
                        name = "Nishimwe Prosper",
                        email = "prosper.rk1@gmail.com"
                ),
                description = "OpenAPI documentation of a Blood donation API v.1.0",
                title = "Blood donation API - Kiki",
                version = "v.1.0"
        ),
        servers = {
                @Server(
                        description = "Local ENV"
                )
        }
)
@SecurityScheme(
        type = SecuritySchemeType.HTTP,
        name = "auth",
        description = "JWT Authentication",
        scheme = "bearer",
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class SwaggerConfig {
}
