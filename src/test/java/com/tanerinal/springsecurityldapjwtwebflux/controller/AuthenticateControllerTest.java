package com.tanerinal.springsecurityldapjwtwebflux.controller;

import com.tanerinal.springsecurityldapjwtwebflux.TestConstants;
import com.tanerinal.springsecurityldapjwtwebflux.model.dto.AuthRequest;
import com.tanerinal.springsecurityldapjwtwebflux.model.dto.AuthResponse;
import com.tanerinal.springsecurityldapjwtwebflux.service.PortalUserService;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(AuthenticateController.class)
@WebFluxTest(AuthenticateController.class)
public class AuthenticateControllerTest {
    private static final String URL_AUTHENTICATE = "/authenticate";

    private WebTestClient webTestClient;
    private AuthRequest authRequest = AuthRequest.builder()
            .username(TestConstants.TEST_AUTH_USERNAME)
            .password(TestConstants.TEST_AUTH_PASSWORD)
            .build();

    @InjectMocks
    private AuthenticateController controller;

    @Mock
    private PortalUserService service;

    @Rule
    private ExpectedException expectedException = ExpectedException.none();

    private AuthenticateController spyController;
    private String token;
    private List<String> userRoles;
    private AuthResponse authResponse;

    @Before
    public void setUp() {
        spyController = PowerMockito.spy(controller);
        webTestClient = WebTestClient.bindToController(spyController).build();

        token = "token";
        userRoles = Arrays.asList("role1", "role2");
        authResponse = AuthResponse.builder()
                .token(token)
                .username(TestConstants.TEST_AUTH_USERNAME)
                .userRoles(userRoles)
                .build();
    }

    @SneakyThrows
    @Test
    public void testAuthenticateWhenAllIsWellShouldAuthenticateUserAndReturnAuthResponse() {
        when(service.authenticateUser(authRequest.getUsername(), authRequest.getPassword())).thenReturn(authResponse);

        webTestClient.post()
                .uri(URL_AUTHENTICATE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Mono.just(authRequest), AuthRequest.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .value(AuthResponse::getToken, equalTo(token))
                .value(AuthResponse::getUsername, equalTo(TestConstants.TEST_AUTH_USERNAME))
                .value(AuthResponse::getUserRoles, equalTo(userRoles));
    }

    @Test
    public void testAuthenticateWhenIllegalArgumentExceptionOccuredShouldThrowAdminPortalServerBaseRuntimeException() {
        IllegalArgumentException exception = new IllegalArgumentException(TestConstants.MESSAGE_EXCEPTION_CUSTOM);

        when(service.authenticateUser(authRequest.getUsername(), authRequest.getPassword())).thenThrow(exception);

        webTestClient.post()
                .uri(URL_AUTHENTICATE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Mono.just(authRequest), AuthRequest.class)
                .exchange()
                .expectStatus().is5xxServerError();
    }
}