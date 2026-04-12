package com.example.keycloak;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Map;

@Path("/")
public class UserPasskeyResource {

    private static final Logger logger = Logger.getLogger(UserPasskeyResource.class);
    private static final String EVENT_DETAIL_AUTH_METHOD = "auth_method";
    private static final String EVENT_DETAIL_PASSKEY_OPERATION = "passkey_operation";
    private static final String EVENT_DETAIL_REASON = "reason";
    private static final String EVENT_DETAIL_CREDENTIAL_ID_PREFIX = "credential_id_prefix";
    private static final String EVENT_DETAIL_VALUE_PASSKEY = "passkey";
    private static final String PASSKEY_OPERATION_REGISTER = "register";
    private static final String PASSKEY_OPERATION_AUTHENTICATE = "authenticate";
    private static final String EVENT_ERROR_PASSKEY_REGISTER_FAILED = "passkey_register_failed";
    private static final String EVENT_ERROR_PASSKEY_LOGIN_FAILED = "passkey_login_failed";

    private final KeycloakSession session;
    private final String clientId;
    private final PasskeyClientSupport clientSupport;

    /**
     * Default constructor for CDI environments that require a no-arg constructor.
     * <p>
     * The SPI-managed constructor should be used for normal runtime operation.
     */
    public UserPasskeyResource() {
        this(null, null);
    }

    /**
     * Creates the passkey resource with SPI-provided session and resolved configuration.
     *
     * @param session Keycloak request session
     * @param clientId configured OIDC client identifier used for passkey flows
     */
    public UserPasskeyResource(KeycloakSession session, String clientId) {
        this.session = session;
        this.clientId = resolveClientId(clientId);
        this.clientSupport = new PasskeyClientSupport(this.clientId);
    }

    /**
     * Handles browser CORS preflight requests for all passkey endpoints.
     *
     * @return preflight response with CORS headers when client configuration is available
     */
    @OPTIONS
    @Path("{any:.*}")
    public Response corsPreflight() {
        Response.ResponseBuilder responseBuilder = Response.ok();
        applyCors(responseBuilder, true);
        return responseBuilder.build();
    }

    /**
     * Issues a short-lived challenge used by registration and authentication requests.
     *
     * @return JSON object containing a base64url challenge value
     */
    @GET
    @Path("challenge")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge() {
        try {
            return jsonOk(Map.of("challenge", challengeService().issueChallenge()));
        } catch (IllegalStateException e) {
            return handleServerConfigurationError("Passkey challenge creation failed due to server configuration", e);
        }
    }

    /**
     * Stores a new passwordless WebAuthn credential for the authenticated bearer token user.
     *
     * @param request passkey registration payload
     * @return created response on success, error response otherwise
     */
    @POST
    @Path("save")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response savePasskey(PasskeyRequest request) {
        Response requestValidation = validateRequestBody(request);
        if (requestValidation != null) {
            logPasskeyRegisterError(null, "missing_request_body", null);
            return requestValidation;
        }

        UserModel user = getUserFromBearerToken();
        if (user == null) {
            logPasskeyRegisterError(null, "authenticated_user_not_found", null);
            return textResponse(Response.Status.UNAUTHORIZED, "Authenticated user not found from access token");
        }

        Response challengeValidation = validateChallenge(challengeService(), request.getChallenge());
        if (challengeValidation != null) {
            logPasskeyRegisterError(user, "invalid_or_expired_challenge", request.getCredentialId());
            return challengeValidation;
        }

        try {
            webAuthnService().registerPasskey(user, request, request.getChallenge());
            logPasskeyRegisterSuccess(user, request.getCredentialId());
            return textResponse(Response.Status.CREATED, "Passkey stored successfully");
        } catch (IllegalArgumentException e) {
            logPasskeyRegisterError(user, "invalid_registration_payload", request.getCredentialId());
            return buildErrorResponse(Response.Status.BAD_REQUEST, "Invalid registration payload: " + e.getMessage());
        } catch (IllegalStateException e) {
            logPasskeyRegisterError(user, "server_configuration_error", request.getCredentialId());
            return handleServerConfigurationError("Passkey registration failed due to server configuration", e);
        }
    }

    /**
     * Verifies a passkey assertion and continues the regular Keycloak browser login flow.
     *
     * @param request passkey authentication payload
     * @return browser flow response on success, error response otherwise
     */
    @POST
    @Path("authenticate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticatePasskey(PasskeyRequest request) {
        Response requestValidation = validateRequestBody(request);
        if (requestValidation != null) {
            logPasskeyLoginError(null, "missing_request_body", null);
            return requestValidation;
        }

        RealmModel realm = session().getContext().getRealm();
        if (realm == null) {
            return handleServerConfigurationError("Realm context unavailable for passkey authentication", new IllegalStateException("Realm context is unavailable"));
        }

        String requestCredentialId = webAuthnService().resolveCredentialId(request);
        if (requestCredentialId == null) {
            logPasskeyLoginError(null, "missing_credential_id", null);
            return buildErrorResponse(Response.Status.BAD_REQUEST, "credentialId or rawId is required");
        }

        Response challengeValidation = validateChallenge(challengeService(), request.getChallenge());
        if (challengeValidation != null) {
            logPasskeyLoginError(null, "invalid_or_expired_challenge", requestCredentialId);
            return challengeValidation;
        }

        UserModel user = webAuthnService().findUserByCredentialId(realm, requestCredentialId);
        if (user == null) {
            logPasskeyLoginError(null, "user_not_found_for_credential", requestCredentialId);
            return buildErrorResponse(Response.Status.NOT_FOUND, "User not found for credential");
        }

        if (!webAuthnService().hasPasskeyCredential(user, requestCredentialId)) {
            logPasskeyLoginError(user, "credential_not_bound_to_user", requestCredentialId);
            return buildErrorResponse(Response.Status.NOT_FOUND, "No passkey found for credential");
        }

        try {
            if (!webAuthnService().authenticatePasskey(user, request, requestCredentialId)) {
                logPasskeyLoginError(user, "invalid_passkey", requestCredentialId);
                return buildErrorResponse(Response.Status.UNAUTHORIZED, "Invalid passkey");
            }

            return completeBrowserFlowLogin(user, realm);
        } catch (IllegalArgumentException e) {
            logPasskeyLoginError(user, "invalid_authentication_payload", requestCredentialId);
            return buildErrorResponse(Response.Status.BAD_REQUEST, "Invalid authentication payload: " + e.getMessage());
        } catch (IllegalStateException e) {
            logPasskeyLoginError(user, "server_configuration_error", requestCredentialId);
            return handleServerConfigurationError("Passkey authentication failed due to server configuration", e);
        } catch (Exception e) {
            logPasskeyLoginError(user, "browser_flow_completion_failed", requestCredentialId);
            logger.error("Browser-flow completion after passkey authentication failed: " + e.getMessage(), e);
            return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Authentication flow failed");
        }
    }

    /**
     * Resolves the current user from the bearer token in request headers using Keycloak's authenticator.
     *
     * @return authenticated user, or {@code null} when token validation fails
     */
    private UserModel getUserFromBearerToken() {
        RealmModel realm = session().getContext().getRealm();
        if (realm == null) {
            return null;
        }

        AuthenticationManager.AuthResult authResult;
        try {
            authResult = new AppAuthManager.BearerTokenAuthenticator(session())
                    .setRealm(realm)
                    .setConnection(session().getContext().getConnection())
                    .setUriInfo(session().getContext().getUri())
                    .setHeaders(session().getContext().getRequestHeaders())
                    .authenticate();
        } catch (RuntimeException ignored) {
            return null;
        }

        if (authResult == null || authResult.getUser() == null) {
            return null;
        }

        if (clientId != null && !clientId.isBlank()) {
            ClientModel tokenClient = authResult.getClient();
            if (tokenClient == null || !clientId.equals(tokenClient.getClientId())) {
                return null;
            }
        }

        return authResult.getUser();
    }

    /**
     * Returns the active SPI session and fails fast if the resource was created without it.
     */
    private KeycloakSession session() {
        if (session == null) {
            throw new IllegalStateException("UserPasskeyResource must be created by UserPasskeyProvider (SPI-managed session required).");
        }
        return session;
    }

    /**
     * Creates the challenge service for the current request context.
     */
    private PasskeyChallengeService challengeService() {
        return new PasskeyChallengeService(session(), clientSupport);
    }

    /**
     * Creates the WebAuthn service for the current request context.
     */
    private PasskeyWebAuthnService webAuthnService() {
        return new PasskeyWebAuthnService(session(), clientSupport);
    }

    /**
     * Creates the browser-login service for the current request context.
     */
    private PasskeyBrowserLoginService browserLoginService() {
        return new PasskeyBrowserLoginService(session(), clientSupport);
    }

    /**
     * Logs and returns a uniform internal-server-error response for configuration problems.
     */
    private Response handleServerConfigurationError(String logMessage, IllegalStateException exception) {
        logger.error(logMessage, exception);
        return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Server configuration error");
    }

    /**
     * Builds a 200 JSON response wrapped with CORS headers.
     */
    private Response jsonOk(Object payload) {
        return jsonResponse(Response.Status.OK, payload);
    }

    /**
     * Builds a JSON response with CORS headers.
     */
    private Response jsonResponse(Response.Status status, Object payload) {
        Response.ResponseBuilder builder = status == Response.Status.OK
                ? Response.ok(payload)
                : Response.status(status).entity(payload);
        return withCors(builder.type(MediaType.APPLICATION_JSON_TYPE).build());
    }

    /**
     * Builds a plain-text response with CORS headers.
     */
    private Response textResponse(Response.Status status, String payload) {
        return withCors(Response.status(status)
                .entity(payload)
                .type(MediaType.TEXT_PLAIN_TYPE)
                .build());
    }

    /**
     * Builds a Keycloak-style error response and applies CORS headers.
     */
    private Response buildErrorResponse(Response.Status status, String message) {
        return withCors(ErrorResponse.error(
                PasskeyConfigResolver.firstNonBlank(message, ""),
                status
        ).getResponse());
    }

    /**
     * Rebuilds the response while appending CORS headers for configured clients.
     */
    private Response withCors(Response response) {
        Response.ResponseBuilder responseBuilder = Response.fromResponse(response);
        applyCors(responseBuilder, false);
        return responseBuilder.build();
    }

    /**
     * Applies Keycloak CORS settings based on configured client web origins.
     *
     * @param responseBuilder response builder to mutate
     * @param preflight whether to apply preflight-specific headers
     */
    private void applyCors(Response.ResponseBuilder responseBuilder, boolean preflight) {
        ClientModel corsClient = clientSupport.resolveConfiguredClient(session().getContext().getRealm());
        if (corsClient == null) {
            return;
        }

        Cors cors = Cors.builder()
                .builder(responseBuilder)
                .auth()
                .allowedMethods("GET", "POST", "OPTIONS");

        if (preflight) {
            cors.preflight();
        }

        cors.allowedOrigins(session(), corsClient);
        cors.add();
    }

    private static String resolveClientId(String configuredClientId) {
        return PasskeyConfigResolver.firstNonBlank(
                configuredClientId,
                PasskeyConfigResolver.resolveClientIdFromEnv()
        );
    }

    private Response validateRequestBody(PasskeyRequest request) {
        if (request == null) {
            return buildErrorResponse(Response.Status.BAD_REQUEST, "Request body is required");
        }
        return null;
    }

    private Response validateChallenge(PasskeyChallengeService challengeService, String challenge) {
        if (challengeService.consumeChallenge(challenge)) {
            return null;
        }
        return buildErrorResponse(Response.Status.UNAUTHORIZED, "Invalid or expired challenge");
    }

    private Response completeBrowserFlowLogin(UserModel user, RealmModel realm) {
        Response browserFlowResponse = browserLoginService().completeLogin(user, realm);
        if (browserFlowResponse == null) {
            return buildErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Authentication flow failed");
        }

        if (!isRedirectResponse(browserFlowResponse)) {
            return withCors(browserFlowResponse);
        }

        Response.ResponseBuilder responseBuilder = Response.noContent();
        copySetCookieHeaders(browserFlowResponse, responseBuilder);
        return withCors(responseBuilder.build());
    }

    private boolean isRedirectResponse(Response response) {
        int status = response.getStatus();
        return (status >= 300 && status < 400) || response.getLocation() != null;
    }

    private void copySetCookieHeaders(Response source, Response.ResponseBuilder target) {
        var headers = source.getHeaders();
        if (headers == null) {
            return;
        }

        var setCookieHeaders = headers.get("Set-Cookie");
        if (setCookieHeaders == null) {
            return;
        }

        for (Object setCookieHeader : setCookieHeaders) {
            target.header("Set-Cookie", setCookieHeader);
        }
    }

    private void logPasskeyRegisterSuccess(UserModel user, String credentialId) {
        EventBuilder event = eventBuilder(EventType.REGISTER, user);
        if (event == null) {
            return;
        }

        event.detail(EVENT_DETAIL_PASSKEY_OPERATION, PASSKEY_OPERATION_REGISTER);
        attachCredentialIdDetail(event, credentialId);
        event.success();
    }

    private void logPasskeyRegisterError(UserModel user, String reason, String credentialId) {
        EventBuilder event = eventBuilder(EventType.REGISTER, user);
        if (event == null) {
            return;
        }

        event.detail(EVENT_DETAIL_PASSKEY_OPERATION, PASSKEY_OPERATION_REGISTER);
        event.detail(EVENT_DETAIL_REASON, reason);
        attachCredentialIdDetail(event, credentialId);
        event.error(EVENT_ERROR_PASSKEY_REGISTER_FAILED);
    }

    private void logPasskeyLoginError(UserModel user, String reason, String credentialId) {
        EventBuilder event = eventBuilder(EventType.LOGIN_ERROR, user);
        if (event == null) {
            return;
        }

        event.detail(EVENT_DETAIL_PASSKEY_OPERATION, PASSKEY_OPERATION_AUTHENTICATE);
        event.detail(EVENT_DETAIL_REASON, reason);
        attachCredentialIdDetail(event, credentialId);
        event.error(EVENT_ERROR_PASSKEY_LOGIN_FAILED);
    }

    private EventBuilder eventBuilder(EventType eventType, UserModel user) {
        RealmModel realm = session().getContext().getRealm();
        if (realm == null) {
            return null;
        }

        EventBuilder event = new EventBuilder(realm, session(), session().getContext().getConnection())
                .event(eventType)
                .detail(EVENT_DETAIL_AUTH_METHOD, EVENT_DETAIL_VALUE_PASSKEY);
        ClientModel configuredClient = clientSupport.resolveConfiguredClient(realm);
        if (configuredClient != null) {
            event.client(configuredClient);
        }
        if (user != null) {
            event.user(user);
        }
        return event;
    }

    private void attachCredentialIdDetail(EventBuilder event, String credentialId) {
        String credentialIdPrefix = credentialIdPrefix(credentialId);
        if (credentialIdPrefix == null) {
            return;
        }
        event.detail(EVENT_DETAIL_CREDENTIAL_ID_PREFIX, credentialIdPrefix);
    }

    private String credentialIdPrefix(String credentialId) {
        if (credentialId == null || credentialId.isBlank()) {
            return null;
        }
        int length = Math.min(10, credentialId.length());
        return credentialId.substring(0, length);
    }
}
