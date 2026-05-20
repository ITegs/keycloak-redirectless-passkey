package com.example.keycloak;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.UriUtils;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.utils.RedirectUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

final class PasskeyWebAuthnService {

    private static final String PASSKEY_TYPE = WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    private static final int MAX_CREDENTIAL_LABEL_LENGTH = 120;
    private static final String DEFAULT_CREDENTIAL_LABEL = "Passkey";
    private static final String HEADER_ORIGIN = "Origin";
    private static final String ANY_ORIGIN = "*";
    private static final String WEB_ORIGIN_USE_REDIRECTS = "+";

    private final KeycloakSession session;

    /**
     * Creates WebAuthn helper logic bound to the current request.
     *
     * @param session Keycloak request session
     */
    PasskeyWebAuthnService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Finds a user for an authentication request from the WebAuthn userHandle.
     *
     * @param realm current realm
     * @param userHandle base64url-encoded WebAuthn userHandle
     * @return matching user or {@code null} when none exists
     */
    UserModel findUserByUserHandle(RealmModel realm, String userHandle) {
        if (userHandle == null || userHandle.isBlank()) {
            return null;
        }

        try {
            String userId = new String(Base64Url.decode(userHandle), StandardCharsets.UTF_8);
            return userId.isBlank() ? null : session.users().getUserById(realm, userId);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Checks whether the user has a stored passwordless credential matching the requested id.
     *
     * @param user target user
     * @param credentialId credential id from client
     * @return {@code true} when a matching passkey credential exists
     */
    boolean hasPasskeyCredential(UserModel user, String credentialId) {
        byte[] requestedCredentialId = credentialIdToBytes(credentialId);
        if (requestedCredentialId.length == 0) {
            return false;
        }

        return user.credentialManager()
                .getStoredCredentialsByTypeStream(PASSKEY_TYPE)
                .map(WebAuthnCredentialModel::createFromCredentialModel)
                .map(WebAuthnCredentialModel::getWebAuthnCredentialData)
                .filter(Objects::nonNull)
                .map(data -> data.getCredentialId())
                .filter(Objects::nonNull)
                .map(this::credentialIdToBytes)
                .anyMatch(storedCredentialId -> Arrays.equals(storedCredentialId, requestedCredentialId));
    }

    /**
     * Validates and stores a new passkey credential through Keycloak's credential provider.
     *
     * @param user target user
     * @param request registration payload
     * @param expectedChallenge challenge issued by this service
     */
    void registerPasskey(ClientModel client, UserModel user, PasskeyRequest request, String expectedChallenge) {
        RealmModel realm = requireRealm();
        RegistrationRequest registrationRequest = new RegistrationRequest(
                decodeRequiredBase64Url(request.getAttestationObject(), "attestationObject"),
                decodeRequiredBase64Url(request.getClientDataJSON(), "clientDataJSON")
        );
        RegistrationParameters registrationParameters = new RegistrationParameters(
                buildServerProperty(realm, client, expectedChallenge),
                isUserVerificationRequired(realm)
        );

        RegistrationData registrationData = validateRegistration(registrationRequest, registrationParameters);
        WebAuthnCredentialProvider provider = getPasswordlessCredentialProvider();
        WebAuthnCredentialModelInput credentialInput = createCredentialInput(registrationData);
        String credentialLabel = buildCredentialLabel(user, request);

        CredentialModel storedCredentialModel = null;
        for (int attempt = 0; attempt < 3 && storedCredentialModel == null; attempt++) {
            WebAuthnCredentialModel credentialModel = provider.getCredentialModelFromCredentialInput(
                    credentialInput,
                    attempt == 0 ? credentialLabel : makeUniqueLabel(credentialLabel, existingCredentialLabels(user))
            );
            try {
                storedCredentialModel = provider.createCredential(realm, user, credentialModel);
            } catch (ModelDuplicateException duplicateException) {
                // Retry once with a recalculated unique label in case concurrent writes happened.
            }
        }

        if (storedCredentialModel == null) {
            throw new IllegalStateException("Failed to store passkey credential");
        }
    }

    /**
     * Validates a WebAuthn assertion using Keycloak credential-manager validation.
     *
     * @param user target user
     * @param request authentication payload
     * @param credentialId resolved credential id
     * @return {@code true} when assertion is valid
     */
    boolean authenticatePasskey(ClientModel client, UserModel user, PasskeyRequest request, String credentialId) {
        RealmModel realm = requireRealm();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                decodeRequiredBase64Url(credentialId, "credentialId"),
                decodeRequiredBase64Url(request.getAuthenticatorData(), "authenticatorData"),
                decodeRequiredBase64Url(request.getClientDataJSON(), "clientDataJSON"),
                decodeRequiredBase64Url(request.getSignature(), "signature")
        );

        WebAuthnCredentialModelInput credentialInput = new WebAuthnCredentialModelInput(PASSKEY_TYPE);
        credentialInput.setAuthenticationRequest(authenticationRequest);
        credentialInput.setAuthenticationParameters(
                new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(
                        buildServerProperty(realm, client, request.getChallenge()),
                        isUserVerificationRequired(realm)
                )
        );

        return user.credentialManager().isValid(credentialInput);
    }

    /**
     * Parses and validates registration payload data.
     */
    private RegistrationData validateRegistration(RegistrationRequest request, RegistrationParameters parameters) {
        try {
            return WebAuthnRegistrationManager
                    .createNonStrictWebAuthnRegistrationManager(new ObjectConverter())
                    .verify(request, parameters);
        } catch (DataConversionException | VerificationException e) {
            throw new IllegalArgumentException("Passkey registration validation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Maps parsed registration data into Keycloak's credential input model.
     */
    private WebAuthnCredentialModelInput createCredentialInput(RegistrationData registrationData) {
        WebAuthnCredentialModelInput credentialInput = new WebAuthnCredentialModelInput(PASSKEY_TYPE);
        credentialInput.setAttestedCredentialData(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        credentialInput.setCount(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
        credentialInput.setAttestationStatementFormat(registrationData.getAttestationObject().getFormat());
        credentialInput.setTransports(registrationData.getTransports());
        return credentialInput;
    }

    /**
     * Builds a non-sensitive, unique-friendly passkey label for Keycloak credential storage.
     */
    private String buildCredentialLabel(UserModel user, PasskeyRequest request) {
        String requestedDeviceName = normalizeDeviceName(request.getDeviceName());
        String baseName = firstNonBlank(requestedDeviceName, DEFAULT_CREDENTIAL_LABEL);
        return makeUniqueLabel(baseName, existingCredentialLabels(user));
    }

    private String normalizeDeviceName(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().replaceAll("\\s+", " ");
        return normalized.isBlank() ? null : normalized;
    }

    private Set<String> existingCredentialLabels(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(PASSKEY_TYPE)
                .map(CredentialModel::getUserLabel)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toSet());
    }

    private String makeUniqueLabel(String requestedLabel, Set<String> existingLabels) {
        String normalizedBase = truncateLabel(requestedLabel);
        if (!existingLabels.contains(normalizedBase)) {
            return normalizedBase;
        }

        for (int counter = 2; counter < 5; counter++) {
            String candidate = truncateLabel(normalizedBase + " (" + counter + ")");
            if (!existingLabels.contains(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to find a unique passkey label");
    }

    private String truncateLabel(String label) {
        String normalized = firstNonBlank(normalizeDeviceName(label), DEFAULT_CREDENTIAL_LABEL);
        if (normalized.length() <= MAX_CREDENTIAL_LABEL_LENGTH) {
            return normalized;
        }
        return normalized.substring(0, MAX_CREDENTIAL_LABEL_LENGTH);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    /**
     * Resolves the passwordless WebAuthn credential provider.
     */
    private WebAuthnCredentialProvider getPasswordlessCredentialProvider() {
        WebAuthnCredentialProvider provider = (WebAuthnCredentialProvider) session.getProvider(
                CredentialProvider.class,
                WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID
        );
        if (provider == null) {
            throw new IllegalStateException("Passwordless WebAuthn credential provider is unavailable");
        }
        return provider;
    }

    /**
     * Constructs server property used by WebAuthn registration/authentication validation.
     */
    private ServerProperty buildServerProperty(RealmModel realm, ClientModel client, String challenge) {
        if (challenge == null || challenge.isBlank()) {
            throw new IllegalArgumentException("challenge is required");
        }
        if (client == null) {
            throw new IllegalStateException("OIDC client is required");
        }
        return new ServerProperty(
                resolveAllowedOrigins(realm, client),
                resolveRequiredRpId(realm),
                new DefaultChallenge(challenge),
                null
        );
    }

    /**
     * Resolves accepted origins from request origin and passwordless extra-origin policy entries.
     */
    private Set<Origin> resolveAllowedOrigins(RealmModel realm, ClientModel client) {
        WebAuthnPolicy policy = requirePasswordlessPolicy(realm);
        Set<Origin> origins = new HashSet<>();
        origins.add(new Origin(requireAllowedOrigin(client)));

        List<String> extraOrigins = policy.getExtraOrigins();
        if (extraOrigins == null) {
            return origins;
        }

        for (String extraOrigin : extraOrigins) {
            if (extraOrigin == null || extraOrigin.isBlank()) {
                continue;
            }
            String normalizedExtraOrigin = normalizeOrigin(extraOrigin.trim());
            origins.add(new Origin(normalizedExtraOrigin));
        }
        return origins;
    }

    /**
     * Extracts and validates the request {@code Origin} header against configured allowlist.
     */
    private String requireAllowedOrigin(ClientModel client) {
        var headers = session.getContext().getRequestHeaders();
        String originHeader = headers == null ? null : headers.getHeaderString(HEADER_ORIGIN);
        if (originHeader == null || originHeader.isBlank()) {
            throw new IllegalArgumentException("Origin header is required");
        }

        String origin = normalizeOrigin(originHeader.trim());
        if (!isAllowedOrigin(client, origin)) {
            throw new IllegalArgumentException("Origin is not allowed");
        }
        return origin;
    }

    private boolean isAllowedOrigin(ClientModel client, String origin) {
        Set<String> configuredWebOrigins = client.getWebOrigins();
        if (configuredWebOrigins == null || configuredWebOrigins.isEmpty()) {
            return false;
        }

        for (String configuredOrigin : configuredWebOrigins) {
            if (configuredOrigin == null || configuredOrigin.isBlank()) {
                continue;
            }
            String trimmedOrigin = configuredOrigin.trim();
            if (ANY_ORIGIN.equals(trimmedOrigin)) {
                return true;
            }
            if (WEB_ORIGIN_USE_REDIRECTS.equals(trimmedOrigin) && isOriginAllowedByRedirectUri(client, origin)) {
                return true;
            }
            try {
                if (normalizeOrigin(trimmedOrigin).equals(origin)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // Ignore non-origin entries and continue evaluation.
            }
        }

        return false;
    }

    private boolean isOriginAllowedByRedirectUri(ClientModel client, String origin) {
        if (RedirectUtils.verifyRedirectUri(session, origin, client) != null) {
            return true;
        }
        return RedirectUtils.verifyRedirectUri(session, origin + "/", client) != null;
    }

    /**
     * Normalizes and validates origin representation.
     */
    private String normalizeOrigin(String candidateOrigin) {
        try {
            String origin = UriUtils.getOrigin(candidateOrigin);
            if (origin == null || !UriUtils.isOrigin(origin)) {
                throw new IllegalArgumentException("Invalid origin: " + candidateOrigin);
            }
            return origin;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid origin: " + candidateOrigin, e);
        }
    }

    /**
     * Resolves RP ID from passwordless policy, falling back to base URI host.
     */
    private String resolveRequiredRpId(RealmModel realm) {
        WebAuthnPolicy policy = requirePasswordlessPolicy(realm);
        String fallbackRpId = session.getContext().getUri() == null || session.getContext().getUri().getBaseUri() == null
                ? null
                : session.getContext().getUri().getBaseUri().getHost();
        String configuredRpId = policy.getRpId();
        String rpId = (configuredRpId == null || configuredRpId.isBlank()) ? fallbackRpId : configuredRpId;
        if (rpId == null || rpId.isBlank()) {
            throw new IllegalStateException("Passwordless WebAuthn RP ID is not configured");
        }
        return rpId.trim();
    }

    /**
     * Determines whether user verification is mandatory for this realm policy.
     */
    private boolean isUserVerificationRequired(RealmModel realm) {
        String uvRequirement = requirePasswordlessPolicy(realm).getUserVerificationRequirement();
        return uvRequirement != null && "required".equalsIgnoreCase(uvRequirement);
    }

    /**
     * Returns passwordless WebAuthn policy or throws when absent.
     */
    private WebAuthnPolicy requirePasswordlessPolicy(RealmModel realm) {
        if (realm == null || realm.getWebAuthnPolicyPasswordless() == null) {
            throw new IllegalStateException("Passwordless WebAuthn policy is not configured");
        }
        return realm.getWebAuthnPolicyPasswordless();
    }

    /**
     * Decodes a required base64url field from client payload.
     */
    private byte[] decodeRequiredBase64Url(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        try {
            return Base64Url.decode(value);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(field + " must be a valid base64url value", e);
        }
    }

    /**
     * Decodes credential id into bytes, returning empty bytes on invalid input.
     */
    private byte[] credentialIdToBytes(String credentialId) {
        if (credentialId == null || credentialId.isBlank()) {
            return new byte[0];
        }

        try {
            return Base64Url.decode(credentialId);
        } catch (RuntimeException ignored) {
            return new byte[0];
        }
    }

    /**
     * Returns the current realm or throws when request context has none.
     */
    private RealmModel requireRealm() {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalStateException("Realm context is unavailable");
        }
        return realm;
    }

}
