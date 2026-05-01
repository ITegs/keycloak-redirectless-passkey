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
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class PasskeyWebAuthnService {

    private static final Logger logger = Logger.getLogger(PasskeyWebAuthnService.class);
    private static final String PASSKEY_TYPE = WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    private static final String CREDENTIAL_USER_ATTR = "passkey-credential-id";
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
     * Resolves credential identifier from request fields.
     *
     * @param request passkey request payload
     * @return credential id, preferring {@code credentialId} over {@code rawId}
     */
    String resolveCredentialId(PasskeyRequest request) {
        String credentialId = request.getCredentialId();
        if (credentialId != null && !credentialId.isBlank()) {
            return credentialId;
        }
        String rawId = request.getRawId();
        return (rawId == null || rawId.isBlank()) ? null : rawId;
    }

    /**
     * Finds a user for an authentication request.
     * <p>
     * Prefer WebAuthn's userHandle because LDAP-backed users may be read-only and cannot store
     * the local helper attribute. The attribute and full credential scan are compatibility fallbacks.
     *
     * @param realm current realm
     * @param request passkey request payload
     * @param credentialId credential id from client
     * @return matching user or {@code null} when none exists
     */
    UserModel findUserByCredentialId(RealmModel realm, PasskeyRequest request, String credentialId) {
        UserModel userFromHandle = findUserByUserHandle(realm, request == null ? null : request.getUserHandle());
        if (userFromHandle != null) {
            return userFromHandle;
        }

        String normalizedCredentialId = normalizeCredentialId(credentialId);
        if (normalizedCredentialId == null) {
            return null;
        }

        UserModel userFromAttribute = session.users()
                .searchForUserByUserAttributeStream(realm, CREDENTIAL_USER_ATTR, normalizedCredentialId)
                .findFirst()
                .orElse(null);
        if (userFromAttribute != null) {
            return userFromAttribute;
        }

        return findUserByStoredCredential(realm, credentialId);
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
        WebAuthnCredentialModel credentialModel = provider.getCredentialModelFromCredentialInput(credentialInput, user.getUsername());
        CredentialModel storedCredentialModel = provider.createCredential(realm, user, credentialModel);
        if (storedCredentialModel == null) {
            throw new IllegalStateException("Failed to store passkey credential");
        }
        WebAuthnCredentialModel storedCredential = WebAuthnCredentialModel.createFromCredentialModel(storedCredentialModel);
        if (storedCredential.getWebAuthnCredentialData() != null) {
            storeCredentialUserMapping(user, storedCredential.getWebAuthnCredentialData().getCredentialId());
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
     * Converts arbitrary credential id input into canonical base64url form.
     */
    private String normalizeCredentialId(String credentialId) {
        byte[] credentialBytes = credentialIdToBytes(credentialId);
        if (credentialBytes.length == 0) {
            return null;
        }
        return Base64Url.encode(credentialBytes);
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
     * Resolves a user from the WebAuthn userHandle. Keycloak's native passwordless flow uses the
     * user id, while older sample clients in this project used the username.
     */
    private UserModel findUserByUserHandle(RealmModel realm, String userHandle) {
        String decodedUserHandle = decodeUserHandle(userHandle);
        if (decodedUserHandle == null) {
            return null;
        }

        UserModel user = session.users().getUserById(realm, decodedUserHandle);
        if (user != null) {
            return user;
        }
        return session.users().getUserByUsername(realm, decodedUserHandle);
    }

    private String decodeUserHandle(String userHandle) {
        if (userHandle == null || userHandle.isBlank()) {
            return null;
        }

        try {
            String decoded = new String(Base64Url.decode(userHandle), StandardCharsets.UTF_8);
            return decoded.isBlank() ? null : decoded;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private UserModel findUserByStoredCredential(RealmModel realm, String credentialId) {
        try {
            return session.users()
                    .searchForUserStream(realm, Map.of(), null, null)
                    .filter(user -> hasPasskeyCredential(user, credentialId))
                    .findFirst()
                    .orElse(null);
        } catch (RuntimeException e) {
            logger.warn("Passkey user lookup by stored credential failed: " + e.getMessage(), e);
            return null;
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

    /**
     * Persists credential-to-user mapping used by direct credential-id lookup.
     */
    private void storeCredentialUserMapping(UserModel user, String credentialId) {
        String normalizedCredentialId = normalizeCredentialId(credentialId);
        if (normalizedCredentialId == null) {
            return;
        }

        List<String> values = new ArrayList<>(user.getAttributeStream(CREDENTIAL_USER_ATTR).toList());
        if (!values.contains(normalizedCredentialId)) {
            values.add(normalizedCredentialId);
            try {
                user.setAttribute(CREDENTIAL_USER_ATTR, values);
            } catch (RuntimeException e) {
                logger.warn("Could not store passkey credential mapping on user attribute; falling back to userHandle-based lookup: " + e.getMessage(), e);
            }
        }
    }
}
