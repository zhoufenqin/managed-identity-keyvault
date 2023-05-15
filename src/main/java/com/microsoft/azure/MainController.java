/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure;

import com.azure.identity.ManagedIdentityCredential;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import lombok.Data;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
public class MainController {

    private static final String defaultKeyVaultUrl = "https://integration-test-prodmsi.vault.azure.net";

    @PostMapping(path = "/secrets/get/{name}")
    public String getSecret(@PathVariable String name, @RequestBody TextNode kvUriNode) {
        String keyVaultUri = getKeyVaultUriOrDefault(kvUriNode);
        SecretClient secretClient = buildSecretClient(keyVaultUri, null);

        try {
            KeyVaultSecret secret = secretClient.getSecret(name);
            return String.format("Successfully got the value of secret %s from Key Vault %s: %s",
                name, defaultKeyVaultUrl, secret.getValue());
        } catch (Exception ex) {
            return String.format("Failed to get secret %s from Key Vault %s due to %s", name,
                defaultKeyVaultUrl, ex.getMessage());
        }
    }

    @PostMapping("/secrets/set/{name}/{value}")
    public String setSecret(@PathVariable String name, @PathVariable String value, @RequestBody TextNode kvUriNode) {
        String keyVaultUri = getKeyVaultUriOrDefault(kvUriNode);
        SecretClient secretClient = buildSecretClient(keyVaultUri, null);

        try {
            KeyVaultSecret secret = secretClient.setSecret(name, value);
            return String.format("Successfully set secret %s in Key Vault %s", name, defaultKeyVaultUrl);
        } catch (Exception ex) {
            return String.format("Failed to set secret %s in Key Vault %s due to %s", name,
                defaultKeyVaultUrl, ex.getMessage());
        }
    }

    @PostMapping("/secretsById/set/{name}/{clientId}/{value}")
    public String setSecretByClientId(@PathVariable String name, @PathVariable String clientId, @PathVariable String value, @RequestBody TextNode kvUriNode) {
        String keyVaultUri = getKeyVaultUriOrDefault(kvUriNode);
        SecretClient secretClient = buildSecretClient(keyVaultUri, clientId);

        try {
            KeyVaultSecret secret = secretClient.setSecret(name, value);
            return String.format("Successfully set secret %s in Key Vault %s", name, keyVaultUri);
        } catch (Exception ex) {
            return String.format("Failed to set secret %s in Key Vault %s due to %s", name,
                keyVaultUri, ex.getMessage());
        }
    }

    @PostMapping("/secretsById/get/{name}/{clientId}")
    public String getSecret(@PathVariable String name, @PathVariable String clientId, @RequestBody TextNode kvUriNode) {
        String keyVaultUri = getKeyVaultUriOrDefault(kvUriNode);
        SecretClient secretClient = buildSecretClient(keyVaultUri, clientId);

        try {
            KeyVaultSecret secret = secretClient.getSecret(name);
            return String.format("Successfully got the value of secret %s from Key Vault %s: %s",
                    name, keyVaultUri, secret.getValue());
        } catch (Exception ex) {
            return String.format("Failed to get secret %s from Key Vault %s due to %s", name,
                keyVaultUri, ex.getMessage());
        }
    }

    private String getKeyVaultUriOrDefault(TextNode kvUriNode) {
        String uri = defaultKeyVaultUrl;

        if (kvUriNode != null && StringUtils.isNotBlank(kvUriNode.getKeyVaultUri()))
        {
            uri = kvUriNode.getKeyVaultUri();
        }

        return uri;
    }

    private SecretClient buildSecretClient(String keyVaultUri, @Nullable String clientId) {
        ManagedIdentityCredential managedIdentityCredential = new ManagedIdentityCredentialBuilder()
            .maxRetry(1)
            .clientId(clientId)
            .retryTimeout(duration -> Duration.ofMinutes(1))
            .build();

        return new SecretClientBuilder()
            .vaultUrl(keyVaultUri)
            .credential(managedIdentityCredential)
            .buildClient();
    }

    @Data
    private static class TextNode {
        public String keyVaultUri;
    }
}
