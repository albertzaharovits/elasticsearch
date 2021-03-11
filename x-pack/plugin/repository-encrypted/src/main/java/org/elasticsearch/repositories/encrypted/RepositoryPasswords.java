/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.repositories.encrypted;

import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;

import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.elasticsearch.repositories.encrypted.EncryptedRepositoryPlugin.ENCRYPTION_PASSWORD_SETTING;

public class RepositoryPasswords {
    static final Setting<String> PASSWORD_NAME_SETTING = Setting.simpleString("password_name", "");
    static final Setting<String> NEW_PASSWORD_NAME_SETTING = Setting.simpleString("new_password_name", "");
    static final Setting<String> PASSWORD_CHANGE_LOCK_SETTING = Setting.simpleString("password_change_lock", "");

    // all the repository password values pulled from the local node's keystore
    private final Map<String, SecureString> repositoryPasswordsMap;
    private final Map<String, String> repositoryPasswordValidatedTagsMap;

    // this is the in-use password, which is always set, but can change
    private volatile String currentPasswordName;
    // these are only set when a password change is in progress (and must be set together)
    private @Nullable volatile String newPasswordName;
    private @Nullable volatile String passwordChangeLock;

    public RepositoryPasswords(Map<String, SecureString> repositoryPasswordsMap, Settings repositorySettings) {
        this.repositoryPasswordsMap = Map.copyOf(repositoryPasswordsMap);
        this.repositoryPasswordValidatedTagsMap = new ConcurrentHashMap<>(repositoryPasswordsMap.size());
        settingsUpdate(repositorySettings);
    }

    /** This method is used to change the in-use password of the snapshot repository.
     * Changing the currently in-use password uses a transitory state where both the old and the new passwords are simultaneously set.
     */
    public void settingsUpdate(Settings repositorySettings) {
        String passwordName = PASSWORD_NAME_SETTING.get(repositorySettings);
        if (Strings.hasLength(passwordName) == false) {
            throw new IllegalArgumentException("Repository setting [" + PASSWORD_NAME_SETTING.getKey() + "] must be set");
        }
        if (false == repositoryPasswordsMap.containsKey(passwordName)) {
            throw new IllegalArgumentException(
                    "Secure setting ["
                            + ENCRYPTION_PASSWORD_SETTING.getConcreteSettingForNamespace(passwordName).getKey()
                            + "] must be set"
            );
        }
        String newPasswordName = NEW_PASSWORD_NAME_SETTING.get(repositorySettings);
        String passwordChangeLock = PASSWORD_CHANGE_LOCK_SETTING.get(repositorySettings);
        if (Strings.hasLength(newPasswordName) && false == Strings.hasLength(passwordChangeLock)) {
            throw new IllegalArgumentException("Repository setting [" + NEW_PASSWORD_NAME_SETTING.getKey() + "] is set" +
                    " but [" + PASSWORD_CHANGE_LOCK_SETTING.getKey() + "] is not, but they must be set together.");
        }
        if (false == Strings.hasLength(newPasswordName) && Strings.hasLength(passwordChangeLock)) {
            throw new IllegalArgumentException("Repository setting [" + PASSWORD_CHANGE_LOCK_SETTING.getKey() + "] is set" +
                    " but [" + NEW_PASSWORD_NAME_SETTING.getKey() + "] is not, but they must be set together.");
        }
        if (Strings.hasLength(newPasswordName) && Strings.hasLength(passwordChangeLock)) {
            // a password change is in progress
            if (false == repositoryPasswordsMap.containsKey(newPasswordName)) {
                throw new IllegalArgumentException(
                        "Secure setting ["
                                + ENCRYPTION_PASSWORD_SETTING.getConcreteSettingForNamespace(newPasswordName).getKey()
                                + "] not set"
                );
            }
            this.newPasswordName = newPasswordName;
            this.passwordChangeLock = passwordChangeLock;
        } else {
            this.newPasswordName = null;
            this.passwordChangeLock = null;
        }
        this.currentPasswordName = passwordName;
    }

    public boolean isPasswordChangeInProgress() {
        assert (newPasswordName != null && passwordChangeLock != null) ||
                (newPasswordName == null && passwordChangeLock == null);
        return newPasswordName != null && passwordChangeLock != null;
    }

    public String getCurrentPasswordName() {
        return currentPasswordName;
    }

    public @Nullable String getNewPasswordName() {
        return newPasswordName;
    }

    public String getPasswordTag(String passwordName) throws GeneralSecurityException {
        String validatedPasswordTag = repositoryPasswordValidatedTagsMap.get(passwordName);
        if (validatedPasswordTag != null) {
            return validatedPasswordTag;
        }
        // unique salt for every tag
        String salt = UUIDs.randomBase64UUID();
        return computeTagForLocalPassword(passwordName, salt);
    }

    public boolean validatePasswordTag(String passwordName, String passwordTag) throws IllegalArgumentException, GeneralSecurityException {
        String previouslyValidatedPasswordTag = repositoryPasswordValidatedTagsMap.get(passwordName);
        if (passwordTag.equals(previouslyValidatedPasswordTag)) {
            // tag has been previously validated
            return true;
        }
        // unseen (or invalid) tag for the given password
        SecureString repositoryPassword = repositoryPasswordsMap.get(passwordName);
        if (repositoryPassword == null) {
            throw new IllegalArgumentException(
                    "Secure setting ["
                            + ENCRYPTION_PASSWORD_SETTING.getConcreteSettingForNamespace(passwordName).getKey()
                            + "] not set"
            );
        }
        String[] saltAndHash = passwordTag.split(":");
        if (saltAndHash == null || saltAndHash.length != 2) {
            throw new IllegalArgumentException("Unrecognized format for repository password tag");
        }
        String computedPasswordTag = computeTagForLocalPassword(passwordName, saltAndHash[0]);
        if (false == passwordTag.equals(computedPasswordTag)) {
            return false;
        }
        repositoryPasswordValidatedTagsMap.put(passwordName, computedPasswordTag);
        return true;
    }

    private String computeTagForLocalPassword(String passwordName, String salt) throws GeneralSecurityException {
        SecureString repositoryPassword = repositoryPasswordsMap.get(passwordName);
        if (repositoryPassword == null) {
            throw new IllegalArgumentException(
                    "Secure setting ["
                            + ENCRYPTION_PASSWORD_SETTING.getConcreteSettingForNamespace(passwordName).getKey()
                            + "] not set"
            );
        }
        // the "hash" of the repository password from the local node is not actually a hash but the ciphertext of a
        // known-plaintext using a key derived from the repository password using a random salt
        String localRepositoryPasswordHash = AESKeyUtils.computeId(
                AESKeyUtils.generatePasswordBasedKey(repositoryPassword, salt)
        );
        return salt + ":" + localRepositoryPasswordHash;
    }

}
