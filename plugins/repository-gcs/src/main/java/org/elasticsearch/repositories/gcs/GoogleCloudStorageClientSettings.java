/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.elasticsearch.repositories.gcs;

import com.google.api.client.googleapis.GoogleUtils;
import com.google.api.client.http.javanet.DefaultConnectionFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.gax.retrying.RetrySettings;
import com.google.api.services.storage.StorageScopes;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.http.HttpTransportOptions;
import com.google.cloud.storage.StorageOptions;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.common.settings.SecureSetting;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.threeten.bp.Duration;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.elasticsearch.common.settings.Setting.timeSetting;

/**
 * Container for Google Cloud Storage clients settings.
 */
public class GoogleCloudStorageClientSettings {

    private static final String PREFIX = "gcs.client.";

    /** A json Service Account file loaded from secure settings. */
    static final Setting.AffixSetting<InputStream> CREDENTIALS_FILE_SETTING = Setting.affixKeySetting(PREFIX, "credentials_file",
            key -> SecureSetting.secureFile(key, null));

    /**
     * An override for the Storage endpoint to connect to. Deprecated, use host
     * setting.
     */
    static final Setting.AffixSetting<String> ENDPOINT_SETTING = Setting.affixKeySetting(PREFIX, "endpoint",
            key -> Setting.simpleString(key, Setting.Property.NodeScope, Setting.Property.Deprecated));

    /** An override for the Storage host name to connect to. */
    static final Setting.AffixSetting<String> HOST_SETTING = Setting.affixKeySetting(PREFIX, "host",
            key -> {
                // falback to the deprecated setting
                if (key.endsWith("host")) {
                    return Setting.simpleString(key,
                            ENDPOINT_SETTING.getConcreteSetting(key.substring(0, key.length() - "host".length()) + "endpoint"),
                            Setting.Property.NodeScope);
                } else {
                    return Setting.simpleString(key, Setting.Property.NodeScope);
                }
            });

    /** An override for the Google Project ID. */
    static final Setting.AffixSetting<String> PROJECT_ID_SETTING = Setting.affixKeySetting(PREFIX, "project_id",
            key -> Setting.simpleString(key, Setting.Property.NodeScope));

    /**
     * The timeout to establish a connection. A value of {@code -1} corresponds to an infinite timeout. A value of {@code 0}
     * corresponds to the default timeout of the Google Cloud Storage Java Library.
     */
    static final Setting.AffixSetting<TimeValue> CONNECT_TIMEOUT_SETTING = Setting.affixKeySetting(PREFIX, "connect_timeout",
        key -> timeSetting(key, TimeValue.ZERO, TimeValue.MINUS_ONE, Setting.Property.NodeScope));

    /**
     * The timeout to read data from an established connection. A value of {@code -1} corresponds to an infinite timeout. A value of
     * {@code 0} corresponds to the default timeout of the Google Cloud Storage Java Library.
     */
    static final Setting.AffixSetting<TimeValue> READ_TIMEOUT_SETTING = Setting.affixKeySetting(PREFIX, "read_timeout",
        key -> timeSetting(key, TimeValue.ZERO, TimeValue.MINUS_ONE, Setting.Property.NodeScope));

    /** Name used by the client when it uses the Google Cloud JSON API. **/
    static final Setting.AffixSetting<String> APPLICATION_NAME_SETTING = Setting.affixKeySetting(PREFIX, "application_name",
            key -> new Setting<>(key, "elasticsearch-repository-gcs", Function.identity(), Setting.Property.NodeScope,
                    Setting.Property.Deprecated));

    private static final RetrySettings retrySettings;
    private static final NetHttpTransport netHttpTransport;

    static {
        retrySettings = RetrySettings.newBuilder()
                .setInitialRetryDelay(Duration.ofMillis(100))
                .setMaxRetryDelay(Duration.ofMillis(6000))
                .setTotalTimeout(Duration.ofMillis(900000))
                .setRetryDelayMultiplier(1.5d)
                .setJittered(true)
                .build();
        try {
            netHttpTransport = new NetHttpTransport.Builder().trustCertificates(GoogleUtils.getCertificateTrustStore())
                    .setConnectionFactory(new DefaultConnectionFactory()) // be explicit about connection factory to assure
                                                                          // thread-safetiness
                    .build();
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** The credentials used by the client to connect to the Storage endpoint **/
    private final ServiceAccountCredentials credential;

    /**
     * The Storage root URL (hostname) the client should talk to, or null string to
     * use the default.
     **/
    private final String host;

    /**
     * The Google project ID overriding the default way to infer it. Null value sets
     * the default.
     **/
    private final String projectId;

    /** The timeout to establish a connection **/
    private final TimeValue connectTimeout;

    /** The timeout to read data from an established connection **/
    private final TimeValue readTimeout;

    /** The Storage client application name **/
    private final String applicationName;

    private transient StorageOptions storageOptions;

    GoogleCloudStorageClientSettings(final ServiceAccountCredentials credential, final String host, final String projectId,
            final TimeValue connectTimeout, final TimeValue readTimeout, final String applicationName) {
        this.credential = credential;
        this.host = host;
        this.projectId = projectId;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.applicationName = applicationName;
        this.storageOptions = null;
    }

    private StorageOptions buildStorageOptions() throws IOException {
        final HttpTransportOptions httpTransportOptions = HttpTransportOptions.newBuilder()
                .setConnectTimeout(toTimeout(getConnectTimeout()))
                .setReadTimeout(toTimeout(getReadTimeout()))
                .setHttpTransportFactory(() -> netHttpTransport)
                .build();
        final StorageOptions.Builder storageOptionsBuilder = StorageOptions.newBuilder()
                .setRetrySettings(retrySettings)
                .setTransportOptions(httpTransportOptions)
                .setHeaderProvider(() -> {
                    final MapBuilder<String, String> mapBuilder = MapBuilder.newMapBuilder();
                    if (Strings.hasLength(getApplicationName())) {
                        mapBuilder.put("user-agent", getApplicationName());
                    }
                    return mapBuilder.immutableMap();
                });
        if (Strings.hasLength(getHost())) {
            storageOptionsBuilder.setHost(getHost());
        }
        if (getCredential() != null) {
            storageOptionsBuilder.setCredentials(getCredential());
        }
        if (Strings.hasLength(getProjectId())) {
            storageOptionsBuilder.setProjectId(getProjectId());
        }
        return SocketAccess.doPrivilegedIOException(() -> storageOptionsBuilder.build());
    }

    public StorageOptions getStorageOptions() throws IOException {
        if (this.storageOptions == null) {
            this.storageOptions = buildStorageOptions();
        }
        return this.storageOptions;
    }

    ServiceAccountCredentials getCredential() {
        return credential;
    }

    String getHost() {
        return host;
    }

    String getProjectId() {
        return Strings.hasLength(projectId) ? projectId : (credential != null ? credential.getProjectId() : null);
    }

    TimeValue getConnectTimeout() {
        return connectTimeout;
    }

    TimeValue getReadTimeout() {
        return readTimeout;
    }

    String getApplicationName() {
        return applicationName;
    }

    public static Map<String, GoogleCloudStorageClientSettings> load(final Settings settings) {
        final Map<String, GoogleCloudStorageClientSettings> clients = new HashMap<>();
        for (final String clientName: settings.getGroups(PREFIX).keySet()) {
            clients.put(clientName, getClientSettings(settings, clientName));
        }
        if (clients.containsKey("default") == false) {
            // this won't find any settings under the default client,
            // but it will pull all the fallback static settings
            clients.put("default", getClientSettings(settings, "default"));
        }
        return Collections.unmodifiableMap(clients);
    }

    static GoogleCloudStorageClientSettings getClientSettings(final Settings settings, final String clientName) {
            return new GoogleCloudStorageClientSettings(loadCredential(settings, clientName),
                    getConfigValue(settings, clientName, HOST_SETTING),
                    getConfigValue(settings, clientName, PROJECT_ID_SETTING),
                    getConfigValue(settings, clientName, CONNECT_TIMEOUT_SETTING),
                    getConfigValue(settings, clientName, READ_TIMEOUT_SETTING),
                    getConfigValue(settings, clientName, APPLICATION_NAME_SETTING));
    }

    /**
     * Loads the service account file corresponding to a given client name. If no
     * file is defined for the client, a {@code null} credential is returned.
     *
     * @param settings
     *            the {@link Settings}
     * @param clientName
     *            the client name
     *
     * @return the {@link ServiceAccountCredentials} to use for the given client,
     *         {@code null} if no service account is defined.
     * @throws IOException
     */
    static ServiceAccountCredentials loadCredential(final Settings settings, final String clientName) {
        try {
            if (CREDENTIALS_FILE_SETTING.getConcreteSettingForNamespace(clientName).exists(settings) == false) {
                // explicitly returning null here so that the default credential
                // can be loaded later when creating the Storage client
                return null;
            }
            try (InputStream credStream = CREDENTIALS_FILE_SETTING.getConcreteSettingForNamespace(clientName).get(settings)) {
                final Collection<String> scopes = Collections.singleton(StorageScopes.DEVSTORAGE_FULL_CONTROL);
                return SocketAccess.doPrivilegedIOException(() -> {
                    final ServiceAccountCredentials credentials = ServiceAccountCredentials.fromStream(credStream);
                    if (credentials.createScopedRequired()) {
                        return (ServiceAccountCredentials) credentials.createScoped(scopes);
                    }
                    return credentials;
                });
            }
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static <T> T getConfigValue(final Settings settings, final String clientName, final Setting.AffixSetting<T> clientSetting) {
        final Setting<T> concreteSetting = clientSetting.getConcreteSettingForNamespace(clientName);
        return concreteSetting.get(settings);
    }

    /**
     * Converts timeout values from the settings to a timeout value for the Google
     * Cloud SDK
     **/
    static Integer toTimeout(TimeValue timeout) {
        // Null or zero in settings means the default timeout
        if ((timeout == null) || TimeValue.ZERO.equals(timeout)) {
            // negative value means using the default value
            return -1;
        }
        // -1 means infinite timeout
        if (TimeValue.MINUS_ONE.equals(timeout)) {
            // 0 is the infinite timeout expected by Google Cloud SDK
            return 0;
        }
        return Math.toIntExact(timeout.getMillis());
    }
}
