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

import com.google.auth.Credentials;
import com.google.cloud.http.HttpTransportOptions;
import com.google.cloud.storage.Storage;

import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.test.ESTestCase;
import org.hamcrest.Matchers;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Locale;

public class GoogleCloudStorageServiceTests extends ESTestCase {

    public void testClientInitializer() throws GeneralSecurityException, IOException {
        final String clientName = randomAlphaOfLength(4).toLowerCase(Locale.ROOT);
        final TimeValue connectTimeValue = TimeValue.timeValueNanos(randomIntBetween(0, 2000000));
        final TimeValue readTimeValue = TimeValue.timeValueNanos(randomIntBetween(0, 2000000));
        final String applicationName = randomAlphaOfLength(4);
        final String hostName = randomAlphaOfLength(4);
        final String projectIdName = randomAlphaOfLength(4);
        final Settings settings = Settings.builder()
                .put(GoogleCloudStorageClientSettings.CONNECT_TIMEOUT_SETTING.getConcreteSettingForNamespace(clientName).getKey(), connectTimeValue.getStringRep())
                .put(GoogleCloudStorageClientSettings.READ_TIMEOUT_SETTING.getConcreteSettingForNamespace(clientName).getKey(), readTimeValue.getStringRep())
                .put(GoogleCloudStorageClientSettings.APPLICATION_NAME_SETTING.getConcreteSettingForNamespace(clientName).getKey(), applicationName)
                .put(GoogleCloudStorageClientSettings.HOST_SETTING.getConcreteSettingForNamespace(clientName).getKey(), hostName)
                .put(GoogleCloudStorageClientSettings.PROJECT_ID_SETTING.getConcreteSettingForNamespace(clientName).getKey(), projectIdName)
                .build();
        final GoogleCloudStorageService service = new GoogleCloudStorageService(settings);
        final IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> service.client("another_client"));
        assertThat(e.getMessage(), Matchers.startsWith("Unknown client name"));
        assertSettingDeprecationsAndWarnings(
                new Setting<?>[] { GoogleCloudStorageClientSettings.APPLICATION_NAME_SETTING.getConcreteSettingForNamespace(clientName) });
        final Storage storage = service.client(clientName);
        assertThat(storage.getOptions().getApplicationName(), Matchers.containsString(applicationName));
        assertThat(storage.getOptions().getHost(), Matchers.is(hostName));
        assertThat(storage.getOptions().getProjectId(), Matchers.is(projectIdName));
        assertThat(storage.getOptions().getTransportOptions(), Matchers.instanceOf(HttpTransportOptions.class));
        assertThat(((HttpTransportOptions) storage.getOptions().getTransportOptions()).getConnectTimeout(),
                Matchers.is((int) connectTimeValue.millis()));
        assertThat(((HttpTransportOptions) storage.getOptions().getTransportOptions()).getReadTimeout(),
                Matchers.is((int) readTimeValue.millis()));
        assertThat(storage.getOptions().getCredentials(), Matchers.nullValue(Credentials.class));
    }

}
