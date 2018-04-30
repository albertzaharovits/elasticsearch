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

import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.ReInitializablePlugin;
import org.elasticsearch.plugins.RepositoryPlugin;
import org.elasticsearch.repositories.Repository;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class GoogleCloudStoragePlugin extends Plugin implements RepositoryPlugin, ReInitializablePlugin {

    private final GoogleCloudStorageService gcsStoreService;

    public GoogleCloudStoragePlugin(Settings settings) {
        // eagerly load client settings so that secure settings are read
        this.gcsStoreService = createGoogleCloudStorageService(settings);
    }

    protected GoogleCloudStorageService createGoogleCloudStorageService(Settings settings) {
        return new GoogleCloudStorageService(settings);
    }

    @Override
    public Map<String, Repository.Factory> getRepositories(Environment env, NamedXContentRegistry namedXContentRegistry) {
        return Collections.singletonMap(GoogleCloudStorageRepository.TYPE,
                (metadata) -> new GoogleCloudStorageRepository(metadata, env, namedXContentRegistry, gcsStoreService));
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
            GoogleCloudStorageClientSettings.CREDENTIALS_FILE_SETTING,
            GoogleCloudStorageClientSettings.ENDPOINT_SETTING,
            GoogleCloudStorageClientSettings.HOST_SETTING,
            GoogleCloudStorageClientSettings.PROJECT_ID_SETTING,
            GoogleCloudStorageClientSettings.CONNECT_TIMEOUT_SETTING,
            GoogleCloudStorageClientSettings.READ_TIMEOUT_SETTING,
            GoogleCloudStorageClientSettings.APPLICATION_NAME_SETTING);
    }

    @Override
    public boolean reinit(Settings settings) {
        // secure settings should be readable
        final Map<String, GoogleCloudStorageClientSettings> clientSettings = GoogleCloudStorageClientSettings.load(settings);
        this.gcsStoreService.updateClientsSettings(clientSettings);
        return true;
    }
}
