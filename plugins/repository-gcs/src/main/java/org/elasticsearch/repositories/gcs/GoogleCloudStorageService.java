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

import com.google.cloud.storage.Storage;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.settings.Settings;

import java.util.Map;

import static java.util.Collections.emptyMap;

public class GoogleCloudStorageService extends AbstractComponent {

    /** Clients settings identified by client name. */
    volatile Map<String, GoogleCloudStorageClientSettings> storageSettings = emptyMap();

    public GoogleCloudStorageService(Settings settings) {
        super(settings);
        // eagerly load client settings so that secure settings are read
        final Map<String, GoogleCloudStorageClientSettings> clientSettings = GoogleCloudStorageClientSettings.load(settings);
        updateClientsSettings(clientSettings);
    }

    /**
     * Creates a client that can be used to manage Google Cloud Storage objects.
     *
     * @param clientName
     *            name of client settings to use from secure settings
     * @return a Client instance that can be used to manage Storage objects
     */
    public Storage client(String clientName) {
        final GoogleCloudStorageClientSettings clientSettings = this.storageSettings.get(clientName);
        if (clientSettings == null) {
            throw new IllegalArgumentException("Unknown client name [" + clientName + "]. Existing client configs: "
                    + Strings.collectionToDelimitedString(storageSettings.keySet(), ","));
        }
        // builds and caches client
        return clientSettings.getStorageOptions().getService();
    }

    /**
     * Updates settings for building clients. Future client requests will use the
     * new settings.
     *
     * @param clientsSettings
     *            the new settings
     * @return the old settings
     */
    Map<String, GoogleCloudStorageClientSettings> updateClientsSettings(Map<String, GoogleCloudStorageClientSettings> clientsSettings) {
        final Map<String, GoogleCloudStorageClientSettings> prevSettings = this.storageSettings;
        this.storageSettings = MapBuilder.newMapBuilder(clientsSettings).immutableMap();
        return prevSettings;
    }

}
