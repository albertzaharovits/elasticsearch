/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.plugins;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.indices.SystemIndexDescriptor;

import java.util.Collection;
import java.util.Collections;

/**
 * Plugin for defining system indices. Extends {@link ActionPlugin} because system indices must be accessed via APIs
 * added by the plugin that owns the system index, rather than standard APIs.
 */
public interface SystemIndexPlugin extends ActionPlugin {

    /**
     * Returns a {@link Collection} of {@link SystemIndexDescriptor}s that describe this plugin's system indices, including
     * name, mapping, and settings.
     * @param settings The node's settings
     * @return Descriptions of the system indices managed by this plugin.
     */
    default Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        return Collections.emptyList();
    }

    /**
     * @return The name of the feature, as used for specifying feature states in snapshot creation and restoration.
     */
    String getFeatureName();

    /**
     * @return A description of the feature, as used for the Get Snapshottable Features API.
     */
    String getFeatureDescription();

    /**
     * Returns a list of index patterns for "associated indices": indices which depend on this plugin's system indices, but are not
     * themselves system indices.
     *
     * @return A list of index patterns which depend on the contents of this plugin's system indices, but are not themselves system indices
     */
    default Collection<String> getAssociatedIndexPatterns() {
        return Collections.emptyList();
    }
}
