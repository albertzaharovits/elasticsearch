/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.watcher.notification;

import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.SecureSetting;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * Basic notification service
 */
public abstract class NotificationService<Account> {

    private final String type;
    private final BiFunction<String, Settings, Account> accountFactory;
    // both are guarded by this
    private Map<String, Account> accounts;
    private Account defaultAccount;

    public NotificationService(String type, Settings settings, ClusterSettings clusterSettings, List<Setting<?>> pluginSettings,
            BiFunction<String, Settings, Account> accountFactory) {
        this(type, accountFactory);
        final List<Setting<?>> dynamicPluginSettings = pluginSettings.stream().filter(s -> s.isDynamic() && s.hasNodeScope())
                .collect(Collectors.toList()); 
        final List<Setting<?>> securePluginSettings = pluginSettings.stream().filter(s -> s instanceof SecureSetting<?>)
                .collect(Collectors.toList());
        clusterSettings.addSettingsUpdateConsumer(this::reload, dynamicPluginSettings);
    }

    // Used for testing only
    NotificationService(String type, BiFunction<String, Settings, Account> accountFactory) {
        this.type = type;
        this.accountFactory = accountFactory;
    }

    public synchronized void reload(Settings settings) {
        // settings has new secure settings but all the other are those from config file 
        buildAccounts(settings, this.accountFactory);
    }

    public Account getAccount(String name) {
        // note this is not final since we mock it in tests and that causes
        // trouble since final methods can't be mocked...
        final Map<String, Account> accounts;
        final Account defaultAccount;
        synchronized (this) { // must read under sync block otherwise it might be inconsistent
            accounts = this.accounts;
            defaultAccount = this.defaultAccount;
        }
        Account theAccount = accounts.getOrDefault(name, defaultAccount);
        if (theAccount == null && name == null) {
            throw new IllegalArgumentException("no accounts of type [" + type + "] configured. " +
                    "Please set up an account using the [xpack.notification." + type +"] settings");
        }
        if (theAccount == null) {
            throw new IllegalArgumentException("no account found for name: [" + name + "]");
        }
        return theAccount;
    }

    private void buildAccounts(Settings settings, BiFunction<String, Settings, Account> accountFactory) {
        Settings accountsSettings = settings.getByPrefix("xpack.notification." + type + ".").getAsSettings("account");
        Map<String, Account> accounts = new HashMap<>();
        for (String name : accountsSettings.names()) {
            Settings accountSettings = accountsSettings.getAsSettings(name);
            Account account = accountFactory.apply(name, accountSettings);
            accounts.put(name, account);
        }
        final String defaultAccountName = settings.get("xpack.notification." + type + ".default_account");
        Account defaultAccount;
        if (defaultAccountName == null) {
            if (accounts.isEmpty()) {
                defaultAccount = null;
            } else {
                Account account = accounts.values().iterator().next();
                defaultAccount = account;
            }
        } else {
            defaultAccount = accounts.get(defaultAccountName);
            if (defaultAccount == null) {
                throw new SettingsException("could not find default account [" + defaultAccountName + "]");
            }
        }
        synchronized (this) {
            this.accounts = Collections.unmodifiableMap(accounts);
            this.defaultAccount = defaultAccount;
        }
    }
}
