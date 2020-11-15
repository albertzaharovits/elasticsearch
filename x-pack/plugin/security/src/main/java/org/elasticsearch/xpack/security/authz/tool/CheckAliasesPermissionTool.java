/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.tool;

import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.get.GetAction;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.LoggingAwareCommand;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.DataStream;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.Index;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentPermissions;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissionsCache;
import org.elasticsearch.xpack.core.security.authz.permission.IndicesPermission;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;
import org.elasticsearch.xpack.security.authz.AuthorizationService;
import org.opensaml.xmlsec.signature.P;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

public class CheckAliasesPermissionTool extends LoggingAwareCommand {

    final OptionSpec<String> allRolesPathSpec;
    final OptionSpec<String> allAliasesPathSpec;
    final OptionSpec<String> allIndexSettingsPathSpec;
    final OptionSpec<String> diagnosticPathSpec;

    public CheckAliasesPermissionTool() {
        super("Given the index-alias association, as well as the security roles, tell which roles grant more privileges on the alias " +
                "than on the pointed to indices");
        allRolesPathSpec =
                parser.accepts("roles", "path to the input file containing all the security roles in the cluster").withRequiredArg();
        allAliasesPathSpec =
                parser.accepts("aliases", "path to the input file containing all the aliases in the cluster").withRequiredArg();
        allIndexSettingsPathSpec =
                parser.accepts("settings", "path to the input file containing the index settings").withRequiredArg();
        diagnosticPathSpec =
                parser.accepts("diagnostic",
                        "path to the diagnostic of the cluster, i.e. the unzipped output dir of the 'diagnostic.sh' utility")
                        .withRequiredArg();
    }

    public static void main(String[] args) throws Exception {
        exit(new CheckAliasesPermissionTool().main(args, Terminal.DEFAULT));
    }

    @Override
    protected void execute(Terminal terminal, OptionSet options) throws Exception {
        final Path allRolesPath;
        final Path allAliasesPath;
        final Path allIndexSettingsPath;
        if (false == (options.has(diagnosticPathSpec) || options.has(allRolesPathSpec) || options.has(allAliasesPathSpec) ||
                options.has(allIndexSettingsPathSpec))) {
            throw new UserException(ExitCodes.CONFIG, "No option specified. Try specifying the diagnostic dir path option.");
        } else if (options.has(diagnosticPathSpec)) {
            if (options.has(allRolesPathSpec) || options.has(allAliasesPathSpec) || options.has(allIndexSettingsPathSpec)) {
                throw new UserException(ExitCodes.CONFIG, "The diagnostic dir path option cannot be used in conjunction with the " +
                        "other options.");
            }
            Path allRolesPath1 = Path.of(diagnosticPathSpec.value(options)).resolve("commercial").resolve("security_roles.json");
            if (Files.exists(allRolesPath1) == false) {
                // "security_roles" path differs in previous version of the diagnostic tool
                Path allRolesPath2 = Path.of(diagnosticPathSpec.value(options)).resolve("security_roles.json");
                if (Files.exists(allRolesPath2) == false) {
                    throw new UserException(ExitCodes.CONFIG,
                            "The roles file paths [" + allRolesPath1 + "] and [" + allRolesPath2 + "] are missing.");
                }
                allRolesPath = allRolesPath2;
            } else {
                allRolesPath = allRolesPath1;
            }
            allAliasesPath = Path.of(diagnosticPathSpec.value(options)).resolve("alias.json");
            allIndexSettingsPath = Path.of(diagnosticPathSpec.value(options)).resolve("settings.json");
        } else if (options.has(allRolesPathSpec) && options.has(allAliasesPathSpec) && options.has(allIndexSettingsPathSpec)) {
            allRolesPath = Path.of(allRolesPathSpec.value(options));
            allAliasesPath = Path.of(allAliasesPathSpec.value(options));
            allIndexSettingsPath = Path.of(allIndexSettingsPathSpec.value(options));
        } else if (false == options.has(allRolesPathSpec)) {
            throw new UserException(ExitCodes.CONFIG, "Missing path option for the security roles file");
        } else if (false == options.has(allAliasesPathSpec)) {
            throw new UserException(ExitCodes.CONFIG, "Missing path option for the aliases file");
        } else {
            throw new UserException(ExitCodes.CONFIG, "Missing path option for the index settings file");
        }

        if (Files.exists(allRolesPath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The roles file [" + allRolesPath + "] is missing");
        }
        if (Files.exists(allAliasesPath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The aliases file [" + allAliasesPath + "] is missing");
        }
        if (Files.exists(allIndexSettingsPath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The index settings file [" + allIndexSettingsPath + "] is missing");
        }

        final Pattern dataStreamPattern = Pattern.compile("\\A" + Pattern.quote(DataStream.BACKING_INDEX_PREFIX) + "(.+)-\\d{6}\\z");
        final Map<String, IndexAbstraction> mockAliasAndIndexLookup = new HashMap<>();
        final Map<String, IndexMetadata> indexMetadataMap = new HashMap<>();
        final Map<String, Set<String>> lifecycleRolloverAliasToIndicesMap = new HashMap<>();
        {
            byte[] allIndexSettingsBytes = Files.readAllBytes(allIndexSettingsPath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allIndexSettingsBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    String indexName = parser.currentName();
                    ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
                    if (false == "settings".equals(parser.currentName())) {
                        throw new ElasticsearchParseException("failed to parse settings for index [{}]", indexName);
                    }
                    ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    Settings settings = Settings.fromXContent(parser);
                    indexMetadataMap.put(indexName, IndexMetadata.builder(indexName).settings(settings).build());
                    String lifecycleRolloverAlias = settings.get("index.lifecycle.rollover_alias");
                    if (Strings.hasText(lifecycleRolloverAlias)) {
                        lifecycleRolloverAliasToIndicesMap.computeIfAbsent(lifecycleRolloverAlias, (k) -> new HashSet<>())
                                .add(indexName);
                    }
                    ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser); // index name
                }
            }
        }
        Map<String, List<Index>> dataStreamToIndicesMap = new HashMap<>();
        for (Map.Entry<String, IndexMetadata> entry : indexMetadataMap.entrySet()) {
            Matcher matcher = dataStreamPattern.matcher(entry.getKey());
            if (matcher.find()) {
                String dataStreamName = matcher.group(1);
                dataStreamToIndicesMap.computeIfAbsent(dataStreamName, (k) -> new ArrayList<>()).add(new Index(entry.getKey(),
                        entry.getValue().getIndexUUID()));
            } else {
                mockAliasAndIndexLookup.put(entry.getKey(), new IndexAbstraction.Index(entry.getValue()));
            }
        }
        dataStreamToIndicesMap.forEach((dataStreamName, indices) -> {
            DataStream dataStream = new DataStream(dataStreamName, new DataStream.TimestampField("@timestamp"),
                    dataStreamToIndicesMap.get(dataStreamName));
            IndexAbstraction.DataStream dataStreamAbstraction = new IndexAbstraction.DataStream(dataStream,
                    indices.stream().map(index -> indexMetadataMap.get(index.getName())).collect(Collectors.toList()));
            mockAliasAndIndexLookup.put(dataStreamName, dataStreamAbstraction);
            indices.stream().forEach(index -> {
                IndexMetadata indexMetadata = indexMetadataMap.get(index.getName());
                mockAliasAndIndexLookup.put(index.getName(), new IndexAbstraction.Index(indexMetadata, dataStreamAbstraction));
            });
        });
        final Map<String, String> aliasToWriteIndexMap = new HashMap<>();
        {
            byte[] allAliasesBytes = Files.readAllBytes(allAliasesPath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allAliasesBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    String indexName = parser.currentName();
                    ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
                    if (false == "aliases".equals(parser.currentName())) {
                        throw new ElasticsearchParseException("failed to parse aliases for index [{}]", indexName);
                    }
                    ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                        ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                        AliasMetadata aliasMetadata = AliasMetadata.Builder.fromXContent(parser);
                        // skip hidden indices; the settings API above also skips them
                        if (aliasMetadata.isHidden() == null || false == aliasMetadata.isHidden()) {
                            if (aliasMetadata.writeIndex() != null && aliasMetadata.writeIndex()) {
                                aliasToWriteIndexMap.put(aliasMetadata.alias(), indexName);
                            }
                            if (mockAliasAndIndexLookup.containsKey(aliasMetadata.getAlias())) {
                                ((IndexAbstraction.Alias) mockAliasAndIndexLookup.get(aliasMetadata.getAlias()))
                                        .addIndex(indexMetadataMap.get(indexName));
                            } else {
                                mockAliasAndIndexLookup.put(aliasMetadata.getAlias(), new IndexAbstraction.Alias(aliasMetadata,
                                        indexMetadataMap.get(indexName)));
                            }
                        }
                    }
                    ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser); // index name
                }
            }
        }
        {
            FieldPermissionsCache fieldPermissionsCache = new FieldPermissionsCache(Settings.EMPTY);
            byte[] allRolesBytes = Files.readAllBytes(allRolesPath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allRolesBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                int countRolesWithIssues = 0;
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    String roleName = parser.currentName();
                    boolean roleHasIssue = false;
                    parser.nextToken();
                    RoleDescriptor roleDescriptor = RoleDescriptor.parse(roleName, parser, false);
                    Role role = Role.builder(roleDescriptor, fieldPermissionsCache).build();
                    // collated results for "read" permission checks
                    Map<String, Set<String>> collatedReadPermissionChecks = new HashMap<>();
                    Map<String, Set<String>> collatedReadDLSPermissionChecks = new HashMap<>();
                    Map<String, Set<String>> collatedReadFLSPermissionChecks = new HashMap<>();
                    // check read permissions
                    for (String readAction : List.of(SearchAction.NAME, GetAction.NAME)) {
                        Map<String, IndicesAccessControl.IndexAccessControl> indicesAccessControlCache = new HashMap<>();
                        for (IndexAbstraction indexAbstraction : mockAliasAndIndexLookup.values()) {
                            if (indexAbstraction.getType() == IndexAbstraction.Type.ALIAS) {
                                // first compute the access control on the alias
                                IndicesAccessControl aliasAccessControl = role.authorize(readAction,
                                        Set.of(indexAbstraction.getName()),
                                        mockAliasAndIndexLookup, fieldPermissionsCache);
                                if (aliasAccessControl.isGranted()) {
                                    for (IndexMetadata indexMetadata : indexAbstraction.getIndices()) {
                                        // if access is granted on the alias, check
                                        String indexName = indexMetadata.getIndex().getName();
                                        IndicesAccessControl.IndexAccessControl indexAccessControl =
                                                indicesAccessControlCache.computeIfAbsent(indexName,
                                                (k) -> role.authorize(readAction,
                                                Set.of(indexName),
                                                mockAliasAndIndexLookup, fieldPermissionsCache).getIndexPermissions(indexName));
                                        IndicesAccessControl.IndexAccessControl aliasedIndexAccessControl =
                                                aliasAccessControl.getIndexPermissions(indexName);
                                        String message = "";
                                        if (false == indexAccessControl.isGranted()) {
                                            message = message.concat("The [" + roleName + "] role permits the [" + readAction +
                                                    "] action on the [" + indexAbstraction.getName() + "] alias, but not on the " +
                                                    "[" + indexName + "] pointed to index.");
                                            collatedReadPermissionChecks.computeIfAbsent(indexAbstraction.getName(), (k) -> new HashSet<>())
                                                    .add(indexName);
                                            roleHasIssue = true;
                                        } else {
                                            if (false == Operations.subsetOf(aliasedIndexAccessControl.getFieldPermissions().getIncludeAutomaton(),
                                                    indexAccessControl.getFieldPermissions().getIncludeAutomaton())) {
                                                message = message.concat("The field permissions granted by the [" + roleName + "] role," +
                                                                " for the [" + readAction + "] action," +
                                                                " over the [" + indexName + "] index DO NOT INCLUDE all the field " +
                                                                "permissions granted over the [" + indexAbstraction.getName() + "] alias," +
                                                                " which points to the said index.");
                                                collatedReadFLSPermissionChecks.computeIfAbsent(indexAbstraction.getName(),
                                                        (k) -> new HashSet<>()).add(indexName);
                                                roleHasIssue = true;
                                            }
                                            if (indexAccessControl.getDocumentPermissions().hasDocumentLevelPermissions()) {
                                                if ((false == aliasedIndexAccessControl.getDocumentPermissions()
                                                        .hasDocumentLevelPermissions()) || (false == indexAccessControl
                                                .getDocumentPermissions().getQueries().containsAll(aliasedIndexAccessControl
                                                                .getDocumentPermissions().getQueries()))) {
                                                    message = message.concat("The document permissions granted by the [" + roleName + "]" +
                                                            " role, for the [" + readAction + "] action, " +
                                                            "over the [" + indexName + "] index DO NOT INCLUDE all the document " +
                                                            "permissions granted over the [" + indexAbstraction.getName() + "] alias," +
                                                            " which points to the said index.");
                                                    collatedReadDLSPermissionChecks.computeIfAbsent(indexAbstraction.getName(),
                                                            (k) -> new HashSet<>()).add(indexName);
                                                    roleHasIssue = true;
                                                }
                                            }
                                        }
                                        if (terminal.isPrintable(Terminal.Verbosity.VERBOSE) && Strings.hasText(message)) {
                                            if (indexAbstraction.getName().equals(indexMetadata
                                                    .getSettings().get("index.lifecycle.rollover_alias"))) {
                                                message = message.concat(" The alias is the rollover alias for the [" +
                                                        indexMetadata.getSettings().get("index.lifecycle.name") + "] lifecycle policy.");
                                            }
                                            terminal.println(Terminal.Verbosity.VERBOSE, message);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    for (Map.Entry<String, Set<String>> aliasAndIndices : collatedReadPermissionChecks.entrySet()) {
                        String message = "The [" + roleName + "] role grants some \"read\" access on the [" + aliasAndIndices.getKey() +
                                "] alias but no \"read\" access on the [" +
                                Strings.collectionToCommaDelimitedString(aliasAndIndices.getValue()) +
                                "] indices that the alias points to.";
                        if (lifecycleRolloverAliasToIndicesMap.containsKey(aliasAndIndices.getKey()) &&
                                lifecycleRolloverAliasToIndicesMap.get(aliasAndIndices.getKey()).containsAll(aliasAndIndices.getValue())) {
                            message = message + " The alias is the rollover alias of the indices' lifecycle policies.";
                        }
                        terminal.println(message);
                    }
                    for (Map.Entry<String, Set<String>> aliasAndIndices : collatedReadDLSPermissionChecks.entrySet()) {
                        String message = "The [" + roleName + "] role grants different DOCUMENT PERMISSIONS on the [" +
                                aliasAndIndices.getKey() + "] alias compared to the [" +
                                Strings.collectionToCommaDelimitedString(aliasAndIndices.getValue()) +
                                "] indices that the alias points to, such that more or different documents are " +
                                "accessible if querying or retrieving via the alias than via the indices.";
                        if (lifecycleRolloverAliasToIndicesMap.containsKey(aliasAndIndices.getKey()) &&
                                lifecycleRolloverAliasToIndicesMap.get(aliasAndIndices.getKey()).containsAll(aliasAndIndices.getValue())) {
                            message = message + " The alias is the rollover alias of the indices' lifecycle policies.";
                        }
                        terminal.println(message);
                    }
                    for (Map.Entry<String, Set<String>> aliasAndIndices : collatedReadDLSPermissionChecks.entrySet()) {
                        String message = "The [" + roleName + "] role grants different FIELD PERMISSIONS on the [" +
                                aliasAndIndices.getKey() + "] alias compared to the [" +
                                Strings.collectionToCommaDelimitedString(aliasAndIndices.getValue()) +
                                "] indices that the alias points to, such that more or different fields are " +
                                "accessible if querying or retrieving via the alias than via the indices.";
                        if (lifecycleRolloverAliasToIndicesMap.containsKey(aliasAndIndices.getKey()) &&
                                lifecycleRolloverAliasToIndicesMap.get(aliasAndIndices.getKey()).containsAll(aliasAndIndices.getValue())) {
                            message = message + " The alias is the rollover alias of the indices' lifecycle policies.";
                        }
                        terminal.println(message);
                    }
                    Map<String, String> collatedWritePermissionChecks = new HashMap<>();
                    // check write permissions
                    for (String writeAction : List.of(UpdateAction.NAME, DeleteAction.NAME, AuthorizationService.IMPLIED_CREATE_ACTION,
                            AuthorizationService.IMPLIED_INDEX_ACTION)) {
                        Map<String, IndicesAccessControl.IndexAccessControl> indicesAccessControlCache = new HashMap<>();
                        for (IndexAbstraction indexAbstraction : mockAliasAndIndexLookup.values()) {
                            if (indexAbstraction.getType() == IndexAbstraction.Type.ALIAS) {
                                IndexMetadata writeIndexMetadata = null;
                                if (indexAbstraction.getIndices().size() == 1) {
                                    writeIndexMetadata = indexAbstraction.getIndices().get(0);
                                } else if (aliasToWriteIndexMap.containsKey(indexAbstraction.getName())) {
                                    writeIndexMetadata = indexMetadataMap.get(aliasToWriteIndexMap.get(indexAbstraction.getName()));
                                }
                                // verify the write permissions, but only if this alias can be written to
                                if (writeIndexMetadata != null) {
                                    // authorize on the alias
                                    IndicesAccessControl aliasAccessControl = role.authorize(writeAction,
                                            Set.of(indexAbstraction.getName()),
                                            mockAliasAndIndexLookup, fieldPermissionsCache);
                                    if (aliasAccessControl.isGranted()) {
                                        // if access is granted on the alias, check access on the write index
                                        String indexName = writeIndexMetadata.getIndex().getName();
                                        IndicesAccessControl.IndexAccessControl indexAccessControl =
                                                indicesAccessControlCache.computeIfAbsent(indexName,
                                                        (k) -> role.authorize(writeAction, Set.of(indexName),
                                                                mockAliasAndIndexLookup, fieldPermissionsCache)
                                                                .getIndexPermissions(indexName));
                                        if (false == indexAccessControl.isGranted()) {
                                            collatedWritePermissionChecks.put(indexAbstraction.getName(), indexName);
                                            roleHasIssue = true;
                                            if (terminal.isPrintable(Terminal.Verbosity.VERBOSE)) {
                                                String message = "The role [" + roleName + "] permits the [" + writeAction +
                                                        "] action on the [" + indexAbstraction.getName() + "] alias, but not on the " +
                                                        "[" + indexName + "] index that the alias points to (on writing).";
                                                if (indexAbstraction.getName().equals(writeIndexMetadata.getSettings()
                                                        .get("index.lifecycle.rollover_alias"))) {
                                                    message = message.concat(" The alias is the rollover alias for the [" +
                                                            writeIndexMetadata.getSettings().get("index.lifecycle.name") + "] lifecycle " +
                                                            "policy.");
                                                }
                                                terminal.println(Terminal.Verbosity.VERBOSE, message);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    for (Map.Entry<String, String> aliasAndWriteIndex : collatedWritePermissionChecks.entrySet()) {
                        String message = "The [" + roleName + "] role grants some \"write\" access on the [" + aliasAndWriteIndex.getKey() +
                                "] alias but no \"write\" access on the [" + aliasAndWriteIndex.getValue() +
                                "] index that the alias points to for writing.";
                        if (lifecycleRolloverAliasToIndicesMap.containsKey(aliasAndWriteIndex.getKey()) &&
                                lifecycleRolloverAliasToIndicesMap.get(aliasAndWriteIndex.getKey()).contains(aliasAndWriteIndex.getValue())) {
                            message = message + " The alias is the rollover alias of the index's lifecycle policy.";
                        }
                        terminal.println(message);
                    }
                    if (roleHasIssue) {
                        countRolesWithIssues++;
                    }
                }
                if (countRolesWithIssues > 0) {
                    throw new UserException(1, "[" + countRolesWithIssues + "] roles have been discovered that grant more or different " +
                            "permissions on the alias than on the indices that the alias points too.");
                }
            }
        }
    }
}
