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
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.LoggingAwareCommand;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.DataStream;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.Index;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.IndicesPermission;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

public class CheckAliasesPermissionTool2 extends LoggingAwareCommand {

    final OptionSpec<String> allRolesPathSpec;
    final OptionSpec<String> allAliasesPathSpec;
    final OptionSpec<String> allIndexSettingsPathSpec;
    final OptionSpec<String> diagnosticPathSpec;

    public CheckAliasesPermissionTool2() {
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
        exit(new CheckAliasesPermissionTool2().main(args, Terminal.DEFAULT));
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

        final Pattern dataStreamPattern = Pattern.compile("^" + Pattern.quote(DataStream.BACKING_INDEX_PREFIX) + "(.+)-\\d{7}$");
        final Map<String, IndexAbstraction> mockAliasAndIndexLookup = new HashMap<>();
        final Map<String, IndexMetadata> indexMetadataMap = new HashMap<>();
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
                    ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser); // index name
                }
            }
        }
        Map<String, List<Index>> dataStreamToIndicesMap = new HashMap<>();
        for (Map.Entry<String, IndexMetadata> entry : indexMetadataMap.entrySet()) {
            Matcher matcher = dataStreamPattern.matcher(entry.getKey());
            if (matcher.find()) {
                String dataStreamName = matcher.group();
                dataStreamToIndicesMap.computeIfAbsent(dataStreamName, (k) -> new ArrayList<>()).add(new Index(entry.getKey(), "uuid"));
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
        final Map<String, Set<String>> aliasToIndicesMap = new HashMap<>();
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
                        aliasToIndicesMap.computeIfAbsent(aliasMetadata.alias(), k -> new HashSet<>()).add(indexName);
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
                    ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser); // index name
                }
            }
        }
        if (aliasToIndicesMap.isEmpty()) {
            terminal.println("No aliases, nothing to check.");
            return;
        }
        {
            byte[] allRolesBytes = Files.readAllBytes(allRolesPath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allRolesBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    String roleName = parser.currentName();
                    parser.nextToken();
                    RoleDescriptor roleDescriptor = RoleDescriptor.parse(roleName, parser, false);
//      String lifecycleAlias = settings.get("index.lifecycle.rollover_alias");
//      if (Strings.hasText(lifecycleAlias)) {
//          indexToLifecycleAliasMap.put(indexName, lifecycleAlias);
//      }
//                    checkAliasesPermissionForRole(terminal, roleDescriptor, indexToAliasesMap, indexToWriteAliasMap,
//                            indexToLifecycleAliasMap);
                }
            }
        }
    }

    private Map<String, IndexAbstraction> mockIndexAndAliasLookup(Map<String, IndexMetadata> indexMetadataMap, Map<String,
            Set<String>> aliasToIndicesMap) {
        Pattern pattern = Pattern.compile("^" + Pattern.quote(DataStream.BACKING_INDEX_PREFIX) + "(.+)-\\d{7}$");
        Map<String, IndexAbstraction> result = new HashMap<>();
        Map<String, List<Index>> dataStreamToIndicesMap = new HashMap<>();
        for (Map.Entry<String, IndexMetadata> entry : indexMetadataMap.entrySet()) {
            Matcher matcher = pattern.matcher(entry.getKey());
            if (matcher.find()) {
                String dataStreamName = matcher.group();
                dataStreamToIndicesMap.computeIfAbsent(dataStreamName, (k) -> new ArrayList<>()).add(new Index(entry.getKey(), "uuid"));
            }
        }
        dataStreamToIndicesMap.forEach((dataStreamName, indices) -> {
            DataStream dataStream = new DataStream(dataStreamName, new DataStream.TimestampField("@timestamp"),
                    dataStreamToIndicesMap.get(dataStreamName));
            result.put(dataStreamName, new IndexAbstraction.DataStream(dataStream,
                    indices.stream().map(index -> indexMetadataMap.get(index.getName())).collect(Collectors.toList())));
        });
            for (Map.Entry<String, IndexMetadata> entry : indexMetadataMap.entrySet()) {
            Matcher matcher = pattern.matcher(entry.getKey());
            if (matcher.find()) {
                String dataStreamName = matcher.group();
                DataStream dataStream = new DataStream(dataStreamName, new DataStream.TimestampField("@timestamp"),
                        dataStreamToIndicesMap.get(dataStreamName));
                result.put(new IndexAbstraction.DataStream(dataStream, dataStreamToIndicesMap.get(dataStreamName).forEach(index -> {

                });));
            } else {
                result.put(entry.getKey(), new IndexAbstraction.Index(entry.getValue()));
            }
        }

        return result;
    }

    private void checkAliasesPermissionForRole(Terminal terminal, RoleDescriptor roleDescriptor,
                                               Map<String, List<String>> indexToAliasesMap,
                                               Map<String, String> indexToWriteAliasMap, Map<String, String> indexToLifecycleAliasMap) {
        final Map<String, Set<String>> aliasesPermissionNamesMap = new HashMap<>();
        // precompute the set of aliases; it saves predicate-match operations later on
        for (List<String> aliases : indexToAliasesMap.values()) {
            for (String alias : aliases) {
                aliasesPermissionNamesMap.putIfAbsent(alias, new HashSet<>());
            }
        }
        final Map<String, Set<String>> indicesPermissionNamesMap = new HashMap<>();
        for (RoleDescriptor.IndicesPrivileges privilege : roleDescriptor.getIndicesPrivileges()) {
            Predicate<String> namePatternPredicate = IndicesPermission.indexMatcher(Arrays.asList(privilege.getIndices()));
            for (String index : indexToAliasesMap.keySet()) {
                if (namePatternPredicate.test(index)) {
                    indicesPermissionNamesMap.computeIfAbsent(index, k -> new HashSet<>()).addAll(Arrays.asList(privilege.getPrivileges()));
                }
            }
            for (String alias : aliasesPermissionNamesMap.keySet()) {
                if (namePatternPredicate.test(alias)) {
                    aliasesPermissionNamesMap.get(alias).addAll(Arrays.asList(privilege.getPrivileges()));
                }
            }
        }
        final Automaton readAutomaton = IndexPrivilege.get(Set.of("read")).getAutomaton();
        final Automaton writeAutomaton = IndexPrivilege.get(Set.of("write")).getAutomaton();
        // only the "read" permissions automaton over aliases
        Map<String, Automaton> aliasesPermissionReadAutomatonMap = new HashMap<>();
        // only the "write" permissions automaton over aliases
        Map<String, Automaton> aliasesPermissionWriteAutomatonMap = new HashMap<>();
        aliasesPermissionNamesMap.forEach((alias, permissionNames) -> {
            Automaton aliasesPermissionAutomaton = IndexPrivilege.get(permissionNames).getAutomaton();
            // precompute the permission automaton intersection with the "read" and "write" automaton
            aliasesPermissionReadAutomatonMap.put(alias, Operations.intersection(aliasesPermissionAutomaton, readAutomaton));
            aliasesPermissionWriteAutomatonMap.put(alias, Operations.intersection(aliasesPermissionAutomaton, writeAutomaton));
        });
        // check the intersection of permission automatons
        for (Map.Entry<String, List<String>> indexAndAliases : indexToAliasesMap.entrySet()) {
            String index = indexAndAliases.getKey();
            String lifecycleAlias = indexToLifecycleAliasMap.get(index);
            Automaton indexPermissionReadAutomaton;
            Automaton indexPermissionWriteAutomaton;
            if (indicesPermissionNamesMap.containsKey(index)) {
                Automaton indexPermissionAutomaton = IndexPrivilege.get(indicesPermissionNamesMap.get(index)).getAutomaton();
                indexPermissionReadAutomaton = Operations.intersection(indexPermissionAutomaton, readAutomaton);
                indexPermissionWriteAutomaton = Operations.intersection(indexPermissionAutomaton, writeAutomaton);
            } else {
                // no permission on the index
                indexPermissionReadAutomaton = Automatons.EMPTY;
                indexPermissionWriteAutomaton = Automatons.EMPTY;
            }
            // check if "read" permission on any of the aliases is a superset of "read" on the index
            for (String alias : indexAndAliases.getValue()) {
                terminal.println(Terminal.Verbosity.VERBOSE, "Verifying \"read\" permissions on the index [" + index + "] " +
                                "relative to the alias [" + alias + "], granted by the role [" + roleDescriptor.getName() + "].");
                Automaton aliasPermissionReadAutomaton = aliasesPermissionReadAutomatonMap.get(alias);
                if (Operations.subsetOf(indexPermissionReadAutomaton, aliasPermissionReadAutomaton)) {
                    if (alias.equals(lifecycleAlias)) {
                        terminal.println("Role [" + roleDescriptor.getName() + "] grants more \"read\" permissions on the " +
                                "lifecycle rollover alias [" + alias + "] than on the pointed to index [" + index + "].");
                    } else {
                        terminal.println("Role [" + roleDescriptor.getName() + "] grants more \"read\" permissions on the " +
                                "alias [" + alias + "] than on the pointed to index [" + index + "].");
                    }
                }
            }
            // check if "write" permission on the write alias is a superset of "write" on the index
            String writeAlias = null;
            if (indexAndAliases.getValue().size() == 1) {
                writeAlias = indexAndAliases.getValue().get(0);
            } else if (indexToWriteAliasMap.containsKey(index)) {
                writeAlias = indexToWriteAliasMap.get(index);
            } else {
                terminal.println(Terminal.Verbosity.VERBOSE, "Index [" + index + "] is pointed to by several aliases, " +
                        "none of which is a write-alias. Skipping alias write permissions check.");
            }
            if (writeAlias != null) {
                terminal.println(Terminal.Verbosity.VERBOSE, "Verifying \"write\" permissions on the index [" + index + "] " +
                        "relative to the alias [" + writeAlias + "], granted by the role [" + roleDescriptor.getName() + "].");
                Automaton aliasPermissionWriteAutomaton = aliasesPermissionWriteAutomatonMap.getOrDefault(writeAlias, Automatons.EMPTY);
                if (Operations.subsetOf(indexPermissionWriteAutomaton, aliasPermissionWriteAutomaton)) {
                    if (writeAlias.equals(lifecycleAlias)) {
                        terminal.println("Role [" + roleDescriptor.getName() + "] grants more \"write\" permissions on the " +
                                "lifecycle rollover alias [" + writeAlias + "] than on the pointed to index [" + index + "].");
                    } else {
                        terminal.println("Role [" + roleDescriptor.getName() + "] grants more \"write\" permissions on the " +
                                "alias [" + writeAlias + "] than on the pointed to index [" + index + "].");
                    }
                }
            }
        }
    }
}
