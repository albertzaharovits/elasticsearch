/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.tool;

import com.carrotsearch.hppc.cursors.ObjectCursor;
import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.cli.ExitCodes;
import org.elasticsearch.cli.LoggingAwareCommand;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.Index;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.permission.IndicesPermission;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.privilege.IndexPrivilege;
import org.elasticsearch.xpack.core.security.support.Automatons;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

public class CheckAliasesPermissionTool extends LoggingAwareCommand {

    final OptionSpec<String> allRolesPathSpec;
    final OptionSpec<String> clusterStatePathSpec;
    final OptionSpec<String> diagnosticPathSpec;

    public CheckAliasesPermissionTool() {
        super("Given the index-alias association, as well as the security roles, tell which roles grant more privileges on the alias " +
                "than on the pointed to indices");
        allRolesPathSpec =
                parser.accepts("roles", "path to the input file containing all the security roles in the cluster").withRequiredArg();
        clusterStatePathSpec =
                parser.accepts("cluster_state", "path to the input file containing the cluster state").withRequiredArg();
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
        final Path clusterStatePath;
        if (false == (options.has(diagnosticPathSpec) || options.has(allRolesPathSpec) || options.has(clusterStatePathSpec))) {
            throw new UserException(ExitCodes.CONFIG, "No option specified. Try specifying the diagnostic dir path option.");
        } else if (options.has(diagnosticPathSpec)) {
            if (options.has(allRolesPathSpec) || options.has(clusterStatePathSpec)) {
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
            clusterStatePath = Path.of(diagnosticPathSpec.value(options)).resolve("cluster_state.json");
        } else if (options.has(allRolesPathSpec) && options.has(clusterStatePathSpec)) {
            allRolesPath = Path.of(allRolesPathSpec.value(options));
            clusterStatePath = Path.of(clusterStatePathSpec.value(options));
        } else {
            throw new UserException(ExitCodes.CONFIG, "Missing path options for security roles and cluster state");
        }

        if (Files.exists(allRolesPath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The roles file [" + allRolesPath + "] is missing");
        }
        if (Files.exists(clusterStatePath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The cluster state file [" + clusterStatePath + "] is missing");
        }

        final Map<String, IndexAbstraction> aliasAndIndexLookup = new HashMap<>();
        final Map<String, Set<String>> aliasToIndicesMap = new HashMap<>();
        final Map<String, String> aliasToWriteIndexMap = new HashMap<>();
        final Map<String, String> indexToLifecycleRolloverAliasMap = new HashMap<>();
        {
            byte[] allAliasesBytes = Files.readAllBytes(clusterStatePath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allAliasesBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    String fieldName = parser.currentName();
                    if ("metadata".equals(fieldName)) {
                        parser.nextToken();
                        Metadata metadata = Metadata.fromXContent(parser);
                        for (Iterator<ObjectObjectCursor<String, IndexMetadata>> it = metadata.indices().iterator(); it.hasNext(); ) {
                            ObjectObjectCursor<String, IndexMetadata> indexCursor = it.next();
                            String indexName = indexCursor.key;
                            IndexMetadata indexMetadata = indexCursor.value;
                            for (Iterator<ObjectObjectCursor<String, AliasMetadata>> iter = indexMetadata.getAliases().iterator(); iter.hasNext(); ) {
                                ObjectObjectCursor<String, AliasMetadata> aliasCursor = iter.next();
                                String aliasName = aliasCursor.key;
                                AliasMetadata aliasMetadata = aliasCursor.value;
                                aliasToIndicesMap.computeIfAbsent(aliasName, (k) -> new HashSet<>()).add(indexName);
                                if (aliasMetadata.writeIndex() != null && aliasMetadata.writeIndex()) {
                                    assert false == aliasToWriteIndexMap.containsKey(aliasName);
                                    aliasToWriteIndexMap.put(aliasName, indexName);
                                }
                            }
                            String lifecycleRolloverAlias = indexMetadata.getSettings().get("index.lifecycle.rollover_alias");
                            if (Strings.hasText(lifecycleRolloverAlias)) {
                                indexToLifecycleRolloverAliasMap.put(indexName, lifecycleRolloverAlias);
                                assert aliasToIndicesMap.containsKey(lifecycleRolloverAlias);
                                assert aliasToIndicesMap.get(lifecycleRolloverAlias).contains(indexName);
                            }
                        }
                    } else {
                        parser.nextToken();
                        parser.skipChildren();
                    }
                }
            }
        }
        if (aliasToIndicesMap.isEmpty()) {
            terminal.println("No aliases present, nothing to check, all good.");
            return;
        }
        {
            byte[] allRolesBytes = Files.readAllBytes(allRolesPath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allRolesBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                String roleName = null;
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    roleName = parser.currentName();
                    parser.nextToken();
                    RoleDescriptor roleDescriptor = RoleDescriptor.parse(roleName, parser, false);
                    Role.Builder()
//                    checkAliasesPermissionForRole(terminal, roleDescriptor, indexToAliasesMap, indexToWriteAliasMap,
//                            indexToLifecycleAliasMap);
                }
            }
        }
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
