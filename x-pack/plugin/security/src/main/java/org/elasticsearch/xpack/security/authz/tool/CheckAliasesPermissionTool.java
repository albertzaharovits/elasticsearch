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
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
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

import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

public class CheckAliasesPermissionTool extends LoggingAwareCommand {

    final OptionSpec<String> allRolesPathSpec;
    final OptionSpec<String> allAliasesPathSpec;
    final OptionSpec<String> diagnosticPathSpec;

    public CheckAliasesPermissionTool() {
        super("Given the index-alias association, as well as the security roles, tell which roles grant more privileges on the alias " +
                "than on the pointed to indices");
        allRolesPathSpec =
                parser.accepts("roles", "path to the input file containing all the security roles in the cluster").withRequiredArg();
        allAliasesPathSpec =
                parser.accepts("aliases", "path to the input file containing all the aliases in the cluster").withRequiredArg();
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

        if (options.has(diagnosticPathSpec)) {
            if (options.has(allRolesPathSpec) || options.has(allAliasesPathSpec)) {
                throw new UserException(ExitCodes.CONFIG, "The diagnostic dir path option cannot be used in conjunction with the " +
                        "other options");
            }
            allRolesPath = Path.of(diagnosticPathSpec.value(options)).resolve("commercial").resolve("security_roles.json");
            allAliasesPath = Path.of(diagnosticPathSpec.value(options)).resolve("alias.json");
        } else if (options.has(allRolesPathSpec) && options.has(allAliasesPathSpec)) {
            allRolesPath = Path.of(allRolesPathSpec.value(options));
            allAliasesPath = Path.of(allAliasesPathSpec.value(options));
        } else if (false == options.has(allRolesPathSpec)) {
            throw new UserException(ExitCodes.CONFIG, "Missing path option for the security roles file");
        } else {
            throw new UserException(ExitCodes.CONFIG, "Missing path option for the aliases file");
        }

        if (Files.exists(allRolesPath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The roles file [" + allRolesPath + "] is missing");
        }

        if (Files.exists(allAliasesPath) == false) {
            throw new UserException(ExitCodes.CONFIG, "The aliases file [" + allRolesPath + "] is missing");
        }

        final Map<String, List<String>> indexToAliasesMap = new HashMap<>();
        final Map<String, String> indexToWriteAliasMap = new HashMap<>();
        {
            byte[] allAliasesBytes = Files.readAllBytes(allAliasesPath);
            XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, allAliasesBytes);
            XContentParser.Token token = parser.nextToken();
            if (token != null) {
                String indexName = null;
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                    indexName = parser.currentName();
                    ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser);
                    if (false == "aliases".equals(parser.currentName())) {
                        throw new ElasticsearchParseException("failed to parse aliases for index [{}]", indexName);
                    }
                    ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                    while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
                        ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                        AliasMetadata aliasMetadata = AliasMetadata.Builder.fromXContent(parser);
                        indexToAliasesMap.computeIfAbsent(indexName, k -> new ArrayList<>())
                                .add(aliasMetadata.alias());
                        if (aliasMetadata.writeIndex() != null && aliasMetadata.writeIndex()) {
                            indexToWriteAliasMap.put(indexName, aliasMetadata.alias());
                        }
                    }
                    ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser); // index name
                }
            }
        }
        if (indexToAliasesMap.isEmpty()) {
            terminal.println("No aliases, nothing to check.");
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
                    checkAliasesPermissionForRole(roleDescriptor, indexToAliasesMap, indexToWriteAliasMap);
                }
            }
        }
    }

    private void checkAliasesPermissionForRole(RoleDescriptor roleDescriptor, Map<String, List<String>> indexToAliasesMap, Map<String,
            String> indexToWriteAliasMap) {
        final Map<String, Set<String>> aliasesPermissionNamesMap = new HashMap<>();
        // precompute the set of aliases; it saves predicate matches later on
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
            // precompute the automaton intersection with the "read" and "write" ones
            aliasesPermissionReadAutomatonMap.put(alias, Operations.intersection(aliasesPermissionAutomaton, readAutomaton));
            aliasesPermissionWriteAutomatonMap.put(alias, Operations.intersection(aliasesPermissionAutomaton, writeAutomaton));
        });
        // check the intersection of permission automatons
        for (Map.Entry<String, List<String>> indexAndAliases : indexToAliasesMap.entrySet()) {
            String index = indexAndAliases.getKey();
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
                Automaton aliasPermissionReadAutomaton = aliasesPermissionReadAutomatonMap.get(alias);
                if (Operations.subsetOf(indexPermissionReadAutomaton, aliasPermissionReadAutomaton)) {
                }
            }
            // check if "write" permission on the write alias is a superset of "write" on the index
            String writeAlias = null;
            if (indexAndAliases.getValue().size() == 1) {
                writeAlias = indexAndAliases.getValue().get(0);
            } else if (indexToWriteAliasMap.containsKey(index)) {
                writeAlias = indexToWriteAliasMap.get(index);
            }
            if (writeAlias != null) {
                Automaton aliasPermissionWriteAutomaton = aliasesPermissionWriteAutomatonMap.getOrDefault(writeAlias, Automatons.EMPTY);
                if (Operations.subsetOf(indexPermissionWriteAutomaton, aliasPermissionWriteAutomaton)) {
                }
            }
        }
    }
}
