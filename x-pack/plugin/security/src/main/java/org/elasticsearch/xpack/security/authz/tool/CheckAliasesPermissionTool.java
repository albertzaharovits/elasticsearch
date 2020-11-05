/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.tool;

import joptsimple.OptionSet;
import joptsimple.OptionSpec;
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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
                    RoleDescriptor descriptor = RoleDescriptor.parse(roleName, parser, false);
                }
            }
        }
    }
}
