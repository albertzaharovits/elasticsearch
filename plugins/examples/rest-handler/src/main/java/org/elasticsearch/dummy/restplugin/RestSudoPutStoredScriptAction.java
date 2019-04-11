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
package org.elasticsearch.dummy.restplugin;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.AcknowledgedRestListener;
import org.elasticsearch.script.StoredScriptSource;

import java.io.IOException;

import static org.elasticsearch.rest.RestRequest.Method.POST;
import static org.elasticsearch.rest.RestRequest.Method.PUT;

public class RestSudoPutStoredScriptAction extends BaseRestHandler {

    public RestSudoPutStoredScriptAction(Settings settings, RestController controller) {
        super(settings);

        controller.registerHandler(POST, "/sudo/_scripts/{id}", this);
        controller.registerHandler(PUT, "/sudo/_scripts/{id}", this);
        controller.registerHandler(POST, "/sudo/_scripts/{id}/{context}", this);
        controller.registerHandler(PUT, "/sudo/_scripts/{id}/{context}", this);
    }

    @Override
    public String getName() {
        return "sudo_put_stored_script_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String id = request.param("id");
        String context = request.param("context");
        BytesReference content = request.requiredContent();
        XContentType xContentType = request.getXContentType();
        StoredScriptSource source = StoredScriptSource.parse(content, xContentType);

        SudoPutStoredScriptRequest sudoPutRequest = new SudoPutStoredScriptRequest(id, context, content, request.getXContentType(), source);
        sudoPutRequest.masterNodeTimeout(request.paramAsTime("master_timeout", sudoPutRequest.masterNodeTimeout()));
        sudoPutRequest.timeout(request.paramAsTime("timeout", sudoPutRequest.timeout()));
        return channel -> client.execute(SudoPutStoredScriptAction.INSTANCE, sudoPutRequest, new AcknowledgedRestListener<>(channel));
    }
}
