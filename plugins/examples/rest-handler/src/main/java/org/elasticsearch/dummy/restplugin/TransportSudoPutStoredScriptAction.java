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

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.storedscripts.PutStoredScriptRequest;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

public class TransportSudoPutStoredScriptAction extends TransportMasterNodeAction<SudoPutStoredScriptRequest, SudoPutStoredScriptResponse> {

    private final ScriptService scriptService;

    @Inject
    public TransportSudoPutStoredScriptAction(Settings settings, TransportService transportService, ClusterService clusterService,
                                              ThreadPool threadPool, ActionFilters actionFilters,
                                              IndexNameExpressionResolver indexNameExpressionResolver, ScriptService scriptService) {
        super(settings, SudoPutStoredScriptAction.NAME, transportService, clusterService, threadPool, actionFilters,
                indexNameExpressionResolver, SudoPutStoredScriptRequest::new);
        this.scriptService = scriptService;
    }

    @Override
    protected String executor() {
        return ThreadPool.Names.SAME;
    }

    @Override
    protected SudoPutStoredScriptResponse newResponse() {
        return new SudoPutStoredScriptResponse();
    }

    @Override
    protected void masterOperation(SudoPutStoredScriptRequest request, ClusterState state,
                                   ActionListener<SudoPutStoredScriptResponse> listener) throws Exception {
        scriptService.putStoredScript(clusterService,
                new PutStoredScriptRequest(request.id(), request.context(), request.content(), request.xContentType(), request.source()),
                ActionListener.wrap(
                        putStoredScriptResponse -> listener
                                .onResponse(new SudoPutStoredScriptResponse(putStoredScriptResponse.isAcknowledged())),
                        listener::onFailure));
    }

    @Override
    protected ClusterBlockException checkBlock(SudoPutStoredScriptRequest request, ClusterState state) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }

}
