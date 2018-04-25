/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.action.token;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenRequest;
import org.elasticsearch.xpack.core.security.action.token.CreateTokenResponse;
import org.elasticsearch.xpack.core.security.action.token.RefreshTokenAction;
import org.elasticsearch.xpack.security.authc.TokenService;

import static org.elasticsearch.xpack.security.action.token.TransportCreateTokenAction.getResponseScopeValue;

public class TransportRefreshTokenAction extends HandledTransportAction<CreateTokenRequest, CreateTokenResponse> {

    private final TokenService tokenService;

    @Inject
    public TransportRefreshTokenAction(Settings settings, ThreadPool threadPool, TransportService transportService,
                                       ActionFilters actionFilters, IndexNameExpressionResolver indexNameExpressionResolver,
                                       TokenService tokenService) {
        super(settings, RefreshTokenAction.NAME, threadPool, transportService, actionFilters, indexNameExpressionResolver,
                CreateTokenRequest::new);
        this.tokenService = tokenService;
    }

    @Override
    protected void doExecute(CreateTokenRequest request, ActionListener<CreateTokenResponse> listener) {
        tokenService.refreshToken(request.getRefreshToken(), ActionListener.wrap(tuple -> {
            final String tokenStr = tokenService.getUserTokenString(tuple.v1());
            final String scope = getResponseScopeValue(request.getScope());

            final CreateTokenResponse response =
                    new CreateTokenResponse(tokenStr, tokenService.getExpirationDelay(), scope, tuple.v2());
            listener.onResponse(response);
        }, listener::onFailure));
    }
}
