/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.ml.rest.results;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.xpack.core.action.util.PageParams;
import org.elasticsearch.xpack.core.ml.action.GetCategoriesAction;
import org.elasticsearch.xpack.core.ml.action.GetCategoriesAction.Request;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;
import static org.elasticsearch.xpack.core.ml.action.GetCategoriesAction.Request.CATEGORY_ID;
import static org.elasticsearch.xpack.core.ml.job.config.Job.ID;
import static org.elasticsearch.xpack.ml.MachineLearning.BASE_PATH;

public class RestGetCategoriesAction extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, BASE_PATH + "anomaly_detectors/{" + ID.getPreferredName() +
                "}/results/categories/{" + CATEGORY_ID.getPreferredName() + "}"),
            new Route(POST, BASE_PATH + "anomaly_detectors/{" + ID.getPreferredName() +
                "}/results/categories/{" + CATEGORY_ID.getPreferredName() + "}"),
            new Route(GET, BASE_PATH + "anomaly_detectors/{" + ID.getPreferredName() + "}/results/categories"),
            new Route(POST, BASE_PATH + "anomaly_detectors/{" + ID.getPreferredName() + "}/results/categories")
        );
    }

    @Override
    public String getName() {
        return "ml_get_categories_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient client) throws IOException {
        Request request;
        String jobId = restRequest.param(ID.getPreferredName());
        Long categoryId = restRequest.hasParam(CATEGORY_ID.getPreferredName()) ? Long.parseLong(
                restRequest.param(CATEGORY_ID.getPreferredName())) : null;

        if (restRequest.hasContentOrSourceParam()) {
            XContentParser parser = restRequest.contentOrSourceParamParser();
            request = GetCategoriesAction.Request.parseRequest(jobId, parser);
            if (categoryId != null) {
                request.setCategoryId(categoryId);
            }
        } else {
            request = new Request(jobId);
            if (categoryId != null) {
                request.setCategoryId(categoryId);
            }
            if (restRequest.hasParam(Request.FROM.getPreferredName())
                    || restRequest.hasParam(Request.SIZE.getPreferredName())
                    || categoryId == null){

                request.setPageParams(new PageParams(
                        restRequest.paramAsInt(Request.FROM.getPreferredName(), PageParams.DEFAULT_FROM),
                        restRequest.paramAsInt(Request.SIZE.getPreferredName(), PageParams.DEFAULT_SIZE)
                ));
            }
            request.setPartitionFieldValue(restRequest.param(Request.PARTITION_FIELD_VALUE.getPreferredName()));
        }

        return channel -> client.execute(GetCategoriesAction.INSTANCE, request, new RestToXContentListener<>(channel));
    }

}
