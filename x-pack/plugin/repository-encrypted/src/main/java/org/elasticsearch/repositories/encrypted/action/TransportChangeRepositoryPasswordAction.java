/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.repositories.encrypted.action;

import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.xpack.core.ml.action.PutJobAction;

public class TransportChangeRepositoryPasswordAction extends TransportMasterNodeAction<PutJobAction.Request, PutJobAction.Response> {
}
