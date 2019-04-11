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

import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.support.master.AcknowledgedRequest;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.script.StoredScriptSource;

import java.io.IOException;
import java.util.Objects;

public class SudoPutStoredScriptRequest extends AcknowledgedRequest<SudoPutStoredScriptRequest> {

    private String id;
    private String context;
    private BytesReference content;
    private XContentType xContentType;
    private StoredScriptSource source;

    public SudoPutStoredScriptRequest() {
        super();
    }

    public SudoPutStoredScriptRequest(String id, String context, BytesReference content, XContentType xContentType,
            StoredScriptSource source) {
        super();
        this.id = id;
        this.context = context;
        this.content = content;
        this.xContentType = Objects.requireNonNull(xContentType);
        this.source = source;
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String id() {
        return id;
    }

    public SudoPutStoredScriptRequest id(String id) {
        this.id = id;
        return this;
    }

    public String context() {
        return context;
    }

    public SudoPutStoredScriptRequest context(String context) {
        this.context = context;
        return this;
    }

    public BytesReference content() {
        return content;
    }

    public XContentType xContentType() {
        return xContentType;
    }

    public StoredScriptSource source() {
        return source;
    }

    /**
     * Set the script source and the content type of the bytes.
     */
    public SudoPutStoredScriptRequest content(BytesReference content, XContentType xContentType) {
        this.content = content;
        this.xContentType = Objects.requireNonNull(xContentType);
        this.source = StoredScriptSource.parse(content, xContentType);
        return this;
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);

        id = in.readOptionalString();
        content = in.readBytesReference();
        xContentType = XContentType.readFrom(in);
        context = in.readOptionalString();
        source = new StoredScriptSource(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);

        out.writeOptionalString(id);
        out.writeBytesReference(content);
        xContentType.writeTo(out);
        out.writeOptionalString(context);
        source.writeTo(out);
    }

    @Override
    public String toString() {
        String source = "_na_";

        try {
            source = XContentHelper.convertToJson(content, false, xContentType);
        } catch (Exception e) {
            // ignore
        }

        return "sudo put stored script {id [" + id + "]" +
            (context != null ? ", context [" + context + "]" : "") +
            ", content [" + source + "]}";
    }
}
