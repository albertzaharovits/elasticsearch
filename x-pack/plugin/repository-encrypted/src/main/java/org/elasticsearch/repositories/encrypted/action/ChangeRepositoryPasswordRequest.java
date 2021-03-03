/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.repositories.encrypted.action;

import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.support.master.AcknowledgedRequest;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;

public class ChangeRepositoryPasswordRequest extends AcknowledgedRequest<ChangeRepositoryPasswordRequest> {

    private String repositoryName;
    @Nullable
    private String fromPasswordNamed;
    private String toPasswordNamed;

    public ChangeRepositoryPasswordRequest() {
    }

    public ChangeRepositoryPasswordRequest(StreamInput in) throws IOException {
        super(in);
        this.repositoryName = in.readString();
        this.fromPasswordNamed = in.readOptionalString();
        this.toPasswordNamed = in.readString();
    }

    public String getRepositoryName() {
        return repositoryName;
    }

    public void setRepositoryName(String repositoryName) {
        this.repositoryName = repositoryName;
    }

    public String getFromPasswordNamed() {
        return fromPasswordNamed;
    }

    public void setFromPasswordNamed(String fromPasswordNamed) {
        this.fromPasswordNamed = fromPasswordNamed;
    }

    public String getToPasswordNamed() {
        return toPasswordNamed;
    }

    public void setToPasswordNamed(String toPasswordNamed) {
        this.toPasswordNamed = toPasswordNamed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ChangeRepositoryPasswordRequest that = (ChangeRepositoryPasswordRequest) o;
        return repositoryName.equals(that.repositoryName) &&
                Objects.equals(fromPasswordNamed, that.fromPasswordNamed) &&
                toPasswordNamed.equals(that.toPasswordNamed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(repositoryName, fromPasswordNamed, toPasswordNamed);
    }

    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(repositoryName);
        out.writeOptionalString(fromPasswordNamed);
        out.writeString(toPasswordNamed);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (Strings.isNullOrEmpty(repositoryName)) {
            validationException = addValidationError("repository name is required", validationException);
        }
        if (Strings.isNullOrEmpty(toPasswordNamed)) {
            validationException = addValidationError("the name for the password to change to is required", validationException);
        }
        if (false == Strings.isNullOrEmpty(fromPasswordNamed) && false == Strings.isNullOrEmpty(toPasswordNamed)) {
            if (fromPasswordNamed.equals(toPasswordNamed)) {
                validationException = addValidationError("the names for the two passwords to change must be different",
                        validationException);
            }
        }
        return validationException;
    }
}
