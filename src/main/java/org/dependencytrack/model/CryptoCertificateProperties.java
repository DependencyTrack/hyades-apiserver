/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import java.io.Serializable;
import java.util.Date;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import org.dependencytrack.resources.v1.serializers.Iso8601DateSerializer;
import org.dependencytrack.util.DateUtil;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@PersistenceCapable(table= "CERTIFICATE_PROPERTIES")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptoCertificateProperties implements Serializable {

    private static final long serialVersionUID = 6421255046930674723L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;


    /*
     * certificateProperties
     */
    @Persistent
    @Column(name = "SUBJECT_NAME", jdbcType = "VARCHAR", length=255)
    private String subjectName;
    @Persistent
    @Column(name = "ISSUER_NAME", jdbcType = "VARCHAR", length=255)
    private String issuerName;
    @Persistent
    @Column(name = "NOT_VALID_BEFORE", jdbcType = "TIMESTAMP")
    @JsonSerialize(using = Iso8601DateSerializer.class)
    private Date notValidBefore;
    @Persistent
    @Column(name = "NOT_VALID_AFTER", jdbcType = "TIMESTAMP")
    @JsonSerialize(using = Iso8601DateSerializer.class)
    private Date notValidAfter;
    @Persistent
    @Column(name = "SIGNATURE_ALGORITHM_REF", jdbcType = "VARCHAR", length=64)
    private String signatureAlgorithmRef;
    @Persistent
    @Column(name = "SUBJECT_PUBLIC_KEY_REF", jdbcType = "VARCHAR", length=64)
    private String subjectPublicKeyRef;
    @Persistent
    @Column(name = "CERTIFICATE_FORMAT", jdbcType = "VARCHAR", length=32)
    private String certificateFormat;
    @Persistent
    @Column(name = "CERTIFICATE_EXTENSION", jdbcType = "VARCHAR", length=32)
    private String certificateExtension;


    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public Date getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(String notValidBefore) {
       this.notValidBefore = DateUtil.fromISO8601(notValidBefore);
    }

    public Date getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(String notValidAfter) {
        this.notValidAfter = DateUtil.fromISO8601(notValidAfter);
    }

    public String getSignatureAlgorithmRef() {
        return signatureAlgorithmRef;
    }

    public void setSignatureAlgorithmRef(String signatureAlgorithmRef) {
        this.signatureAlgorithmRef = signatureAlgorithmRef;
    }

    public String getSubjectPublicKeyRef() {
        return subjectPublicKeyRef;
    }

    public void setSubjectPublicKeyRef(String subjectPublicKeyRef) {
        this.subjectPublicKeyRef = subjectPublicKeyRef;
    }

    public String getCertificateFormat() {
        return certificateFormat;
    }

    public void setCertificateFormat(String certificateFormat) {
        this.certificateFormat = certificateFormat;
    }

    public String getCertificateExtension() {
        return certificateExtension;
    }

    public void setCertificateExtension(String certificateExtension) {
        this.certificateExtension = certificateExtension;
    }
}
