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

import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.cyclonedx.model.component.crypto.enums.State;
import org.dependencytrack.resources.v1.serializers.Iso8601DateSerializer;
import org.dependencytrack.util.DateUtil;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@PersistenceCapable(table= "RELATED_CRYPTO_MATERIAL_PROPERTIES")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptoRelatedMaterialProperties implements Serializable {

    private static final long serialVersionUID = 6421255046930674724L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;


    /*
     * relatedCryptoMaterialProperties
     */
    @Persistent
    @Column(name = "TYPE")
    private RelatedCryptoMaterialType type;
    @Persistent
    @Column(name = "IDENTIFIER", jdbcType = "VARCHAR", length=64)
    private String identifier;
    @Persistent
    @Column(name = "STATE", jdbcType = "VARCHAR", length=16)
    private State state;
    @Persistent
    @Column(name = "ALGORITHM_REF", jdbcType = "VARCHAR", length=64)
    private String algorithmRef;
    @Persistent
    @Column(name = "CREATION_DATE", jdbcType = "TIMESTAMP")
    @JsonSerialize(using = Iso8601DateSerializer.class)
    private Date creationDate;
    @Persistent
    @Column(name = "ACTIVATION_DATE", jdbcType = "TIMESTAMP")
    @JsonSerialize(using = Iso8601DateSerializer.class)
    private Date activationDate;
    @Persistent
    @Column(name = "UPDATE_DATE", jdbcType = "TIMESTAMP")
    @JsonSerialize(using = Iso8601DateSerializer.class)
    private Date updateDate;
    @Persistent
    @Column(name = "EXPIRATION_DATE", jdbcType = "TIMESTAMP")
    @JsonSerialize(using = Iso8601DateSerializer.class)
    private Date expirationDate;
    @Persistent
    @Column(name = "VALUE", jdbcType = "VARCHAR", length=32)
    private String value;
    @Persistent
    @Column(name = "SIZE")
    private Integer size;
    @Persistent
    @Column(name = "FORMAT", jdbcType = "VARCHAR", length=8)
    private String format;
    @Persistent(defaultFetchGroup = "true", dependent = "true")
    @Column(name = "SECURED_BY_ID", allowsNull = "true")
    private SecuredBy securedBy;
    

    public RelatedCryptoMaterialType getType() {
        return type;
    }

    public void setType(RelatedCryptoMaterialType type) {
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String id) {
        this.identifier = id;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public String getAlgorithmRef() {
        return algorithmRef;
    }

    public void setAlgorithmRef(String algorithmRef) {
        this.algorithmRef = algorithmRef;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(String creationDate) {
        this.creationDate = DateUtil.fromISO8601(creationDate);
    }

    public Date getActivationDate() {
        return activationDate;
    }

    public void setActivationDate(String activationDate) {
        this.activationDate = DateUtil.fromISO8601(activationDate);
    }

    public Date getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(String updateDate) {
        this.updateDate = DateUtil.fromISO8601(updateDate);
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = DateUtil.fromISO8601(expirationDate);
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public SecuredBy getSecuredBy() {
        return securedBy;
    }

    public void setSecuredBy(SecuredBy securedBy) {
        this.securedBy = securedBy;
    }
}
