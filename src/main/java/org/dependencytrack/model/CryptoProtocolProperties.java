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
import java.util.List;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.dependencytrack.resources.v1.serializers.Ikev2TypesSerializer;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@PersistenceCapable(table= "PROTOCOL_PROPERTIES")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptoProtocolProperties implements Serializable {

    private static final long serialVersionUID = 6421255046930674725L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

 
    /*
     * protocolProperties
     */
    @Persistent
    @Column(name = "TYPE", jdbcType = "VARCHAR", length=16)
    private ProtocolType type;
    @Persistent
    @Column(name = "VERSION", jdbcType = "VARCHAR", length=16)
    private String version;
    
    @Persistent(table = "PROTOCOL_CIPHER_SUITES", defaultFetchGroup = "true")
    @Join(column = "PROTOCOL_PROPERTY_ID")
    @Element(column = "CIPHER_SUITE_ID", dependent = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<CipherSuite> cipherSuites;

    @Persistent(table = "PROTOCOL_IKEV2_TYPES", defaultFetchGroup = "true")
    @Join(column = "PROTOCOL_PROPERTY_ID")
    @Element(column = "IKEV2_TYPE_ID", dependent = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    @JsonSerialize(using = Ikev2TypesSerializer.class)
    private List<Ikev2Type> ikev2Types;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "CRYPTO_REFS", jdbcType="ARRAY", sqlType = "TEXT ARRAY")
    private List<String> cryptoRefs;

    public ProtocolType getType() {
        return type;
    }

    public void setType(ProtocolType type) {
        this.type = type;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<Ikev2Type> getIkev2Types() {
         return ikev2Types;
    }

    public void setIkev2Types(List<Ikev2Type> ikev2Types) {
         this.ikev2Types = ikev2Types;
    }

    public List<String> getCryptoRefs() {
        return cryptoRefs;
    }

    public void setCryptoRefs(List<String> cryptoRefs) {
        this.cryptoRefs = cryptoRefs;
    }
}
