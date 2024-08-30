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

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import jakarta.validation.constraints.Pattern;

import org.cyclonedx.model.component.crypto.enums.AssetType;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

//import alpine.common.logging.Logger;


@PersistenceCapable(table= "CRYPTO_PROPERTIES")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptoAssetProperties implements Serializable {

    private static final long serialVersionUID = 6421255046930674702L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "ASSET_TYPE", jdbcType = "VARCHAR", length=32)
    private AssetType assetType;

    @Persistent(defaultFetchGroup = "true", dependent = "true")
    @Index(name = "COMPONENT_ALGORITHM_ID_IDX")
    @Column(name = "ALGORITHM_PROPERTIES_ID", allowsNull = "true")
    private CryptoAlgorithmProperties algorithmProperties;
    
    @Persistent(defaultFetchGroup = "true", dependent = "true")
    @Index(name = "COMPONENT_CERTIFICATE_ID_IDX")
    @Column(name = "CERTIFICATE_PROPERTIES_ID", allowsNull = "true")
    private CryptoCertificateProperties certificateProperties;

    @Persistent(defaultFetchGroup = "true", dependent = "true")
    @Index(name = "COMPONENT_RELATED_MATERIAL_ID_IDX")
    @Column(name = "RELATED_MATERIAL_PROPERTIES_ID", allowsNull = "true")
    private CryptoRelatedMaterialProperties relatedMaterialProperties;

    @Persistent(defaultFetchGroup = "true", dependent = "true")
    @Index(name = "COMPONENT_PROTOCOL_ID_IDX")
    @Column(name = "PROTOCOL_PROPERTIES_ID", allowsNull = "true")
    private CryptoProtocolProperties protocolProperties;

    @Persistent
    @Column(name = "OID", jdbcType = "VARCHAR", length=255)
    @Pattern(regexp = "^([0-2])((\\.0)|(\\.[1-9][0-9]*))*$", message = "The OID must be a valid")
    private String oid;

    public long getId() {
        return id;
    }

    public AssetType getAssetType() {
        return assetType;
    }

    public void setAssetType(AssetType assetType) {
        this.assetType = assetType;
    }

    public CryptoAlgorithmProperties getAlgorithmProperties() {
        return algorithmProperties;
    }

    public void setAlgorithmProperties(CryptoAlgorithmProperties algorithmProperties) {
        this.algorithmProperties = algorithmProperties;
    }

    public CryptoCertificateProperties getCertificateProperties() {
        return certificateProperties;
    }

    public void setCertificateProperties(CryptoCertificateProperties certificateProperties) {
        this.certificateProperties = certificateProperties;
    }

    public CryptoRelatedMaterialProperties getRelatedMaterialProperties() {
        return relatedMaterialProperties;
    }

    public void setRelatedMaterialProperties(CryptoRelatedMaterialProperties relatedMaterialProperties) {
        this.relatedMaterialProperties = relatedMaterialProperties;
    }

    public CryptoProtocolProperties getProtocolProperties() {
        return protocolProperties;
    }

    public void setProtocolProperties(CryptoProtocolProperties protocolProperties) {
        this.protocolProperties = protocolProperties;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }
}
