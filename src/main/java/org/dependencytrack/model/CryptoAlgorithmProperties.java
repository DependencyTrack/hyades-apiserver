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

import org.cyclonedx.model.component.crypto.enums.CertificationLevel;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.ExecutionEnvironment;
import org.cyclonedx.model.component.crypto.enums.ImplementationPlatform;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.crypto.enums.Primitive;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

@PersistenceCapable(table= "ALGORITHM_PROPERTIES")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptoAlgorithmProperties implements Serializable {

    private static final long serialVersionUID = 6421255046930674722L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    // @Persistent
    // @Column(name = "CRYPTO_PROPERTIES_ID")
    // @JsonIgnore
    // private CryptoAssetProperties cryptoAssetProperties;

    // public CryptoAssetProperties getCryptoAssetProperties() {
    //      return cryptoAssetProperties;
    // }

    // public void setCryptoAssetProperties(CryptoAssetProperties cryptoAssetProperties) {
    //      this.cryptoAssetProperties = cryptoAssetProperties;
    // }

    /*
     * algorithmProperties
     */
    @Persistent
    @Column(name = "PRIMITIVE", jdbcType = "VARCHAR", length=32)
    private Primitive primitive;
    @Persistent
    @Column(name = "PARAMETER_SET_ID", jdbcType = "VARCHAR", length=32)
    private String parameterSetIdentifier;
    @Persistent
    @Column(name = "CURVE", jdbcType = "VARCHAR", length=32)
    private String curve;
    @Persistent
    @Column(name = "EXECUTION_ENV", jdbcType = "VARCHAR", length=32)
    private ExecutionEnvironment executionEnvironment;
    @Persistent
    @Column(name = "IMPLEMENTATION_PLATFORM", jdbcType = "VARCHAR", length=32)
    private ImplementationPlatform implementationPlatform;
    @Persistent
    @Column(name = "CERTIFICATION_LEVEL", jdbcType = "VARCHAR", length=32)
    private CertificationLevel certificationLevel;
    @Persistent
    @Column(name = "MODE", jdbcType = "VARCHAR", length=16)
    private Mode mode;
    @Persistent
    @Column(name = "PADDING", jdbcType = "VARCHAR", length=16)
    private Padding padding;

    @Persistent(table = "CRYPTO_FUNCTIONS", defaultFetchGroup = "true")
    @Join(column="ALGORITHM_PROPERTY_ID")
    @Element(column="CRYPTO_FUNCTION", dependent = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<CryptoFunction> cryptoFunctions;

    @Persistent
    @Column(name = "CLASSICAL_SECURITY_LEVEL")
    private Integer classicalSecurityLevel;
    @Persistent
    @Column(name = "NIST_QUANTUM_SECURITY_LEVEL")
    private Integer nistQuantumSecurityLevel;
    
    public Primitive getPrimitive() {
        return primitive;
    }
    public void setPrimitive(Primitive primitive) {
        this.primitive = primitive;
    }
    public String getParameterSetIdentifier() {
        return parameterSetIdentifier;
    }
    public void setParameterSetIdentifier(String parameterSetIdentifier) {
        this.parameterSetIdentifier = parameterSetIdentifier;
    }
    public String getCurve() {
        return curve;
    }
    public void setCurve(String curve) {
        this.curve = curve;
    }
    public ExecutionEnvironment getExecutionEnvironment() {
        return executionEnvironment;
    }
    public void setExecutionEnvironment(ExecutionEnvironment executionEnvironment) {
        this.executionEnvironment = executionEnvironment;
    }
    public ImplementationPlatform getImplementationPlatform() {
        return implementationPlatform;
    }
    public void setImplementationPlatform(ImplementationPlatform implementationPlatform) {
        this.implementationPlatform = implementationPlatform;
    }
    public CertificationLevel getCertificationLevel() {
        return certificationLevel;
    }
    public void setCertificationLevel(CertificationLevel certificationLevel) {
        this.certificationLevel = certificationLevel;
    }
    public Mode getMode() {
        return mode;
    }
    public void setMode(Mode mode) {
        this.mode = mode;
    }
    public Padding getPadding() {
        return padding;
    }
    public void setPadding(Padding padding) {
        this.padding = padding;
    }
    public List<CryptoFunction> getCryptoFunctions() {
        return cryptoFunctions;
    }
    public void setCryptoFunctions(List<CryptoFunction> cryptoFunctions) {
        this.cryptoFunctions = cryptoFunctions;
    }
    public Integer getClassicalSecurityLevel() {
        return classicalSecurityLevel;
    }
    public void setClassicalSecurityLevel(Integer classicalSecurityLevel) {
        this.classicalSecurityLevel = classicalSecurityLevel;
    }
    public Integer getNistQuantumSecurityLevel() {
        return nistQuantumSecurityLevel;
    }
    public void setNistQuantumSecurityLevel(Integer nistQuantumSecurityLevel) {
        this.nistQuantumSecurityLevel = nistQuantumSecurityLevel;
    }

    

}