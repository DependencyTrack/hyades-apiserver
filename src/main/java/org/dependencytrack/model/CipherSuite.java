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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

@PersistenceCapable(table = "CIPHER_SUITE")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CipherSuite implements Serializable {

    private static final long serialVersionUID = 8548267900098588016L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "NAME", jdbcType = "VARCHAR", length=64)
    private String name;

    @Persistent(table = "CIPHER_SUITE_ALGORITHM", defaultFetchGroup = "true")
    @Join(column = "CIPHER_SUITE_ID")
    @Element(column = "ALGORITHM", dependent = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<String> algorithms;

    @Persistent(table = "CIPHER_SUITE_IDENTIFIER", defaultFetchGroup = "true")
    @Join(column = "CIPHER_SUITE_ID")
    @Element(column = "IDENTIFIER", dependent = "true")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<String> identifiers;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<String> algorithms) {
        this.algorithms = algorithms;
    }

    public List<String> getIdentifiers() {
        return identifiers;
    }

    public void setIdentifiers(List<String> identifiers) {
        this.identifiers = identifiers;
    }
}

