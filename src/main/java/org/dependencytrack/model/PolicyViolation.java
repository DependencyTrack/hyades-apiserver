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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import alpine.common.validation.RegexSequence;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Defines a Model class for defining a policy violation.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyViolation implements Serializable {

    public enum Type {
        LICENSE,
        SECURITY,
        OPERATIONAL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "TYPE", allowsNull = "false")
    private Type type;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @Index(name = "POLICYVIOLATION_PROJECT_IDX")
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "COMPONENT_ID", allowsNull = "true")
    @Index(name = "POLICYVIOLATION_COMPONENT_IDX")
    private Component component;

    @Persistent
    @Column(name = "POLICY_ID", allowsNull = "true")
    private Policy policy;

    // TODO: Remove
    @Deprecated(forRemoval = true)
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "POLICYCONDITION_ID", allowsNull = "true")
    private PolicyCondition policyCondition;

    @Persistent(table = "POLICYVIOLATIONS_MATCHED_POLICYCONDITIONS")
    @Join(column = "POLICYVIOLATION_ID")
    @Element(column = "POLICYCONDITION_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private List<PolicyCondition> matchedConditions;

    @Persistent
    @Column(name = "TIMESTAMP", allowsNull = "false")
    private Date timestamp;

    @Persistent
    @Column(name = "TEXT")
    @Size(min = 1, max = 255)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The text may only contain printable characters")
    private String text;

    @Persistent(mappedBy="policyViolation", defaultFetchGroup = "true")
    private ViolationAnalysis analysis;

    /**
     * The unique identifier of the object.
     */
    @Persistent(customValueStrategy = "uuid")
    @Unique(name = "POLICYVIOLATION_UUID_IDX")
    @Column(name = "UUID", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(final Project project) {
        this.project = project;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(final Policy policy) {
        this.policy = policy;
    }

    // TODO: Remove
    @Deprecated(forRemoval = true)
    public PolicyCondition getPolicyCondition() {
        return policyCondition;
    }

    // TODO: Remove
    @Deprecated(forRemoval = true)
    public void setPolicyCondition(PolicyCondition policyCondition) {
        this.policyCondition = policyCondition;
    }

    public List<PolicyCondition> getMatchedConditions() {
        return matchedConditions;
    }

    public void setMatchedConditions(final List<PolicyCondition> matchedConditions) {
        this.matchedConditions = matchedConditions;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public ViolationAnalysis getAnalysis() {
        return analysis;
    }

    public void setAnalysis(ViolationAnalysis analysis) {
        this.analysis = analysis;
    }
}


