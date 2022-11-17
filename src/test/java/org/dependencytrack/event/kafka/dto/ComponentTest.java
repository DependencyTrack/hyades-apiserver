package org.dependencytrack.event.kafka.dto;

import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class ComponentTest {

    @Test
    public void testConstructor() {
        final var uuid = UUID.fromString("ff5070bb-f8ed-485c-9361-f6c7c92ffd45");
        var dto = new Component(uuid, "group", "name", "version", "purl", "cpe");
        assertThat(dto.uuid()).isEqualTo(uuid);
        assertThat(dto.group()).isEqualTo("group");
        assertThat(dto.name()).isEqualTo("name");
        assertThat(dto.version()).isEqualTo("version");
        assertThat(dto.purl()).isEqualTo("purl");
        assertThat(dto.cpe()).isEqualTo("cpe");
    }

    @Test
    public void testConstructorWithComponent() {
        final var uuid = UUID.fromString("ff5070bb-f8ed-485c-9361-f6c7c92ffd45");
        final var component = new org.dependencytrack.model.Component();
        component.setUuid(uuid);
        component.setGroup("group");
        component.setName("name");
        component.setVersion("version");
        component.setPurl("pkg:maven/foo/bar@1.2.3");
        component.setCpe("cpe");

        final var dto = new Component(component);
        assertThat(dto.uuid()).isEqualTo(uuid);
        assertThat(dto.group()).isEqualTo("group");
        assertThat(dto.name()).isEqualTo("name");
        assertThat(dto.version()).isEqualTo("version");
        assertThat(dto.purl()).isEqualTo("pkg:maven/foo/bar@1.2.3");
        assertThat(dto.cpe()).isEqualTo("cpe");
    }

}