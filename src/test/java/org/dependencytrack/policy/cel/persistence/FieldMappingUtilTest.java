package org.dependencytrack.policy.cel.persistence;

import com.google.protobuf.Descriptors.Descriptor;
import org.hyades.proto.policy.v1.Component;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class FieldMappingUtilTest {

    @Test
    public void testGetFieldMappingsForComponentProjection() {
        final Descriptor protoDescriptor = Component.getDescriptor();

        assertThat(FieldMappingUtil.getFieldMappings(ComponentProjection.class)).allSatisfy(
                fieldMapping -> assertThat(protoDescriptor.findFieldByName(fieldMapping.protoFieldName())).isNotNull()
        );
    }

}