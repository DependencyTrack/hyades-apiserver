package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.proto.policy.v1.VersionDistance;

public class VersionDistanceCelScriptBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = Logger.getLogger(VersionDistanceCelScriptBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {
        return """
                component.version_distance("%s", %s)
                    """.formatted(comparator(policyCondition.getOperator()), toProtoString(policyCondition.getValue()));
    }


    private String toProtoString(String conditionValue) {
        try {
            VersionDistance.Builder structBuilder = VersionDistance.newBuilder();
            JsonFormat.parser().ignoringUnknownFields().merge(conditionValue, structBuilder);
            return convertToString(structBuilder.build());
        } catch (InvalidProtocolBufferException e) {
            LOGGER.error("Invalid version distance proto " + e);
            return convertToString(VersionDistance.newBuilder().build());
        }
    }

    private String convertToString(VersionDistance versionDistance) {
        StringBuilder sbf = new StringBuilder();
        if (!StringUtils.isEmpty(versionDistance.getEpoch())) {
            sbf.append("epoch:").append("\"").append(versionDistance.getEpoch()).append("\"").append(",");
        }
        sbf.append("major:").append("\"").append(versionDistance.getMajor()).append("\"").append(",");
        sbf.append("minor:").append("\"").append(versionDistance.getMinor()).append("\"").append(",");
        sbf.append("patch:").append("\"").append(versionDistance.getPatch()).append("\"");
        return "v1.VersionDistance{" + sbf + "}";
    }

    private String comparator(PolicyCondition.Operator operator) {
        return switch (operator) {
            case NUMERIC_GREATER_THAN -> ">";
            case NUMERIC_GREATER_THAN_OR_EQUAL -> ">=";
            case NUMERIC_EQUAL -> "==";
            case NUMERIC_NOT_EQUAL -> "!=";
            case NUMERIC_LESSER_THAN_OR_EQUAL -> "<=";
            case NUMERIC_LESS_THAN -> "<";
            default -> "";
        };
    }
}
