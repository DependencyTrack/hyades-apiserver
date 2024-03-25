package org.dependencytrack.persistence.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.JsonViews;
import org.dependencytrack.model.Tools;

public class ToolsJsonConverter extends AbstractJsonConverter<Tools> {

    public ToolsJsonConverter() {
        super(new TypeReference<>() {}, JsonViews.MetadataTools.class);
    }

    @Override
    public String convertToDatastore(final Tools attributeValue) {
        // Overriding is required for DataNucleus to correctly detect the return type.
        return super.convertToDatastore(attributeValue);
    }

    @Override
    public Tools convertToAttribute(final String datastoreValue) {
        // Overriding is required for DataNucleus to correctly detect the return type.
        return super.convertToAttribute(datastoreValue);
    }

}
