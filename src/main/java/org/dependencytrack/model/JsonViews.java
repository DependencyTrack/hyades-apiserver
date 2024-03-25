package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonView;

/**
 * Marker interfaces to be used in conjunction with Jackson's {@link JsonView} annotation.
 */
public class JsonViews {

    /**
     * Marks fields to be included when (de-)serializing {@link Tools}.
     */
    public interface MetadataTools {
    }

}
