package org.dependencytrack;

import org.datanucleus.PropertyNames;

import java.util.Properties;

public class TestUtil {

    public static Properties getDatanucleusProperties(String jdbcUrl, String driverName, String username, String pwd) {
        final var dnProps = new Properties();
        dnProps.put(PropertyNames.PROPERTY_PERSISTENCE_UNIT_NAME, "Alpine");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_DATABASE, "false");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_TABLES, "false");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_COLUMNS, "false");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_CONSTRAINTS, "false");
        dnProps.put("datanucleus.schema.generatedatabase.mode", "none");
        dnProps.put("datanucleus.query.jdoql.allowall", "true");
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_URL, jdbcUrl);
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, driverName);
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_USER_NAME, username);
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_PASSWORD, pwd);
        return dnProps;
    }
}
