package org.dependencytrack.upgrade.v510;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class v510Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v510Updater.class);

    @Override
    public String getSchemaVersion() {
        return "5.1.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        changePolicyConditionValueTypeToText(connection);
    }

    private static void changePolicyConditionValueTypeToText(final Connection connection) throws Exception {
        LOGGER.info("Changing type of \"POLICYCONDITION\".\"VALUE\" from VARCHAR(255) to TEXT");
        try (final PreparedStatement ps = connection.prepareStatement("""
                ALTER TABLE "POLICYCONDITION" ALTER COLUMN "VALUE" TYPE TEXT;
                """)) {
            ps.execute();
        }
    }

}
