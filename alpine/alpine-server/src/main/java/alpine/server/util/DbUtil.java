/*
 * This file is part of Alpine.
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
package alpine.server.util;

import javax.annotation.WillClose;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DbUtil {

    private static final String H2_PLATFORM_NAME = "H2";
    private static final String MSSQL_PLATFORM_NAME = "Microsoft SQL Server";
    private static final String MYSQL_PLATFORM_NAME = "MySQL";
    private static final String ORACLE_PLATFORM_NAME = "Oracle";
    private static final String POSTGRESQL_PLATFORM_NAME = "PostgreSQL";

    private static String platform;

    public static void rollback(Connection connection) {
        try {
            if (connection != null) {
                connection.rollback();
            }
        } catch (SQLException e) {
            // throw it away
        }
    }

    @WillClose
    public static void close(Statement statement) {
        try {
            if (statement != null) {
                statement.close();
            }
        } catch (SQLException e) {
            // throw it away
        }
    }

    @WillClose
    public static void close(ResultSet resultSet) {
        try {
            if (resultSet != null) {
                resultSet.close();
            }
        } catch (SQLException e) {
            // throw it away
        }
    }

    @WillClose
    public static void close(Connection connection) {
        try {
            if (connection != null) {
                connection.close();
            }
        } catch (SQLException e) {
            // throw it away
        }
    }

    public static void initPlatformName(Connection connection) {
        try {
            DatabaseMetaData dbmd = connection.getMetaData();
            platform = dbmd.getDatabaseProductName();
        } catch (SQLException e) {
            // throw it away
        }
    }

    public static boolean isH2() {
        return platform != null && platform.equalsIgnoreCase(H2_PLATFORM_NAME);
    }

    public static boolean isMssql() {
        return platform != null && platform.equalsIgnoreCase(MSSQL_PLATFORM_NAME);
    }

    public static boolean isMysql() {
        return platform != null && platform.equalsIgnoreCase(MYSQL_PLATFORM_NAME);
    }

    public static boolean isOracle() {
        return platform != null && platform.equalsIgnoreCase(ORACLE_PLATFORM_NAME);
    }

    public static boolean isPostgreSQL() {
        return platform != null && platform.equalsIgnoreCase(POSTGRESQL_PLATFORM_NAME);
    }

}
