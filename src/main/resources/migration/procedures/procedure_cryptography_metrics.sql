CREATE OR REPLACE PROCEDURE "UPDATE_CRYPTOGRAPHY_METRICS"()
    LANGUAGE "plpgsql"
AS
$$
DECLARE
    "v_number_of_cryptographic_assets"                          INT;
    "v_most_used_algorithm_name"                                VARCHAR;
    "v_most_used_algorithm_percentage"                          DOUBLE PRECISION;
    "v_number_of_keys"                                          INT;
    "v_existing_id"                                             BIGINT; -- ID of the existing row that matches the data point calculated in this procedure
BEGIN
    SELECT COUNT(*)
    FROM "COMPONENT"
    WHERE "CLASSIFIER" = 'CRYPTOGRAPHIC_ASSET'
    INTO "v_number_of_cryptographic_assets";

    SELECT
        "NAME",
        COUNT("NAME") / SUM(COUNT(*)) OVER () * 100 percent
    FROM "COMPONENT" INNER JOIN "CRYPTO_PROPERTIES" CP on "COMPONENT"."CRYPTO_PROPERTIES_ID" = CP."ID"
    WHERE "CLASSIFIER" = 'CRYPTOGRAPHIC_ASSET' AND "ASSET_TYPE" = 'ALGORITHM'
    GROUP BY "NAME"
    INTO "v_most_used_algorithm_name", "v_most_used_algorithm_percentage";

    SELECT
        COUNT(*)
    FROM "COMPONENT"
        INNER JOIN "CRYPTO_PROPERTIES" CP on "COMPONENT"."CRYPTO_PROPERTIES_ID" = CP."ID"
        INNER JOIN "RELATED_CRYPTO_MATERIAL_PROPERTIES" RP on CP."RELATED_MATERIAL_PROPERTIES_ID" = RP."ID"
    WHERE "CLASSIFIER" = 'CRYPTOGRAPHIC_ASSET' AND "ASSET_TYPE" = 'RELATED_CRYPTO_MATERIAL' AND
          ("TYPE" = 'SECRET_KEY' OR "TYPE" = 'PUBLIC_KEY' OR "TYPE" = 'PRIVATE_KEY' OR "TYPE" = 'KEY')
    INTO "v_number_of_keys";

    SELECT "ID"
    FROM "CRYPTOGRAPHYMETRICS"
    WHERE "NUMBER_OF_CRYPTOGRAPHIC_ASSETS" = "v_number_of_cryptographic_assets"
        AND "MOST_USED_ALGORITHM_NAME" = "v_most_used_algorithm_name"
        AND "MOST_USED_ALGORITHM_PERCENTAGE" = "v_most_used_algorithm_percentage"
        AND "NUMBER_OF_KEYS" = "v_number_of_keys"
    ORDER BY "LAST_OCCURRENCE" DESC
    LIMIT 1
    INTO "v_existing_id";

    IF "v_existing_id" IS NOT NULL THEN
        UPDATE "CRYPTOGRAPHYMETRICS" SET "LAST_OCCURRENCE" = NOW() WHERE "ID" = "v_existing_id";
    ELSE
        INSERT INTO "CRYPTOGRAPHYMETRICS" ("NUMBER_OF_CRYPTOGRAPHIC_ASSETS",
                                        "MOST_USED_ALGORITHM_NAME",
                                        "MOST_USED_ALGORITHM_PERCENTAGE",
                                        "NUMBER_OF_KEYS",
                                        "FIRST_OCCURRENCE",
                                        "LAST_OCCURRENCE")
        VALUES ("v_number_of_cryptographic_assets",
                "v_most_used_algorithm_name",
                "v_most_used_algorithm_percentage",
                "v_number_of_keys",
                NOW(),
                NOW());
    END IF;
END;
$$;