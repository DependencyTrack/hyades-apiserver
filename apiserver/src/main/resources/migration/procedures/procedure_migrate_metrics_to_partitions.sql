CREATE OR REPLACE PROCEDURE "MIGRATE_METRICS_TO_PARTITIONS"(
    target_table TEXT,
    source_table TEXT
)
LANGUAGE "plpgsql"
AS
$$
DECLARE
    retention_days INTEGER := 90;
    start_date DATE;
    end_date DATE := current_date;
    partition_date DATE;
    partition_name TEXT;
    next_day DATE;
BEGIN
    -- Fetch retention value from config
    SELECT COALESCE((
        SELECT cp."PROPERTYVALUE"::INTEGER
        FROM "CONFIGPROPERTY" cp
        WHERE cp."GROUPNAME" = 'maintenance'
          AND cp."PROPERTYNAME" = 'metrics.retention.days'
    ), 90)
    INTO retention_days;

    start_date := current_date - retention_days;
    partition_date := start_date;

    -- Create partitions for each day starting from retention period
    WHILE partition_date < end_date LOOP
        next_day := partition_date + INTERVAL '1 day';
        partition_name := format('%s_%s', source_table, to_char(partition_date, 'YYYYMMDD'));

        -- Create partition if it doesn't exist
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
             FOR VALUES FROM (%L) TO (%L);',
            partition_name,
            target_table,
            partition_date,
            next_day
        );

        -- Insert data from existing table into this partition
        EXECUTE format(
            'INSERT INTO %I SELECT * FROM %I WHERE "LAST_OCCURRENCE" >= %L AND "LAST_OCCURRENCE" < %L;',
            target_table,
            source_table,
            partition_date,
            next_day
        );

        partition_date := next_day;
    END LOOP;
END;
$$;
