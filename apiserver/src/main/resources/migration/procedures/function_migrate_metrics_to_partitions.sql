CREATE OR REPLACE FUNCTION "MIGRATE_METRICS_TO_PARTITIONS"(target_table TEXT)
    RETURNS void
    LANGUAGE plpgsql
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
    SELECT COALESCE(cp."PROPERTYVALUE"::INTEGER, 90)
    INTO retention_days
    FROM "CONFIGPROPERTY" cp
    WHERE cp."GROUPNAME" = 'maintenance'
      AND cp."PROPERTYNAME" = 'metrics.retention.days';

    start_date := current_date - retention_days;
    partition_date := start_date;

    WHILE partition_date < end_date LOOP
        next_day := partition_date + INTERVAL '1 day';
        partition_name := format('%I_%s', target_table, to_char(partition_date, 'YYYYMMDD'));

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
             FOR VALUES FROM (%L) TO (%L);',
            partition_name,
            target_table,
            partition_date,
            next_day
        );

        partition_date := next_day;
    END LOOP;
END;
$$;
