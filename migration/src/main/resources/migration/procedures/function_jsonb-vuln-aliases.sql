CREATE OR REPLACE FUNCTION JSONB_VULN_ALIASES(
  "vuln_source" TEXT
, "vuln_id" TEXT
) RETURNS JSONB
  LANGUAGE "sql"
  PARALLEL SAFE
  STABLE
AS
$$
SELECT JSONB_AGG(DISTINCT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
         'cveId', "VA"."CVE_ID"
       , 'ghsaId', "VA"."GHSA_ID"
       , 'gsdId', "VA"."GSD_ID"
       , 'internalId', "VA"."INTERNAL_ID"
       , 'osvId', "VA"."OSV_ID"
       , 'sonatypeId', "VA"."SONATYPE_ID"
       , 'snykId', "VA"."SNYK_ID"
       , 'vulnDbId', "VA"."VULNDB_ID"
       )))
  FROM "VULNERABILITYALIAS" AS "VA"
 WHERE ("vuln_source" = 'NVD' AND "VA"."CVE_ID" = "vuln_id")
    OR ("vuln_source" = 'GITHUB' AND "VA"."GHSA_ID" = "vuln_id")
    OR ("vuln_source" = 'GSD' AND "VA"."GSD_ID" = "vuln_id")
    OR ("vuln_source" = 'INTERNAL' AND "VA"."INTERNAL_ID" = "vuln_id")
    OR ("vuln_source" = 'OSV' AND "VA"."OSV_ID" = "vuln_id")
    OR ("vuln_source" = 'SONATYPE' AND "VA"."SONATYPE_ID" = "vuln_id")
    OR ("vuln_source" = 'SNYK' AND "VA"."SNYK_ID" = "vuln_id")
    OR ("vuln_source" = 'VULNDB' AND "VA"."VULNDB_ID" = "vuln_id")
$$;