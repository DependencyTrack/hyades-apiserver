# Rating Source Tracking for OWASP Ratings

## Rating Source Hierarchy

Ratings are tracked with their source using the `RatingSource` enum, which enforces the following precedence order (highest to lowest):

1. **POLICY** (Precedence: 4) - Rating applied by organizational policies
2. **VEX** (Precedence: 3) - Rating from VEX documents (authoritative context-specific assessment)
3. **MANUAL** (Precedence: 2) - User-provided rating (analyst notes)
4. **NVD** (Precedence: 1) - Default rating from vulnerability databases

**Rationale:** POLICY has highest precedence to enforce organizational security standards. VEX can overwrite MANUAL assessments as it represents authoritative context-aware analysis. MANUAL ratings serve as analyst notes but are subject to policy enforcement.

## Precedence Rules

- Higher precedence sources can overwrite lower precedence sources
- Equal precedence sources can overwrite each other (updates)
- Lower precedence sources **cannot** overwrite higher precedence sources

**Examples:**

```
POLICY (8.0) ← VEX (7.2)     ✗ VEX cannot overwrite POLICY
VEX (7.2)    ← MANUAL (9.0)  ✗ MANUAL cannot overwrite VEX
MANUAL (5.0) ← NVD (5.3)     ✗ NVD cannot overwrite MANUAL
VEX (7.2)    ← VEX (8.5)     ✓ Updated VEX can overwrite previous VEX
POLICY (8.0) ← POLICY (9.0)  ✓ Updated POLICY can overwrite previous POLICY
```