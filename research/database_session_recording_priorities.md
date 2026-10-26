# Database Session Recording Priorities for HashiCorp Boundary

## Executive Summary

This document identifies the top 5 databases that would provide the highest value for credential injection and session recording support in HashiCorp Boundary. Prioritization considers market share, enterprise adoption, security/compliance requirements, and alignment with Boundary's existing plugin architecture.

## Current Boundary Architecture Analysis

### Existing Support
- **Backend Database**: PostgreSQL only (required for Boundary's own state)
- **Target Types**: TCP, SSH, RDP
- **Session Recording**: Currently implemented for SSH (multiplexed protocols with channel recording)
- **Credential Management**: Brokered and injected application credential sources
- **Plugin Architecture**: 
  - Host plugins (AWS, Azure, GCP for dynamic host catalogs)
  - Storage plugins (MinIO for session recording storage)
  - KMS plugins (AWS KMS, Azure Key Vault, GCP KMS, etc.)

### Plugin Service Model
Boundary uses HashiCorp's go-plugin framework with gRPC for extensibility:
- `HostPluginService` - Dynamic host catalog operations
- `StoragePluginService` - Session recording storage backends

## Prioritized Database List

---

## 1. PostgreSQL (Highest Priority)

### Justification

**Market Share & Enterprise Usage:**
- #4 most popular database overall (DB-Engines Ranking 2024)
- #2 open-source database after MySQL
- Default choice for enterprise applications requiring ACID compliance
- Widely adopted in financial services, healthcare, and government sectors

**Security & Compliance Value:**
- **PCI-DSS**: Required audit trails for cardholder data access
- **HIPAA**: Database activity monitoring for PHI access
- **SOX**: Financial data access logging and query auditing
- **GDPR**: Data access tracking for personal information
- **FedRAMP**: Government cloud compliance requirements

**Technical Fit with Boundary:**
- Protocol runs over standard TCP (port 5432)
- Supports SSL/TLS encryption natively
- Well-documented wire protocol for session parsing
- Connection strings support credential injection patterns
- Existing Boundary PostgreSQL backend demonstrates team expertise

**Session Recording Value:**
- SQL query capture for audit trails
- Credential rotation without application changes
- Privileged access monitoring for DBAs
- Data exfiltration detection via query analysis

**Implementation Complexity:** Low-Medium
- TCP-based protocol (fits existing TCP target model)
- Clear authentication handshake for credential injection
- Text-based query protocol simplifies recording parsing

---

## 2. MySQL / MariaDB (High Priority)

### Justification

**Market Share & Enterprise Usage:**
- #1 most popular open-source database (DB-Engines)
- #3 overall database popularity
- Powers majority of web applications (LAMP stack)
- Enterprise MySQL widely deployed in Fortune 500 companies
- MariaDB gaining traction as MySQL alternative

**Security & Compliance Value:**
- **PCI-DSS**: Payment data access auditing
- **HIPAA**: Healthcare application backends
- **SOC 2**: SaaS application database access controls
- **ISO 27001**: Information security management

**Technical Fit with Boundary:**
- TCP-based protocol (port 3306)
- Native SSL/TLS support
- Well-documented protocol specification
- Standard credential patterns (username/password)
- Compatible with existing TCP target infrastructure

**Session Recording Value:**
- Query logging for compliance audits
- Privileged user activity monitoring
- Schema change tracking
- Data access pattern analysis

**Implementation Complexity:** Low-Medium
- Similar to PostgreSQL in architecture
- Mature protocol documentation
- Large install base for testing

---

## 3. Microsoft SQL Server (High Priority)

### Justification

**Market Share & Enterprise Usage:**
- #3 overall database popularity
- Dominant in enterprise Windows environments
- Standard in corporate IT infrastructure
- Heavy adoption in finance, healthcare, manufacturing

**Security & Compliance Value:**
- **PCI-DSS**: Enterprise payment systems
- **HIPAA**: Healthcare record systems
- **SOX**: Financial reporting databases
- **FedRAMP**: Government contractor systems
- **CJIS**: Criminal justice information systems

**Technical Fit with Boundary:**
- TCP-based (port 1433)
- TLS encryption support
- Windows Authentication and SQL Authentication
- TDS (Tabular Data Stream) protocol well-documented

**Session Recording Value:**
- Stored procedure execution auditing
- Schema modification tracking
- Privileged access monitoring (sysadmin roles)
- Compliance reporting for regulated industries

**Implementation Complexity:** Medium
- Proprietary protocol (TDS) requires careful implementation
- Windows Authentication integration considerations
- Enterprise demand justifies complexity

**Enterprise Demand Factor:** Very High
- Organizations running SQL Server typically have strict compliance requirements
- Willing to invest in security tooling
- Often require session recording for audits

---

## 4. MongoDB (Medium-High Priority)

### Justification

**Market Share & Enterprise Usage:**
- #1 NoSQL database (DB-Engines)
- #5 overall database popularity
- Standard for modern application development
- MongoDB Atlas cloud service widely adopted
- Popular in startups and tech companies

**Security & Compliance Value:**
- **PCI-DSS**: NoSQL data access auditing
- **HIPAA**: Document store for medical records
- **GDPR**: Personal data access tracking
- **SOC 2**: SaaS platform compliance

**Technical Fit with Boundary:**
- TCP-based (port 27017)
- TLS/SSL support
- SCRAM-SHA authentication
- Wire protocol documented

**Session Recording Value:**
- Query auditing for document access
- Aggregation pipeline monitoring
- Schema-less data access tracking
- Role-based access verification

**Implementation Complexity:** Medium
- NoSQL query patterns differ from SQL
- BSON protocol requires specific parsing
- Dynamic schemas complicate access auditing

**Strategic Consideration:**
- Represents NoSQL category coverage
- Important for modern application stacks
- Growing enterprise adoption

---

## 5. Oracle Database (Medium Priority)

### Justification

**Market Share & Enterprise Usage:**
- #2 overall database popularity
- Dominant in large enterprise, banking, telecommunications
- High-value deployments (critical infrastructure)
- Oracle Cloud Infrastructure growth

**Security & Compliance Value:**
- **PCI-DSS**: Financial transaction systems
- **SOX**: Financial reporting mandates
- **HIPAA**: Healthcare enterprise systems
- **Government**: Defense, intelligence agencies
- **Banking**: Regulatory compliance (Basel III, etc.)

**Technical Fit with Boundary:**
- TCP-based (port 1521)
- Advanced security features (TDE, Database Vault)
- Multiple authentication methods
- Proprietary Net8/SQL*Net protocol

**Session Recording Value:**
- PL/SQL execution auditing
- Privileged user monitoring (SYS, SYSTEM)
- Data change tracking
- Compliance reporting for auditors

**Implementation Complexity:** High
- Complex proprietary protocol
- Multiple authentication mechanisms
- Enterprise features add complexity
- Licensing considerations for testing

**Strategic Consideration:**
- Highest compliance requirements of any database
- Enterprise customers willing to pay for security
- Complex implementation may require dedicated resources

---

## Databases Not Prioritized (Yet)

### Redis
- **Use Case**: Caching, session storage, not primary data store
- **Compliance Value**: Lower (transient data)
- **Recommendation**: Future consideration for specific use cases

### Cassandra / ScyllaDB
- **Use Case**: Time-series, high-write workloads
- **Compliance Value**: Moderate
- **Recommendation**: After top 5 established

### Elasticsearch / OpenSearch
- **Use Case**: Search, logging, analytics
- **Compliance Value**: Moderate (log access auditing)
- **Recommendation**: Consider as specialized target type

### Snowflake / BigQuery
- **Use Case**: Cloud data warehouses
- **Compliance Value**: High
- **Recommendation**: Cloud-native integrations may differ from database plugin model

---

## Implementation Recommendations

### Phase 1: PostgreSQL + MySQL
- Covers ~60% of open-source database deployments
- Similar protocol patterns (SQL over TCP)
- Leverages existing TCP target infrastructure
- Fastest path to market

### Phase 2: Microsoft SQL Server
- Addresses enterprise Windows environments
- Highest compliance demand
- May require commercial partnerships for testing

### Phase 3: MongoDB
- NoSQL category coverage
- Modern application stack support
- Different protocol pattern (document-based)

### Phase 4: Oracle
- Enterprise flagship database
- Highest complexity
- Requires dedicated resources

---

## Plugin Architecture Recommendations

### Database Plugin Service
Consider extending Boundary's plugin architecture with a `DatabasePluginService`:

```go
type DatabasePluginService interface {
    // Connection handling
    EstablishConnection(ctx, credentials, target) -> Connection
    // Session recording
    RecordSession(connection) -> RecordingStream
    // Credential injection
    InjectCredentials(connection, credentials) -> error
    // Protocol-specific parsing
    ParseQuery(data) -> QueryInfo
}
```

### Credential Types to Support
1. **Username/Password** - Universal across all databases
2. **Certificate-based** - PostgreSQL, MySQL, MongoDB
3. **Kerberos/Windows Auth** - SQL Server, PostgreSQL
4. **IAM-based** - Cloud database services (RDS, Aurora, Cloud SQL)

### Session Recording Storage
- Leverage existing Storage Plugin architecture (MinIO, S3, Azure Blob, GCS)
- Support encryption at rest for recordings
- Implement retention policies per compliance requirements

---

## Compliance Mapping

| Database | PCI-DSS | HIPAA | SOX | GDPR | FedRAMP |
|----------|---------|-------|-----|------|---------|
| PostgreSQL | ✓ | ✓ | ✓ | ✓ | ✓ |
| MySQL | ✓ | ✓ | ✓ | ✓ | - |
| SQL Server | ✓ | ✓ | ✓ | ✓ | ✓ |
| MongoDB | ✓ | ✓ | - | ✓ | - |
| Oracle | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Conclusion

**Top 3 Immediate Priorities:**
1. **PostgreSQL** - Best balance of adoption, compliance value, and implementation complexity
2. **MySQL** - Largest install base, straightforward implementation
3. **SQL Server** - Highest enterprise compliance demand

These three databases cover approximately 70%+ of enterprise database deployments and address the majority of compliance requirements that drive session recording needs.

**Recommended Next Steps:**
1. Define database target type protobuf extensions
2. Design credential injection patterns for each protocol
3. Implement session recording for SQL query capture
4. Create database-specific plugins or extend TCP target with database awareness
5. Partner with enterprise customers for compliance validation
