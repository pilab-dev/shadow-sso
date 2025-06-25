# Distributed Token Store (DTS) - Functional Specification

## 1. Introduction

This document describes the functional requirements for the Distributed Token Store (DTS) service. The DTS provides a backend storage mechanism for the SSSO (Shadow SSO) application, focusing on high performance and data persistence for ephemeral and semi-persistent OIDC and OAuth2 related data such as authorization codes, refresh tokens, OIDC flow states, user sessions, device authorization grants, and PKCE states. It utilizes gRPC for communication and BBoltDB for data storage.

This document is derived from the technical specification `DISTRIBUTED_TOKEN_STORE_SPEC.md`.

## 2. Goals and Scope

### 2.1. Goals

*   **Store and Retrieve OIDC/OAuth2 Artifacts:** The primary function is to reliably store and retrieve various data artifacts generated during OIDC and OAuth2 flows.
*   **Data Expiration (TTL):** Automatically manage the lifecycle of stored data through Time-To-Live (TTL) mechanisms.
*   **Data Persistence:** Ensure that stored data survives service restarts by persisting it to disk using BBoltDB.
*   **High Availability (Single Node):** The service itself should be resilient, but this specification covers a single-node DTS. High availability of the SSSO system using DTS would involve multiple DTS instances managed by SSSO.
*   **Clear API:** Offer a well-defined gRPC API for interaction.

### 2.2. Out of Scope (for this version)

*   Data replication or synchronization between multiple DTS instances.
*   Automatic sharding of data across multiple DTS instances.
*   User interface for managing the DTS.

## 3. Functional Requirements

### 3.1. General Storage Operations

The DTS must provide generic key-value storage capabilities, which can be used directly or as the basis for more specialized object storage.

*   **FR-DTS-GEN-001: Store Key-Value Pair:** The system shall allow a client to store an arbitrary byte array value associated with a string key within a specified bucket.
*   **FR-DTS-GEN-002: Store Key-Value Pair with TTL:** The system shall allow a client to store a key-value pair with an associated Time-To-Live (TTL). After the TTL expires, the key-value pair should be effectively inaccessible and eventually removed.
*   **FR-DTS-GEN-003: Retrieve Key-Value Pair:** The system shall allow a client to retrieve the value associated with a string key from a specified bucket. If the key is not found or has expired, this should be indicated.
*   **FR-DTS-GEN-004: Delete Key-Value Pair:** The system shall allow a client to delete a key-value pair from a specified bucket using its key.
*   **FR-DTS-GEN-005: Bucket Isolation:** Data stored in one bucket must not be accessible or interfere with data in another bucket.

### 3.2. Specialized SSSO Artifact Storage

The DTS must provide specialized operations for storing, retrieving, and managing common SSSO artifacts. These operations ensure type safety and encapsulate artifact-specific logic.

#### 3.2.1. Authorization Codes

*   **FR-DTS-AC-001: Store Authorization Code:** The system shall store authorization code details, including the code itself, client ID, user ID, redirect URI, scope, code challenge, code challenge method, and expiration time.
*   **FR-DTS-AC-002: Retrieve Authorization Code:** The system shall retrieve authorization code details using the authorization code string. An error or indication of absence shall be returned if the code is not found or has expired.
*   **FR-DTS-AC-003: Delete Authorization Code:** The system shall delete authorization code details using the authorization code string, typically after it has been exchanged for tokens.

#### 3.2.2. Refresh Tokens

*   **FR-DTS-RT-001: Store Refresh Token:** The system shall store refresh token details, including the token string, client ID, user ID, scope, and expiration time.
*   **FR-DTS-RT-002: Retrieve Refresh Token:** The system shall retrieve refresh token details using the token string. An error or indication of absence shall be returned if the token is not found or has expired.
*   **FR-DTS-RT-003: Delete Refresh Token:** The system shall delete refresh token details using the token string, typically when it's used or revoked.

#### 3.2.3. Access Token Metadata (Optional Storage)

While access tokens are often self-contained JWTs, the DTS may need to store metadata associated with them if required for features like active token tracking or custom introspection details.

*   **FR-DTS-AT-001: Store Access Token Metadata:** The system shall store metadata related to an access token, such as a token hash (if the token itself is not stored), client ID, user ID, scope, expiration time, and an active status.
*   **FR-DTS-AT-002: Retrieve Access Token Metadata:** The system shall retrieve access token metadata using a token hash or identifier.
*   **FR-DTS-AT-003: Delete Access Token Metadata:** The system shall delete access token metadata.

#### 3.2.4. OIDC Flow States

*   **FR-DTS-OF-001: Store OIDC Flow State:** The system shall store the state of an OIDC login flow, including flow ID, client ID, redirect URI, scope, state, nonce, code challenge, code challenge method, expiration time, and original OIDC parameters.
*   **FR-DTS-OF-002: Retrieve OIDC Flow State:** The system shall retrieve an OIDC flow state using its flow ID. An error or indication of absence shall be returned if the flow is not found or has expired.
*   **FR-DTS-OF-003: Update OIDC Flow State:** The system shall allow updating an existing OIDC flow state, for example, to add the authenticated User ID and authentication timestamp.
*   **FR-DTS-OF-004: Delete OIDC Flow State:** The system shall delete an OIDC flow state using its flow ID, typically after the flow is completed or abandoned.

#### 3.2.5. OIDC Provider User Sessions

*   **FR-DTS-US-001: Store User Session:** The system shall store details of an OIDC provider's user session, including session ID, user ID, authentication timestamp, expiration timestamp, user agent, and IP address.
*   **FR-DTS-US-002: Retrieve User Session:** The system shall retrieve user session details using the session ID. An error or indication of absence shall be returned if the session is not found or has expired.
*   **FR-DTS-US-003: Delete User Session:** The system shall delete user session details using the session ID, typically upon logout or session expiration.

#### 3.2.6. Device Authorization Grants

*   **FR-DTS-DA-001: Store Device Authorization Grant:** The system shall store details of a device authorization grant, including device code, user code, client ID, scope, expiration time, last polled time, poll interval, and status (e.g., "pending").
*   **FR-DTS-DA-002: Retrieve Device Authorization Grant by Device Code:** The system shall retrieve grant details using the device code.
*   **FR-DTS-DA-003: Retrieve Device Authorization Grant by User Code:** The system shall retrieve grant details using the user code.
*   **FR-DTS-DA-004: Update Device Authorization Grant:** The system shall allow updating an existing grant, for example, to change its status to "approved" and associate a user ID.
*   **FR-DTS-DA-005: Delete Device Authorization Grant:** The system shall delete a grant, typically after it's been exchanged for tokens or has expired.

#### 3.2.7. PKCE States

*   **FR-DTS-PKCE-001: Store PKCE State:** The system shall store PKCE-related state, including a hash of the authorization code it's associated with, the code challenge, code challenge method, and an expiration time.
*   **FR-DTS-PKCE-002: Retrieve PKCE State:** The system shall retrieve PKCE state using the associated authorization code hash.
*   **FR-DTS-PKCE-003: Delete PKCE State:** The system shall delete PKCE state, typically after the corresponding authorization code has been used.

### 3.3. Data Management

*   **FR-DTS-DM-001: TTL Enforcement - Read Path:** When data is requested, if it has an associated TTL and that TTL has expired, the data must not be returned as valid. It should be treated as if it does not exist.
*   **FR-DTS-DM-002: TTL Enforcement - Background Cleanup:** The system must include a mechanism to periodically scan and remove data items that have exceeded their TTL to reclaim storage space.
*   **FR-DTS-DM-003: Data Persistence:** All stored data (unless explicitly configured for in-memory only mode, which is a future consideration) must be persisted to disk using BBoltDB, ensuring data survives service restarts.
*   **FR-DTS-DM-004: Data Serialization:** Data must be serialized using Protocol Buffers before being stored in BBoltDB.

### 3.4. Service Configuration

*   **FR-DTS-CFG-001: BBoltDB File Path:** The system must be configurable with the file path for the BBoltDB database file.
*   **FR-DTS-CFG-002: gRPC Server Address:** The system must be configurable with the network address (host and port) on which the gRPC server will listen.
*   **FR-DTS-CFG-003: Default TTLs:** The system should allow configuration of default TTL values for different data types if not specified in individual storage requests.
*   **FR-DTS-CFG-004: TTL Cleanup Interval:** The system must be configurable for how frequently the background TTL cleanup process runs.

### 3.5. Error Handling

*   **FR-DTS-ERR-001: Clear gRPC Status Codes:** The gRPC API must use appropriate gRPC status codes to indicate success or specific error conditions (e.g., `OK`, `NOT_FOUND`, `INVALID_ARGUMENT`, `ALREADY_EXISTS`, `INTERNAL`).

## 4. Non-Functional Requirements

*   **NFR-DTS-PERF-001: Low Latency:** Read and write operations for individual items should ideally complete within single-digit milliseconds under moderate load (specific benchmarks TBD).
*   **NFR-DTS-REL-001: Stability:** The DTS service should be stable and operate continuously without frequent crashes or data corruption. BBoltDB's transactional nature should be leveraged.
*   **NFR-DTS-SEC-001: Secure Communication (Optional):** The gRPC communication channel can be secured using TLS, configurable by the deployer. (The DTS itself doesn't manage TLS certificates for SSSO but can use them for its own gRPC endpoint).
*   **NFR-DTS-MAINT-001: Maintainability:** The Go codebase for the DTS should be well-structured, documented, and include unit tests.

## 5. SSSO Backend Integration Points (Informative)

While this document focuses on the DTS's functionality, its utility is realized through integration with the SSSO backend. The SSSO backend will require:

*   gRPC client logic to communicate with the DTS.
*   Adapter implementations for its existing repository/store interfaces (e.g., `TokenRepository`, `FlowStore`) that delegate calls to the DTS client.
*   Configuration options to enable DTS usage and specify DTS service endpoint(s).

## 6. Future Considerations (Functional Implications)

*   **NFR-DTS-SCALE-001 (Future): Clustering for HA/Scale:** If DTS nodes were to form a cluster, functional requirements for data replication, consistency models, and node discovery would be needed.
*   **FR-DTS-QUERY-001 (Future): Advanced Querying:** If requirements arise for querying data by attributes other than the primary key, additional indexing or query methods would be specified.
*   **FR-DTS-MEM-001 (Future): In-Memory Mode:** Functional requirements for how an in-memory only mode would behave regarding data persistence and TTL.

This functional specification will guide the development and testing of the Distributed Token Store service.
