# Specification: Distributed Token Store Service (DTS)

## 1. Overview

This document specifies a Distributed Token Store (DTS) service designed to provide a high-performance, persistent, and optionally in-memory key-value storage solution for session data, OIDC flows, and tokens. The DTS will be implemented as a gRPC service, utilizing BBoltDB as its underlying storage engine. This service aims to offer an alternative to Redis or direct database calls for state that needs to be shared and rapidly accessed across multiple instances of the SSSO backend.

**Goals:**

*   **High Performance:** Leverage gRPC and an embedded key-value store (BBoltDB) for low-latency access.
*   **Persistence:** Ensure data durability by storing information on disk.
*   **Scalability:** While BBoltDB itself is a single-node database, the DTS service instances can be deployed alongside SSSO instances. The SSSO instances would be responsible for sharding or consistently routing requests to the appropriate DTS instance if a multi-node DTS solution is required (beyond this initial spec). This specification focuses on a single DTS node that SSSO instances connect to. A future extension could involve DTS nodes forming a cluster.
*   **Simplicity:** Provide a clear and straightforward gRPC API for common token and session management operations.
*   **Alternative to Redis/DB:** Offer a self-contained solution for distributed state without external dependencies like Redis, for specific use cases.

**Non-Goals (for this version):**

*   Automatic sharding or clustering of DTS nodes (DTS nodes are independent, SSSO instances manage connections).
*   Leader election among DTS nodes.
*   Cross-node data replication within the DTS service itself (persistence is per-node).

## 2. Architecture

*   **DTS Service:** A gRPC server written in Go.
    *   Manages a BBoltDB file for data persistence.
    *   Exposes gRPC endpoints for CRUD operations on various data types.
    *   Handles data serialization/deserialization (e.g., Protocol Buffers, JSON).
    *   Manages TTL (Time-To-Live) for stored entries.
*   **SSSO Backend Integration:**
    *   SSSO instances will act as gRPC clients to the DTS service.
    *   Configuration in SSSO will allow specifying the DTS service address(es).
    *   SSSO's existing repository interfaces (`domain.TokenRepository`, `oidcflow.InMemoryFlowStore`, `oidcflow.InMemoryUserSessionStore`, etc.) can be adapted or new implementations created to use the DTS client.

**BBoltDB Structure:**

The BBoltDB file will use separate buckets for different types of data to ensure organization and efficient querying/deletion.

*   `tokensBucket`: Stores various tokens (access, refresh, device codes, auth codes). Key: Token string or derived ID. Value: Serialized token data + metadata.
*   `sessionsBucket`: Stores user sessions for the OIDC Provider. Key: Session ID. Value: Serialized session data.
*   `flowsBucket`: Stores OIDC login flow states. Key: Flow ID. Value: Serialized flow state.
*   `deviceAuthBucket`: Stores device authorization grant details. Key: User Code or Device Code. Value: Serialized device auth data.

Each value will also include metadata like `ExpiresAt` to manage TTL.

## 3. gRPC Service Definition (`dts.proto`)

```protobuf
syntax = "proto3";

package dts.v1;

option go_package = "github.com/pilab-dev/ssso/gen/proto/dts/v1;dtsv1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";
import "google/protobuf/empty.proto";

// Service Definition
service TokenStoreService {
  // Generic Key-Value operations (can be used for simple data)
  rpc Set(SetRequest) returns (google.protobuf.Empty);
  rpc Get(GetRequest) returns (GetResponse);
  rpc Delete(DeleteRequest) returns (google.protobuf.Empty);

  // Specialized operations for SSSO objects
  // These might internally use the generic Set/Get/Delete but offer type safety
  // and potentially object-specific logic (e.g., indexing for specific fields if BBolt allows).

  // --- Authorization Codes ---
  rpc StoreAuthCode(StoreAuthCodeRequest) returns (google.protobuf.Empty);
  rpc GetAuthCode(GetAuthCodeRequest) returns (AuthCode);
  rpc DeleteAuthCode(DeleteAuthCodeRequest) returns (google.protobuf.Empty);

  // --- Refresh Tokens ---
  rpc StoreRefreshToken(StoreRefreshTokenRequest) returns (google.protobuf.Empty);
  rpc GetRefreshToken(GetRefreshTokenRequest) returns (RefreshToken);
  rpc DeleteRefreshToken(DeleteRefreshTokenRequest) returns (google.protobuf.Empty);

  // --- Access Tokens (if introspection details are stored) ---
  // Typically, access tokens are self-contained (JWTs), but if metadata needs to be stored:
  rpc StoreAccessTokenMetadata(StoreAccessTokenMetadataRequest) returns (google.protobuf.Empty);
  rpc GetAccessTokenMetadata(GetAccessTokenMetadataRequest) returns (AccessTokenMetadata);
  rpc DeleteAccessTokenMetadata(DeleteAccessTokenMetadataRequest) returns (google.protobuf.Empty);

  // --- OIDC Flows ---
  rpc StoreOIDCFlw(StoreOIDCFlwRequest) returns (google.protobuf.Empty);
  rpc GetOIDCFlw(GetOIDCFlwRequest) returns (OIDCFlw);
  rpc DeleteOIDCFlw(DeleteOIDCFlwRequest) returns (google.protobuf.Empty);
  rpc UpdateOIDCFlw(UpdateOIDCFlwRequest) returns (google.protobuf.Empty); // For updating user ID post-authentication

  // --- OIDC User Sessions ---
  rpc StoreUserSession(StoreUserSessionRequest) returns (google.protobuf.Empty);
  rpc GetUserSession(GetUserSessionRequest) returns (UserSession);
  rpc DeleteUserSession(DeleteUserSessionRequest) returns (google.protobuf.Empty);

  // --- Device Authorization Grants & Codes ---
  rpc StoreDeviceAuth(StoreDeviceAuthRequest) returns (google.protobuf.Empty);
  rpc GetDeviceAuthByDeviceCode(GetDeviceAuthByDeviceCodeRequest) returns (DeviceAuth);
  rpc GetDeviceAuthByUserCode(GetDeviceAuthByUserCodeRequest) returns (DeviceAuth);
  rpc UpdateDeviceAuth(UpdateDeviceAuthRequest) returns (google.protobuf.Empty); // e.g., to mark as approved
  rpc DeleteDeviceAuth(DeleteDeviceAuthRequest) returns (google.protobuf.Empty);

  // --- PKCE States ---
  rpc StorePKCEState(StorePKCEStateRequest) returns (google.protobuf.Empty);
  rpc GetPKCEState(GetPKCEStateRequest) returns (PKCEState);
  rpc DeletePKCEState(DeletePKCEStateRequest) returns (google.protobuf.Empty);

}

// --- Generic Messages ---
message SetRequest {
  string bucket = 1;
  string key = 2;
  bytes value = 3;
  google.protobuf.Duration ttl = 4; // Optional: Time to live for this key
}

message GetRequest {
  string bucket = 1;
  string key = 2;
}

message GetResponse {
  bytes value = 1;
  bool found = 2;
  google.protobuf.Timestamp expires_at = 3; // If TTL was set
}

message DeleteRequest {
  string bucket = 1;
  string key = 2;
}

// --- SSSO Object Definitions (mirroring domain objects) ---
// These should be simplified versions or direct mappings of existing domain objects.
// For brevity, only a few are detailed here. Others would follow a similar pattern.

message AuthCode {
  string code = 1;
  string client_id = 2;
  string user_id = 3;
  string redirect_uri = 4;
  string scope = 5;
  string code_challenge = 6;
  string code_challenge_method = 7;
  google.protobuf.Timestamp expires_at = 8;
  // Add other relevant fields from domain.AuthCodeData
}

message StoreAuthCodeRequest {
  AuthCode auth_code = 1;
}

message GetAuthCodeRequest {
  string code = 1;
}

message DeleteAuthCodeRequest {
  string code = 1;
}


message RefreshToken {
  string token = 1;
  string client_id = 2;
  string user_id = 3;
  string scope = 4;
  google.protobuf.Timestamp expires_at = 5;
  // Add other relevant fields from domain.RefreshTokenData
}
message StoreRefreshTokenRequest { RefreshToken refresh_token = 1; }
message GetRefreshTokenRequest { string token = 1; }
message DeleteRefreshTokenRequest { string token = 1; }


message AccessTokenMetadata {
  string token_hash = 1; // Or full token if not JWT and needs lookup
  string client_id = 2;
  string user_id = 3;
  string scope = 4;
  google.protobuf.Timestamp expires_at = 5;
  bool active = 6;
}
message StoreAccessTokenMetadataRequest { AccessTokenMetadata access_token_metadata = 1; }
message GetAccessTokenMetadataRequest { string token_hash = 1; }
message DeleteAccessTokenMetadataRequest { string token_hash = 1; }


message OIDCFlw {
  string flow_id = 1;
  string client_id = 2;
  string redirect_uri = 3;
  string scope = 4;
  string state = 5;
  string nonce = 6;
  string code_challenge = 7;
  string code_challenge_method = 8;
  google.protobuf.Timestamp expires_at = 9;
  string user_id = 10; // Populated after user authentication
  google.protobuf.Timestamp user_authenticated_at = 11;
  map<string, string> original_oidc_params = 12;
}
message StoreOIDCFlwRequest { OIDCFlw oidc_flow = 1; }
message GetOIDCFlwRequest { string flow_id = 1; }
message DeleteOIDCFlwRequest { string flow_id = 1; }
message UpdateOIDCFlwRequest { OIDCFlw oidc_flow = 1; }


message UserSession {
  string session_id = 1;
  string user_id = 2;
  google.protobuf.Timestamp authenticated_at = 3;
  google.protobuf.Timestamp expires_at = 4;
  string user_agent = 5;
  string ip_address = 6;
}
message StoreUserSessionRequest { UserSession user_session = 1; }
message GetUserSessionRequest { string session_id = 1; }
message DeleteUserSessionRequest { string session_id = 1; }


message DeviceAuth {
  string device_code = 1;
  string user_code = 2;
  string client_id = 3;
  string scope = 4;
  google.protobuf.Timestamp expires_at = 5;
  google.protobuf.Timestamp last_polled_at = 6;
  google.protobuf.Duration poll_interval = 7;
  string status = 8; // e.g., "pending", "approved", "denied", "expired"
  string user_id = 9; // if approved
}
message StoreDeviceAuthRequest { DeviceAuth device_auth = 1; }
message GetDeviceAuthByDeviceCodeRequest { string device_code = 1; }
message GetDeviceAuthByUserCodeRequest { string user_code = 1; }
message UpdateDeviceAuthRequest { DeviceAuth device_auth = 1; }
message DeleteDeviceAuthRequest { string device_code = 1; } // Or by user_code


message PKCEState {
    string code_hash = 1; // Hash of the authorization code this PKCE state is tied to
    string code_challenge = 2;
    string code_challenge_method = 3;
    google.protobuf.Timestamp expires_at = 4;
}
message StorePKCEStateRequest { PKCEState pkce_state = 1; }
message GetPKCEStateRequest { string code_hash = 1; }
message DeletePKCEStateRequest { string code_hash = 1; }

```

## 4. Data Handling

*   **Serialization:** Protocol Buffers will be used for serializing data before storing in BBoltDB. This ensures efficient storage and data compatibility with the gRPC layer.
*   **TTL Management:**
    *   The DTS service will be responsible for managing TTL.
    *   When an item is stored with a TTL, its `ExpiresAt` timestamp is also stored.
    *   A background goroutine in the DTS service will periodically scan relevant buckets for expired items and delete them.
    *   `Get` operations should also check for expiration and not return expired items (optionally deleting them on read if expired).
*   **Keys:** Keys will generally be the natural identifiers (e.g., token string, session ID, flow ID). For objects that might be queried by different attributes (like device auth by user_code or device_code), separate index entries or query methods might be needed if BBoltDB's prefix scans aren't sufficient. Initially, we'll rely on direct key lookups.

## 5. DTS Service Implementation Details

*   **BBoltDB Initialization:**
    *   Open/create a BBoltDB file at a configurable path.
    *   Create necessary buckets (`tokensBucket`, `sessionsBucket`, etc.) if they don't exist.
*   **gRPC Server:**
    *   Implement the `TokenStoreService` interface.
    *   Each RPC handler will interact with BBoltDB within a transaction (`db.Update` or `db.View`).
*   **Error Handling:** Clear gRPC status codes will be used to indicate success or failure (e.g., `NOT_FOUND`, `INVALID_ARGUMENT`, `INTERNAL`).
*   **Configuration:**
    *   BBoltDB file path.
    *   gRPC server address.
    *   Default TTLs for various data types (if not specified in requests).
    *   TTL cleanup interval.

## 6. SSSO Backend Adaptation

*   **New Repository Implementations:**
    *   Create new implementations for `domain.TokenRepository`, `oidcflow.FlowStore`, `oidcflow.UserSessionStore`, `services.PKCEService`'s store dependency, etc., that use the DTS gRPC client.
    *   For example, a `dtsTokenRepository` would implement `StoreAuthCode`, `FetchAuthCodeData`, etc., by calling the corresponding gRPC methods on the DTS.
*   **Client Configuration:**
    *   SSSO configuration will include the address of the DTS gRPC service.
    *   Mechanisms for connection pooling and retries for the gRPC client should be considered.
*   **Conditional Logic:** SSSO will need a way to switch between using the current MongoDB-backed repositories and the new DTS-backed repositories based on configuration.

## 7. Deployment Considerations

*   The DTS service can be deployed as a separate container/process alongside each SSSO instance or as a shared service (though a single shared BBoltDB instance doesn't scale writes well).
*   If deployed per SSSO instance, data is not shared between SSSO instances via DTS unless SSSO itself implements routing to specific DTS instances.
*   For true distributed consensus or replication, a different backend than BBoltDB (like etcd, Consul, or a clustered DB) would be needed for the DTS, or a clustering layer built on top of multiple DTS/BBoltDB nodes. This spec assumes a simpler model where SSSO instances connect to one or more independent DTS nodes.

## 8. Future Considerations / Extensions

*   **DTS Clustering:** Implementing a Raft-based or gossip-based clustering mechanism for DTS nodes to replicate data and provide high availability.
*   **Advanced Indexing:** If BBoltDB's key-prefix scanning is insufficient, explore adding secondary indexing capabilities within DTS.
*   **Metrics & Monitoring:** Expose Prometheus metrics from the DTS service (e.g., request latency, error rates, cache hit/miss if an in-memory layer is added).
*   **Optional In-Memory Mode:** Allow DTS to run purely in-memory (without BBoltDB persistence) for use cases where extreme speed is needed and data loss on restart is acceptable (e.g., for short-lived flows). This would likely be a compile-time or startup flag.

This specification provides a starting point for developing the Distributed Token Store service. Further details will emerge during the design and implementation phases.
