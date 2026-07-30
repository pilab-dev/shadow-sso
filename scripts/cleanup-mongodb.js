// MongoDB SSO Database Cleanup Script
// This script removes orphaned data from the shadow-sso MongoDB database
//
// Usage:
//   mongosh "mongodb+srv://..." --file cleanup-mongodb.js
//
// Or with environment variables:
//   SSSO_MONGO_URI="mongodb+srv://..." SSSO_MONGO_DB_NAME="sso_dev" mongosh --file cleanup-mongodb.js

// Get database name from environment or use default
const dbName = typeof SSSO_MONGO_DB_NAME !== 'undefined' ? SSSO_MONGO_DB_NAME : 'sso_dev';
const db = db.getSiblingDB(dbName);

print("\n========================================");
print("  Shadow SSO MongoDB Cleanup");
print("========================================");
print(`Database: ${dbName}\n`);

let totalDeleted = 0;

// Helper function to count documents
function countDocs(collection, filter) {
    return db.getCollection(collection).countDocuments(filter);
}

// Helper function to delete documents
function deleteDocs(collection, filter, description) {
    const count = countDocs(collection, filter);
    if (count > 0) {
        const result = db.getCollection(collection).deleteMany(filter);
        print(`✓ Removed ${result.deletedCount} documents from ${collection}: ${description}`);
        totalDeleted += result.deletedCount;
        return result.deletedCount;
    }
    return 0;
}

// Get all valid user IDs
const userIds = db.getCollection("oauth_users").find({}, { _id: 1 }).map(doc => doc._id);
print(`Found ${userIds.length} valid users`);

// Get all valid client IDs
const clientIds = db.getCollection("oauth_clients").find({}, { client_id: 1 }).map(doc => doc.client_id);
print(`Found ${clientIds.length} valid clients`);

// Get all valid service account IDs
const saIds = db.getCollection("service_accounts").find({}, { _id: 1 }).map(doc => doc._id);
print(`Found ${saIds.length} valid service accounts`);

print("\n--- Cleaning Tokens ---");

// 1. Clean expired tokens
deleteDocs("oauth_tokens", 
    { expires_at: { $lt: new Date() } }, 
    "expired tokens");

// 2. Clean tokens without valid users
if (userIds.length > 0) {
    deleteDocs("oauth_tokens", 
        { user_id: { $nin: userIds } }, 
        "tokens without valid users");
}

// 3. Clean tokens without valid clients
if (clientIds.length > 0) {
    deleteDocs("oauth_tokens", 
        { client_id: { $nin: clientIds } }, 
        "tokens without valid clients");
}

print("\n--- Cleaning Sessions ---");

// 4. Clean sessions without valid users
if (userIds.length > 0) {
    deleteDocs("oauth_user_sessions", 
        { user_id: { $nin: userIds } }, 
        "sessions without valid users");
}

// 5. Clean OIDC sessions without valid users
if (userIds.length > 0) {
    deleteDocs("user_sessions_oidc", 
        { user_id: { $nin: userIds } }, 
        "OIDC sessions without valid users");
}

print("\n--- Cleaning Authorization Codes ---");

// 6. Clean auth codes without valid users
if (userIds.length > 0) {
    deleteDocs("oauth_auth_codes", 
        { user_id: { $nin: userIds } }, 
        "auth codes without valid users");
}

// 7. Clean auth codes without valid clients
if (clientIds.length > 0) {
    deleteDocs("oauth_auth_codes", 
        { client_id: { $nin: clientIds } }, 
        "auth codes without valid clients");
}

// 8. Clean expired auth codes
deleteDocs("oauth_auth_codes", 
    { expires_at: { $lt: new Date() } }, 
    "expired auth codes");

print("\n--- Cleaning Device Authorizations ---");

// 9. Clean device authorizations without valid users
if (userIds.length > 0) {
    deleteDocs("device_authorizations", 
        { user_id: { $nin: userIds, $exists: true } }, 
        "device authorizations without valid users");
}

// 10. Clean expired device authorizations
deleteDocs("device_authorizations", 
    { expires_at: { $lt: new Date() } }, 
    "expired device authorizations");

print("\n--- Cleaning Service Accounts ---");

// 11. Clean service accounts without valid clients
if (clientIds.length > 0) {
    deleteDocs("service_accounts", 
        { client_id: { $nin: clientIds } }, 
        "service accounts without valid clients");
}

print("\n--- Cleaning Public Keys ---");

// 12. Clean public keys without valid service accounts
if (saIds.length > 0) {
    deleteDocs("public_keys", 
        { service_account_id: { $nin: saIds } }, 
        "public keys without valid service accounts");
}

print("\n--- Cleaning PKCE Challenges ---");

// 13. Clean expired PKCE challenges (they should be short-lived)
deleteDocs("oauth_pkce_challenges", 
    { created_at: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }, 
    "PKCE challenges older than 24 hours");

print("\n========================================");
print("  Cleanup Summary");
print("========================================");
print(`Total documents removed: ${totalDeleted}`);
print("========================================\n");
