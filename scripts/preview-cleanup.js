// MongoDB SSO Database Cleanup Preview Script
// This script shows what WOULD be cleaned up without actually deleting anything
//
// Usage:
//   mongosh "mongodb+srv://..." --file preview-cleanup.js

// Get database name from environment or use default
const dbName = typeof SSSO_MONGO_DB_NAME !== 'undefined' ? SSSO_MONGO_DB_NAME : 'sso_dev';
const db = db.getSiblingDB(dbName);

print("\n========================================");
print("  Shadow SSO MongoDB Cleanup Preview");
print("========================================");
print(`Database: ${dbName}`);
print("Mode: DRY RUN (no changes will be made)\n");

// Helper function to count and display
function previewDocs(collection, filter, description) {
    const count = db.getCollection(collection).countDocuments(filter);
    if (count > 0) {
        print(`⚠ ${collection}: ${count} documents ${description}`);
        return count;
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

print("\n--- Tokens ---");
let totalWouldDelete = 0;

totalWouldDelete += previewDocs("oauth_tokens", 
    { expires_at: { $lt: new Date() } }, 
    "would be removed (expired)");

if (userIds.length > 0) {
    totalWouldDelete += previewDocs("oauth_tokens", 
        { user_id: { $nin: userIds } }, 
        "would be removed (no valid user)");
}

if (clientIds.length > 0) {
    totalWouldDelete += previewDocs("oauth_tokens", 
        { client_id: { $nin: clientIds } }, 
        "would be removed (no valid client)");
}

print("\n--- Sessions ---");

if (userIds.length > 0) {
    totalWouldDelete += previewDocs("oauth_user_sessions", 
        { user_id: { $nin: userIds } }, 
        "would be removed (no valid user)");
}

if (userIds.length > 0) {
    totalWouldDelete += previewDocs("user_sessions_oidc", 
        { user_id: { $nin: userIds } }, 
        "would be removed (no valid user)");
}

print("\n--- Authorization Codes ---");

if (userIds.length > 0) {
    totalWouldDelete += previewDocs("oauth_auth_codes", 
        { user_id: { $nin: userIds } }, 
        "would be removed (no valid user)");
}

if (clientIds.length > 0) {
    totalWouldDelete += previewDocs("oauth_auth_codes", 
        { client_id: { $nin: clientIds } }, 
        "would be removed (no valid client)");
}

totalWouldDelete += previewDocs("oauth_auth_codes", 
    { expires_at: { $lt: new Date() } }, 
    "would be removed (expired)");

print("\n--- Device Authorizations ---");

if (userIds.length > 0) {
    totalWouldDelete += previewDocs("device_authorizations", 
        { user_id: { $nin: userIds, $exists: true } }, 
        "would be removed (no valid user)");
}

totalWouldDelete += previewDocs("device_authorizations", 
    { expires_at: { $lt: new Date() } }, 
    "would be removed (expired)");

print("\n--- Service Accounts ---");

if (clientIds.length > 0) {
    totalWouldDelete += previewDocs("service_accounts", 
        { client_id: { $nin: clientIds } }, 
        "would be removed (no valid client)");
}

print("\n--- Public Keys ---");

if (saIds.length > 0) {
    totalWouldDelete += previewDocs("public_keys", 
        { service_account_id: { $nin: saIds } }, 
        "would be removed (no valid service account)");
}

print("\n--- PKCE Challenges ---");

totalWouldDelete += previewDocs("oauth_pkce_challenges", 
    { created_at: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } }, 
    "would be removed (older than 24 hours)");

print("\n========================================");
print("  Preview Summary");
print("========================================");
print(`Total documents that would be removed: ${totalWouldDelete}`);
print("\nTo run the actual cleanup, execute:");
print(`  mongosh "${db.getMongo().toString()}" --file cleanup-mongodb.js`);
print("========================================\n");
