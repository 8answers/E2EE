-- Encrypted project payload storage for app-side end-to-end encryption rollout.
-- The database stores ciphertext-only payload blobs.

CREATE TABLE IF NOT EXISTS project_secure_payloads (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    key_version INTEGER NOT NULL DEFAULT 1,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    mac_b64 TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_project_secure_payloads_user_id
    ON project_secure_payloads(user_id);

ALTER TABLE project_secure_payloads ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own secure payloads"
    ON project_secure_payloads
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own secure payloads"
    ON project_secure_payloads
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own secure payloads"
    ON project_secure_payloads
    FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own secure payloads"
    ON project_secure_payloads
    FOR DELETE
    USING (auth.uid() = user_id);
