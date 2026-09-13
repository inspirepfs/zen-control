BEGIN TRANSACTION;
CREATE TABLE profiles (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 desired_mode TEXT NOT NULL DEFAULT 'normal',
 bandwidth_preset TEXT NOT NULL DEFAULT 'normal',
 notes TEXT NOT NULL DEFAULT '',
 blocked_services TEXT NOT NULL DEFAULT '[]'
);
INSERT INTO profiles(name,desired_mode,bandwidth_preset,notes,blocked_services)
VALUES('v054 child','slow','slow','retain-v054','["youtube"]');
CREATE TABLE device_policy (
 ip TEXT PRIMARY KEY,
 alias TEXT NOT NULL DEFAULT '',
 notes TEXT NOT NULL DEFAULT '',
 profile_id INTEGER NULL,
 mode_override TEXT NOT NULL DEFAULT 'inherit',
 FOREIGN KEY(profile_id) REFERENCES profiles(id)
);
INSERT INTO device_policy(ip,alias,notes,profile_id,mode_override)
VALUES('192.0.2.54','v054 tablet','retain-v054-device',1,'inherit');
CREATE TABLE policy_templates (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 desired_mode TEXT NOT NULL,
 bandwidth_preset TEXT NOT NULL,
 notes TEXT NOT NULL DEFAULT '',
 blocked_services TEXT NOT NULL DEFAULT '[]'
);
INSERT INTO policy_templates(name,desired_mode,bandwidth_preset,notes,blocked_services)
VALUES('v054 template','normal','normal','retain-v054-template','[]');
CREATE TABLE services (
 key TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '',
 builtin INTEGER NOT NULL DEFAULT 0
);
INSERT INTO services(key,name,description,builtin) VALUES('youtube','YouTube','legacy builtin',1);
CREATE TABLE policy_state_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 captured_at TEXT NOT NULL,
 ip TEXT NOT NULL,
 state_hash TEXT NOT NULL,
 source TEXT NOT NULL DEFAULT 'effective-resolver',
 desired_mode TEXT NOT NULL,
 mode_source TEXT NOT NULL DEFAULT '',
 bandwidth_preset TEXT NOT NULL DEFAULT 'normal',
 blocked_services TEXT NOT NULL DEFAULT '[]',
 policy_groups TEXT NOT NULL DEFAULT '[]',
 schedule_active INTEGER NOT NULL DEFAULT 0,
 schedule_reason TEXT NOT NULL DEFAULT '',
 active_date_exception TEXT NOT NULL DEFAULT '{}',
 quota_state TEXT NOT NULL DEFAULT '{}',
 policy_at TEXT NOT NULL DEFAULT ''
);
INSERT INTO policy_state_history(captured_at,ip,state_hash,desired_mode)
VALUES('2026-09-01T12:00:00+01:00','192.0.2.54','v054-state','slow');
COMMIT;
