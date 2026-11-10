-- Simulated database backup for the offline fixture. No real data.
-- connection: mysql://dbadmin:Db9#vaultKey@10.0.0.5:3306/appdb
CREATE TABLE device_settings (
    id INTEGER PRIMARY KEY,
    setting_name TEXT NOT NULL,
    setting_value TEXT
);
INSERT INTO device_settings VALUES (1, 'service_mode', 'test');
