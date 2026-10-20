ALTER TABLE vulnerability_scans DROP CONSTRAINT IF EXISTS vulnerability_scans_scan_type_check;
ALTER TABLE vulnerability_scans ADD CONSTRAINT vulnerability_scans_scan_type_check CHECK (scan_type IN ('network','port','web','host','full'));
ALTER TABLE vulnerability_scans DROP CONSTRAINT IF EXISTS vulnerability_scans_scan_status_check;
ALTER TABLE vulnerability_scans ADD CONSTRAINT vulnerability_scans_scan_status_check CHECK (scan_status IN ('pending','running','completed','failed','stopped'));
ALTER TABLE network_alerts DROP CONSTRAINT IF EXISTS network_alerts_status_check;
ALTER TABLE network_alerts ADD CONSTRAINT network_alerts_status_check CHECK (status IN ('new','investigating','acknowledged','resolved','false_positive'));
