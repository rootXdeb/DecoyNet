-- Fake API keys (honey data — none of these are real)
INSERT OR IGNORE INTO honey_api_keys (user_id, key, scope, active) VALUES
(1,  'sk-prod-FAKEKEY0000000000000000000000001', 'read:data,write:data',  1),
(2,  'sk-prod-FAKEKEY0000000000000000000000002', 'admin',                 1),
(3,  'sk-prod-FAKEKEY0000000000000000000000003', 'read:data',             1),
(4,  'sk-prod-FAKEKEY0000000000000000000000004', 'deploy',                1),
(5,  'sk-prod-FAKEKEY0000000000000000000000005', 'read:data,write:data',  0),
(1,  'sk-dev-FAKEKEY00000000000000000000000006', 'read:data',             1),
(6,  'sk-prod-FAKEKEY0000000000000000000000007', 'analytics',             1),
(7,  'sk-prod-FAKEKEY0000000000000000000000008', 'admin',                 0),
(8,  'sk-prod-FAKEKEY0000000000000000000000009', 'read:data',             1),
(9,  'sk-prod-FAKEKEY0000000000000000000000010', 'deploy,write:data',     1);
