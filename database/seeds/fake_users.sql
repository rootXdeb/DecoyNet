-- Fake enterprise user accounts (honey data)
INSERT OR IGNORE INTO honey_users (id, username, email, role, pw_hash, created) VALUES
(1,  'alice.smith',   'alice.smith@corp.internal',   'developer', '$6$FAKE$hash_alice_001',   1672531200),
(2,  'bob.jones',     'bob.jones@corp.internal',     'sysadmin',  '$6$FAKE$hash_bob_002',     1672617600),
(3,  'charlie.taylor','charlie.taylor@corp.internal','analyst',   '$6$FAKE$hash_charlie_003', 1672704000),
(4,  'diana.brown',   'diana.brown@corp.internal',   'devops',    '$6$FAKE$hash_diana_004',   1672790400),
(5,  'eve.wilson',    'eve.wilson@corp.internal',    'manager',   '$6$FAKE$hash_eve_005',     1672876800),
(6,  'frank.moore',   'frank.moore@corp.internal',   'developer', '$6$FAKE$hash_frank_006',   1672963200),
(7,  'grace.taylor',  'grace.taylor@corp.internal',  'sysadmin',  '$6$FAKE$hash_grace_007',   1673049600),
(8,  'henry.clark',   'henry.clark@corp.internal',   'analyst',   '$6$FAKE$hash_henry_008',   1673136000),
(9,  'iris.lewis',    'iris.lewis@corp.internal',    'devops',    '$6$FAKE$hash_iris_009',    1673222400),
(10, 'jack.walker',   'jack.walker@corp.internal',   'developer', '$6$FAKE$hash_jack_010',    1673308800);
