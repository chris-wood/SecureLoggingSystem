create table entityKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table epochKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table initialEntityKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table initialEpochKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table policyKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, policy blob, key blob, iv blob); -- there has to be a better to store the crypto stuff (i.e. not blobs...)
