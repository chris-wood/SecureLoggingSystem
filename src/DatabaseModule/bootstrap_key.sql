create table entityKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob, inserted_at varchar(255) not null);
create table epochKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob, inserted_at varchar(255) not null);
create table initialEntityKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob, inserted_at varchar(255) not null);
create table initialEpochKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob, inserted_at varchar(255) not null);
create table policyKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, policy blob, key blob, iv blob, inserted_at varchar(255) not null); 
