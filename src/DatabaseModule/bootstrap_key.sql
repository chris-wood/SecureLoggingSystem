create table entityKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table epochKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table initialEntityKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
create table initialEpochKey (id integer primary key autoincrement, userId integer not null, sessionId integer not null, key blob);
