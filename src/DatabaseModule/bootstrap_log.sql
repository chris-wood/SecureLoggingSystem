create table entity (id integer primary key autoincrement, userId integer not null, sessionId integer not null, digest varchar(255));
create table epoch (id integer primary key autoincrement, userId integer not null, sessionId integer not null, digest varchar(255));
create table log (id integer primary key autoincrement, userId integer not null, sessionId integer not null, epochId integer not null, message blob, xhash varchar(255), yhash varchar(255));
