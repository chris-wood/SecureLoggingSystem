create table entity (id integer primary key autoincrement, userId bigint not null, sessionId bigint not null, digest varchar(255));
create table epoch (id integer primary key autoincrement, userId bigint not null, sessionId bigint not null, digest varchar(255));
create table log (id integer primary key autoincrement, userId bigint not null, sessionId bigint not null, epochId bigint not null, message blob, xhash varchar(255), yhash varchar(255));
