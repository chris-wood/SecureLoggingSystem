create table entity (id integer primary key autoincrement, userId integer not null, sessionId integer not null, digest blob);
create table epoch (id integer primary key autoincrement, userId integer not null, sessionId integer not null, digest blob);
create table log (id integer primary key autoincrement, userId integer not null, sessionId integer not null, epochId integer not null, message blob, xhash blob, yhash blob);
