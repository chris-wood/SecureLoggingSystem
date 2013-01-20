create table entity 
(
	id integer primary key autoincrement, 
	userId integer not null, 
	sessionId integer not null, 
	digest blob, 
	inserted_at varchar(255) not null
);

create table epoch
(
	id integer primary key autoincrement, 
	userId integer not null, 
	sessionId integer not null, 
	digest blob, 
	inserted_at varchar(255) not null
);

create table log 
(
	id integer primary key autoincrement, 
	userId integer not null, 
	sessionId integer not null, 
	epochId integer not null, 
	message blob, 
	xhash blob, 
	yhash blob, 
	inserted_at varchar(255) not null
);
