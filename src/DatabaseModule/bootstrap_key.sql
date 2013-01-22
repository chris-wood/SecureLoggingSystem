create table entityKey 
(
	id integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table epochKey 
(
	id integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table initialEntityKey 
(
	id integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table initialEpochKey 
(
	id integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table policyKey 
(
	id integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	policy blob, 
	key blob, 
	iv blob, 
	inserted_at varchar(255) not null
); 
