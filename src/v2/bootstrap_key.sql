create table LogEntityKey 
(
	logEntityKeyId integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table InitialLogEntityKey 
(
	initialLogEntityKey integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table EventEntityKey 
(
	eventEntityKeyId integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table InitialEventEntityKey 
(
	initialEventEntityKey integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	key blob, 
	inserted_at varchar(255) not null
);

create table PolicyKey 
(
	policyKeyId integer primary key autoincrement, 
	userId varchar(255) not null, 
	sessionId varchar(255) not null, 
	policy blob, 
	key blob, 
	iv blob, 
	inserted_at varchar(255) not null
); 
