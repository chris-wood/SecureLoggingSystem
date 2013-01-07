create table entityKey (userId bigint not null, sessionId bigint not null, key varchar(255), constraint pk_entityKey primary key (userId, sessionId));
create table epochKey (userId bigint not null, sessionId bigint not null, key varchar(255), constraint pk_epochKey primary key (userId, sessionId));
create table initialEntityKey (userId bigint not null, sessionId bigint not null, key varchar(255), constraint pk_initialEntityKey primary key (userId, sessionId));
create table initialEpochKey (userId bigint not null, sessionId bigint not null, key varchar(255), constraint pk_initialEpochKey primary key (userId, sessionId));
