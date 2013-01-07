create table users (userId bigint not null, name varchar(255), email varchar(255), attributes blob, constraint pk_users primary key (userId));
