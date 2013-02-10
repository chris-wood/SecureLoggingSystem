create table User
(
	userId integer primary key autoincrement, 
	name varchar(255) not null, 
	email varchar(255), 
	attributes blob
);

create table Role
(
	roleId integer primary key autoincrement,
	roleName varchar(255) not null
);

create table UserRole
(
	userRoleId integer primary key autoincrement,
	userId integer not null,
	roleId integer not null	
);

/* Insert some dummy users into the database */
INSERT INTO 'User' (name, email, attributes) VALUES ("alice", "alice@test.com", "one");
INSERT INTO 'User' (name, email, attributes) VALUES ("bob", "bob@test.com", "two");
INSERT INTO 'User' (name, email, attributes) VALUES ("chris", "chris@test.com", "three");

/* Insert some dummy roles */
INSERT INTO 'Role' (roleName) VALUES ("User");
INSERT INTO 'Role' (roleName) VALUES ("SuperUser");

/* Assign some roles */
INSERT INTO 'UserRole' (userId, roleId) VALUES (1, 1);
INSERT INTO 'UserRole' (userId, roleId) VALUES (2, 1);
INSERT INTO 'UserRole' (userId, roleId) VALUES (3, 2); /* chris is the superuser */