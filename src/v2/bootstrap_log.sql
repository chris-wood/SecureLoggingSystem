CREATE TABLE LogChainEntity
(
	logEntityId integer primary key autoincrement, 
	userId varchar(255) not null, /* encrypted */
	sessionId varchar(255) not null, /* encrypted */
	digest blob not null, 
	inserted_at varchar(255) not null
);
CREATE TABLE Log
(
	logId integer primary key autoincrement, 
	userId varchar(255) not null,  /* encrypted */
	sessionId varchar(255) not null, /* encrypted */
	payload blob not null,  /* message */
	digest blob not null, /* x hash */
	link blob not null,  /* y hash */
	inserted_at varchar(255) not null
);

CREATE TABLE EventChainEntity
(
	eventEntityId integer primary key autoincrement, 
	userId varchar(255) not null, /* encrypted */
	sessionId varchar(255) not null, /* encrypted */
	digest blob not null, 
	inserted_at varchar(255) not null
);
CREATE TABLE Event
(
	eventId integer primary key autoincrement,
	userId varchar(255) not null, /* encrypted */
	sessionId varchar(255) not null, /* encrypted */
	action integer not null, /* plaintext because action is finite */
	object integer, /* plaintext because object is finite */
	/*userGroup integer, */ /* hash userGroup + salt (OR ENCRYPT?) */
	salt varchar(255) not null, /* Randomly generated salt that masks user group ID */
	FOREIGN KEY(action) REFERENCES Action(artistId),
	FOREIGN KEY(object) REFERENCES Object(objectId)
	/*FOREIGN KEY(userGroup) REFERENCES UserGroup(userGroupId)*/
);

CREATE TABLE AffectedUserGroup
(
	affectedUserGroupId integer primary key autoincrement,
	eventId integer, /* MASKED */
	userId varchar(255) /* MASKED */
);

/* These two tables are not confidential */
CREATE TABLE Action
(	
	actionId integer primary key autoincrement,
	actionName varchar(255) not null
);
CREATE TABLE Object
(
	objectId integer primary key autoincrement,
	objectName varchar(255) not null
);

/* Insert actions into the action table */
INSERT INTO 'Action' (actionName) VALUES ("ADD");
INSERT INTO 'Action' (actionName) VALUES ("DELETE");
INSERT INTO 'Action' (actionName) VALUES ("MODIFY");

/* Insert some objects into the object table */
INSERT INTO 'Object' (objectName) VALUES ("Object-X");
INSERT INTO 'Object' (objectName) VALUES ("Object-Y");
INSERT INTO 'Object' (objectName) VALUES ("Object-Z");