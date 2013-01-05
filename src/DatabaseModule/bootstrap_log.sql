create table entity (
  userId                    bigint not null,
  sessionId                 bigint not null,
  digest                    varchar(255),
  constraint pk_entity primary key (userId, sessionId)
);

create table epoch (
  userId                    bigint not null,
  sessionId                 bigint not null,
  digest                    varchar(255),
  constraint pk_epoch primary key (userId, sessionId)
);

create table log (
  userId                    bigint not null,
  sessionId                 bigint not null,
  epochId                   bigint not null,
  message                   blob,
  xhash                     varchar(255),
  yhash                     varchar(255),
  constraint pk_log primary key (userId, sessionId),
  foreign key (userId, sessionId) references epoch (userId, sessionId) on delete set null on update restrict
);
