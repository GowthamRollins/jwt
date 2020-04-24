create table users
(
    id           bigserial,
    username     varchar(50),
    passowrd     varchar(50),
    date_created timestamp with time zone,
    last_updated timestamp with time zone,
    primary key (id)
);

insert into users(username, passowrd, date_created, last_updated) values ('Rollins', 'Rollins', now(), now());
