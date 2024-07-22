
create sequence _user_seq start with 1 increment by 50

create table _user (
                       id integer not null,
                       email varchar(255),
                       firstname varchar(255),
                       lastname varchar(255),
                       password varchar(255),
                       role varchar(255) check (role in ('USER','ADMIN')),
                       primary key (id)
)