INSERT INTO user(id,created_at, updated_at, email, intro, nickname, password, status, user_role, username, company_id)
VALUES (1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'abc1234@naver.com','한줄소개','닉네임' ,'password','ACTIVE','USER','이병익',1);

INSERT INTO company(id,created_at,updated_at,name,status)
VALUES(1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'이튜','ACTIVE');

