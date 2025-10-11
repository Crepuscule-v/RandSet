CREATE TABLE foo(
  a INT,
  b CHAR(16)
);
CREATE TABLE bar(
  a INT,
  b CHAR(16)
);

INSERT INTO foo VALUES(1, 'a'),
                    (2, 'b'),
                    (3, 'c');

INSERT INTO bar VALUES(1, 'a'),
                    (2, 'B'),
                    (3, 'C');

SELECT a, b FROM foo;
SELECT a, b FROM bar ORDER BY a DESC;

SELECT foo.b, bar.b FROM foo, bar WHERE foo.a = bar.a + 1;

DROP TABLE foo;
DROP TABLE bar;
