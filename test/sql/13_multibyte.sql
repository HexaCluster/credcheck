--
-- Issue #91: length, character class and repeat rules count characters, not
-- bytes, for multibyte encodings. Only meaningful in a UTF8 database.
--
SELECT getdatabaseencoding() <> 'UTF8' AS skip_test \gset
\if :skip_test
\quit
\endif

LOAD 'credcheck';

-- username length
SET credcheck.username_min_length = 2;
CREATE USER "ф" PASSWORD 'MultiByte1!';            -- error, 1 character
CREATE USER "фы" PASSWORD 'MultiByte1!';           -- 2 characters
DROP USER "фы";
RESET credcheck.username_min_length;

-- password length
SET credcheck.password_min_length = 4;
CREATE USER mb_len PASSWORD 'фыв';                 -- error, 3 characters
CREATE USER mb_len PASSWORD 'фывa';                -- 4 characters
DROP USER mb_len;
RESET credcheck.password_min_length;

-- a multibyte character is one special character, not one per byte
SET credcheck.password_min_special = 1;
CREATE USER mb_special PASSWORD 'фывапро';         -- error, no special character
CREATE USER mb_special PASSWORD 'фыв-апро';
DROP USER mb_special;
RESET credcheck.password_min_special;

-- case of multibyte letters follows the database collation
SET credcheck.password_min_upper = 1;
SET credcheck.password_min_lower = 1;
CREATE USER mb_case PASSWORD 'фывапро';            -- error, no upper case
CREATE USER mb_case PASSWORD 'ФЫВАПРО';            -- error, no lower case
CREATE USER mb_case PASSWORD 'Фывапро';
DROP USER mb_case;
RESET credcheck.password_min_upper;
RESET credcheck.password_min_lower;

-- repeated multibyte characters
SET credcheck.password_min_repeat = 2;
CREATE USER mb_repeat PASSWORD 'жжжабв12';         -- error, repeated 3 times
CREATE USER mb_repeat PASSWORD 'жжабвв12';
DROP USER mb_repeat;
RESET credcheck.password_min_repeat;

-- case-insensitive comparison of multibyte characters
SET credcheck.password_contain_username = on;
SET credcheck.password_ignore_case = on;
CREATE USER "ФЁДОР" PASSWORD 'xфёдорx';           -- error, contains username
CREATE USER "ФЁДОР" PASSWORD 'xпетрx';
DROP USER "ФЁДОР";
RESET credcheck.password_contain_username;
RESET credcheck.password_ignore_case;
