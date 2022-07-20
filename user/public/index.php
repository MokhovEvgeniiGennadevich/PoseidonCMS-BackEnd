<?php 
// php -S localhost:8010

############################################################################
### Script Config
# Database settings

$mysql_host = 'db';
$mysql_port = 3306;
$mysql_user = 'sail';
$mysql_pass = 'password';
$mysql_base = 'backend_user_database';

# Cipher, Iv Len, Key Len, Key

$keys = array(
    array('aes-256-cbc', 16, 32, 'b1888edbfe2baa3772f1d8ddc11d1059ba63f31c386b2a9b89919be6914d4091',),
);

$hash_key = 'dbb9d0a4f8002ec5795c1d353056ccb845b2fe3d7d3c6a74808b70c5b571b0551bd78b372f5c017be98b667831eff8f04721b5ce64b4c388462da254292c1232';

# Request working time 
$max_request_time = 60 * 60 * 24;

############################################################################
### JSON Result

$suc    = array();
$err    = array();
$log    = array();
$time   = array();
$cookie = array();

function json_result() {
    global $suc, $err, $log, $time, $cookie;

    $time []= round(microtime(true) - $_SERVER["REQUEST_TIME_FLOAT"], 4);

    echo json_encode(array('suc' => $suc, 'err' => $err, 'log' => $log, 'time' => $time, 'cookie' => $cookie));
    exit;
}

$log []= 'Started 2';

############################################################################
### Check Request

$a_post = filter_input(INPUT_POST, 'a', FILTER_VALIDATE_INT);

if ($a_post === false) {
    $log []= '_POST["a"] is bad';

    json_result();
}

if ( isset($_POST['a']) === false or strlen($_POST['a']) < 1 ) {
    $log []= '_POST["a"] not set';

    json_result();
}

$b_post = (string) filter_input(INPUT_POST, 'b');

if ($b_post === false) {
    $log []= '_POST["b"] is bad';

    json_result();
}

if ( isset($_POST['b']) === false or strlen($_POST['b']) < 1 ) {
    $log []= '_POST["b"] not set';

    json_result();
}

############################################################################
### Decode Request

# Parameters
$b_post_bin = hex2bin($b_post);

$iv   = substr($b_post_bin, 0, 16);
$hash = substr($b_post_bin, 16, 64);
$data = substr($b_post_bin, 80);

if ( strlen($iv) !== 16 ) {
    $log []= '_POST[] strlen $iv is not 16';

    json_result();
}

if ( strlen($hash) !== 64 ) {
    $log []= '_POST[] strlen $hash is not 64';

    json_result();
}

if ( strlen($data) < 1 )  {
    $log []= '_POST[] strlen $data is < 1';

    json_result();
}

// Checking HASH
$hash1 = hash_hmac('sha3-512', $data, hex2bin('2ec5b3b3afe0757ef58a233d1dc295bb2c8d28a4ff85718dade8f575df572e4de0796fbab15343c32d0e25ed8e8a1ca5ccf7d9f2a99749f6922d120e3bad4e80'), true);

if ( hash_equals($hash1, $hash) === false ) {
    $log []= '_POST hash_equals false';

    json_result();
}

// Trying to decode _POST parameters
$decrypted = openssl_decrypt($data, 'aes-256-cbc', hex2bin('b1888edbfe2baa3772f1d8ddc11d1059ba63f31c386b2a9b89919be6914d4091'), $options=OPENSSL_RAW_DATA, $iv);
if ( !$decrypted ) {
    $log []= '_POST openssl_decrypt false';

    json_result();
}

$post_json = json_decode($decrypted, true);
if ( !$post_json ) {
    $log []= '_POST json_decode false';

    json_result();
}

file_put_contents('test.txt', json_encode($post_json));

$log []= '_POST check passed';

############################################################################
### MySQLi
# Connect
$db = mysqli_connect($mysql_host, $mysql_user, $mysql_pass, $mysql_base, $mysql_port);

if (!$db) {
    $log ['mysql'] = 'Could not connect to MySQL Database';
    json_result();
}

# Charset
mysqli_set_charset($db, 'utf8mb4');

$log [] = 'MySQL Connection Info: ' . mysqli_get_host_info($db);

############################################################################
### User MySQL Clear
if ($post_json['module'] === 'user_mysql_clear' or $post_json['module'] === 'user_mysql_create') {
    if ( $post_json['module'] !== 'user_mysql_create' ) {
        # Drop user table
        $sql = "DROP TABLE IF EXISTS user;";

        $log [] = 'DROP user table';

        $result = mysqli_query($db, $sql);

        if ( !$result ) {
            $log [] = 'DROP user table: ERROR: ' . mysqli_error($db, $result);

            json_result();
        } else {
            $log [] = 'DROP user table: OK';
        }
    }

    # Create user table
    $sql = "CREATE TABLE IF NOT EXISTS user (
        `id` bigint(20) unsigned NOT NULL PRIMARY KEY AUTO_INCREMENT
        ,`user_login` VARCHAR(255) NOT NULL UNIQUE
        ,`user_password` VARCHAR(255) NOT NULL
        ,`created` timestamp DEFAULT CURRENT_TIMESTAMP
        ,`updated` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );";

    $log [] = 'CREATE user table';

    $result = mysqli_query($db, $sql);

    if ( !$result ) {
        $log [] = 'CREATE user table: ERROR: ' . mysqli_error($db, $result);

        json_result();
    } else {
        $log [] = 'CREATE user table: OK';
    }

    if ( $post_json['module'] !== 'user_mysql_create' ) {
        # Drop token table
        $sql = "DROP TABLE IF EXISTS token;";

        $log [] = 'DROP token table';

        $result = mysqli_query($db, $sql);

        if ( !$result ) {
            $log [] = 'DROP token table: ERROR: ' . mysqli_error($db, $result);

            json_result();
        } else {
            $log [] = 'DROP token table: OK';
        }
    }

    # Create token table
    $sql = "CREATE TABLE IF NOT EXISTS token (
         `id` bigint(20) unsigned NOT NULL
        ,`token` VARCHAR(255) NOT NULL
        ,`created` timestamp DEFAULT CURRENT_TIMESTAMP
        ,`updated` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );";

    $log [] = 'CREATE token table';

    $result = mysqli_query($db, $sql);

    if ( !$result ) {
        $log [] = 'CREATE token table: ERROR: ' . mysqli_error($db, $result);

        json_result();
    } else {
        $log [] = 'CREATE token table: OK';
    }

    if ( $post_json['module'] !== 'user_mysql_create' ) {
        # Add user
        $sql = 'INSERT INTO user VALUES(0, "toxic", "123", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);';
        $result = mysqli_query($db, $sql);

        if ( !$result ) {
            $log [] = 'ADD user: ERROR: ' . mysqli_error($db, $result);

            json_result();
        } else {
            $log [] = 'ADD user: OK';
        }

        $user_id = mysqli_insert_id($db);

        if ( !$user_id ) {
            $log [] = 'ADD user insert id: ERROR: ' . mysqli_error($db, $result);

            json_result();
        } else {
            $log [] = 'ADD user insert id: OK: ' . $user_id;
        }
    }

}

############################################################################
### User Login
if ($post_json['module'] === 'login') {
    $log []= 'Module Login: Searching User';

    $stmt = mysqli_prepare($db, 'SELECT id, user_login, created FROM user WHERE user_login = ? and user_password = ?');
    mysqli_stmt_bind_param($stmt, "ss", $post_json['user_name'], $post_json['user_pass']);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $temp['id'], $temp['user_login'], $temp['created']);
    mysqli_stmt_store_result($stmt);
    $count = mysqli_stmt_num_rows($stmt);

    $log []= 'Module Login: Users Found: ' . $count;

    if ( $count !== 0 ) {
        # Result array
        $result = array();

        /* получение значений */
        $array = array();
        while (mysqli_stmt_fetch($stmt)) {
            $array = [
                 $temp['id']
                ,$temp['user_login']
                ,$temp['created']
            ];
        }

        $suc []= json_encode($array);
    } else {
        $err []= 'invalid username or password';
    }


    mysqli_stmt_close($stmt);

    json_result();
}

############################################################################
### User Register
if ($post_json['module'] === 'register') {
    # Checking login 
    $stmt = mysqli_prepare($db, 'SELECT id FROM user WHERE user_login = ?');
    mysqli_stmt_bind_param($stmt, "s", $post_json['user_name']);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $id);
    mysqli_stmt_store_result($stmt);
    $count = mysqli_stmt_num_rows($stmt);
    mysqli_stmt_close($stmt);

    $log [] = 'COUNT user FROM user_name: ' . $count;

    if ( $count !== 0 ) {
        $err []= array('login already taken');
        json_result();
    }

    # Adding user
    $stmt = mysqli_prepare($db, 'INSERT INTO user VALUES(0, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);');
    mysqli_stmt_bind_param($stmt, "ss", $post_json['user_name'], $post_json['user_pass']);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    $count = mysqli_stmt_num_rows($stmt);
    $user_id = mysqli_insert_id($db);
    mysqli_stmt_close($stmt);

    # Adding token
    $token = bin2hex(random_bytes(7));

    $stmt = mysqli_prepare($db, 'INSERT INTO token VALUES(?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);');
    mysqli_stmt_bind_param($stmt, "is", $user_id, $token);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    # Sending Result 
    
}

json_result();
