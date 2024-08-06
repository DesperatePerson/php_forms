<?php
session_start();

$error = null;

if (isset($_POST["login"])) {
	$identifier = $_POST["identifier"];
	$password = $_POST["password"];

	$db = new SQLite3("users.db");

	$query =
		"SELECT * FROM users WHERE phone = :identifier OR email = :identifier";
	$stmt = $db->prepare($query);

	if ($stmt) {
		$stmt->bindValue(":identifier", $identifier, SQLITE3_TEXT);
		$result = $stmt->execute();

		if ($user = $result->fetchArray(SQLITE3_ASSOC)) {
			if (password_verify($password, $user["password"])) {
				$_SESSION["user_id"] = $user["id"];
				$_SESSION["username"] = $user["username"];
				header("Location: profile.php");
				exit();
			} else {
				$error = "Неправильный пароль!";
			}
		} else {
			$error = "Пользователь не найден!";
		}
	} else {
		$error = "Ошибка подготовки состояния: " . $db->lastErrorMsg();
	}
}
?>

<!doctype html>
<html>
<head>
    <style>
        input {
            margin: 5px;
        }
    </style>
    <title>Вход</title>
</head>
<body>
    <form action="login_form.php" method="post">
        Телефон или Почта: <input type="text" name="identifier" required><br />
        Пароль: <input type="password" name="password" required><br />
        <input type="submit" name="login" value="Вход" />
    </form>

    <?php if ($error) {
    	echo "<p style='color: red;'>$error</p>";
    } ?>
</body>
</html>
