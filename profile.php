<?php
session_start();

if (!isset($_SESSION["user_id"])) {
	header("Location: login_form.php");
	exit();
}

$error = null;
$success = null;

// Подключение к базе данных
$db = new SQLite3("users.db");

// Получение текущих данных пользователя
$user_id = $_SESSION["user_id"];
$query = "SELECT username, phone, email, password FROM users WHERE id = :id";
$stmt = $db->prepare($query);
$stmt->bindValue(":id", $user_id, SQLITE3_INTEGER);
$result = $stmt->execute();
$user = $result->fetchArray(SQLITE3_ASSOC);

// Обработка формы для изменения данных
if (isset($_POST["update"])) {
	$new_username = $_POST["username"];
	$new_phone = $_POST["phone"];
	$new_email = $_POST["email"];

	// Проверка на уникальность имени пользователя, телефона и почты
	$checkQuery =
		"SELECT * FROM users WHERE (username = :username OR phone = :phone OR email = :email) AND id != :id";
	$stmt = $db->prepare($checkQuery);
	$stmt->bindValue(":username", $new_username, SQLITE3_TEXT);
	$stmt->bindValue(":phone", $new_phone, SQLITE3_TEXT);
	$stmt->bindValue(":email", $new_email, SQLITE3_TEXT);
	$stmt->bindValue(":id", $user_id, SQLITE3_INTEGER);
	$result = $stmt->execute();

	if ($result->fetchArray()) {
		$error =
			"Имя пользователя, номер телефона или почта уже используются другим пользователем!";
	} else {
		// Обновление данных пользователя
		$updateQuery =
			"UPDATE users SET username = :username, phone = :phone, email = :email WHERE id = :id";
		$stmt = $db->prepare($updateQuery);
		$stmt->bindValue(":username", $new_username, SQLITE3_TEXT);
		$stmt->bindValue(":phone", $new_phone, SQLITE3_TEXT);
		$stmt->bindValue(":email", $new_email, SQLITE3_TEXT);
		$stmt->bindValue(":id", $user_id, SQLITE3_INTEGER);

		if ($stmt->execute()) {
			$_SESSION["username"] = $new_username;
			$success = "Данные успешно обновлены!";
			$user["username"] = $new_username;
			$user["phone"] = $new_phone;
			$user["email"] = $new_email;
		} else {
			$error = "Ошибка обновления данных: " . $db->lastErrorMsg();
		}
	}
}

// Обработка формы для смены пароля
if (isset($_POST["change_password"])) {
	$current_password = $_POST["current_password"];
	$new_password = $_POST["new_password"];
	$confirm_new_password = $_POST["confirm_new_password"];

	if (!password_verify($current_password, $user["password"])) {
		$error = "Текущий пароль неверен!";
	} elseif ($new_password !== $confirm_new_password) {
		$error = "Новые пароли не совпадают!";
	} else {
		$hashed_new_password = password_hash($new_password, PASSWORD_BCRYPT);
		$updatePasswordQuery =
			"UPDATE users SET password = :password WHERE id = :id";
		$stmt = $db->prepare($updatePasswordQuery);
		$stmt->bindValue(":password", $hashed_new_password, SQLITE3_TEXT);
		$stmt->bindValue(":id", $user_id, SQLITE3_INTEGER);

		if ($stmt->execute()) {
			$success = "Пароль успешно обновлен!";
		} else {
			$error = "Ошибка обновления пароля: " . $db->lastErrorMsg();
		}
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
    <title>Профиль</title>
</head>
<body>
    <h1>Добро пожаловать, <?php echo htmlspecialchars(
    	$user["username"]
    ); ?>!</h1>

    <h2>Изменить данные</h2>
    <form action="profile.php" method="post">
        Имя: <input type="text" name="username" required value="<?php echo htmlspecialchars(
        	$user["username"]
        ); ?>"><br />
        Номер телефона: <input type="tel" name="phone" required value="<?php echo htmlspecialchars(
        	$user["phone"]
        ); ?>"><br />
        Почта: <input type="email" name="email" required value="<?php echo htmlspecialchars(
        	$user["email"]
        ); ?>"><br />
        <input type="submit" name="update" value="Обновить данные">
    </form>

    <h2>Сменить пароль</h2>
    <form action="profile.php" method="post">
        Текущий пароль: <input type="password" name="current_password" required><br />
        Новый пароль: <input type="password" name="new_password" required><br />
        Подтвердите новый пароль: <input type="password" name="confirm_new_password" required><br />
        <input type="submit" name="change_password" value="Сменить пароль">
    </form>

    <?php if ($error) {
    	echo "<p style='color: red;'>$error</p>";
    } ?>
    <?php if ($success) {
    	echo "<p style='color: green;'>$success</p>";
    } ?>

    <p><a href="logout.php">Выход</a></p>
</body>
</html>
