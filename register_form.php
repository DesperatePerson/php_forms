<?php
session_start();

$error = null;
$username = "";
$phone = "";
$email = "";

// Обработка данных формы
if (isset($_POST["register"])) {
	$username = $_POST["username"];
	$phone = $_POST["number"];
	$email = $_POST["email"];
	$password = $_POST["password"];
	$repeat_password = $_POST["repeat_password"];

	// Проверка совпадения паролей
	if ($password !== $repeat_password) {
		$error = "Passwords do not match!";
	} else {
		$hashed_password = password_hash($password, PASSWORD_BCRYPT);

		$db = new SQLite3("users.db");

		$createTableQuery = "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                phone TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT
            )";
		if (!$db->exec($createTableQuery)) {
			$error = "Error creating table: " . $db->lastErrorMsg();
		} else {
			// Проверка на уникальность имени пользователя, телефона и почты
			$checkQuery =
				"SELECT * FROM users WHERE username = :username OR phone = :phone OR email = :email";
			$stmt = $db->prepare($checkQuery);

			if ($stmt) {
				$stmt->bindValue(":username", $username, SQLITE3_TEXT);
				$stmt->bindValue(":phone", $phone, SQLITE3_TEXT);
				$stmt->bindValue(":email", $email, SQLITE3_TEXT);
				$result = $stmt->execute();

				if ($result->fetchArray()) {
					$error =
						"Пользователь с таким именем, номером телефона или почтой уже существует!";
				} else {
					// Вставка нового пользователя
					$insertQuery =
						"INSERT INTO users (username, phone, email, password) VALUES (:username, :phone, :email, :password)";
					$stmt = $db->prepare($insertQuery);

					if ($stmt) {
						$stmt->bindValue(":username", $username, SQLITE3_TEXT);
						$stmt->bindValue(":phone", $phone, SQLITE3_TEXT);
						$stmt->bindValue(":email", $email, SQLITE3_TEXT);
						$stmt->bindValue(
							":password",
							$hashed_password,
							SQLITE3_TEXT
						);

						$result = $stmt->execute();
						if ($result) {
							// Редирект на страницу входа после успешной регистрации
							header("Location: login_form.php");
							exit();
						} else {
							$error =
								"Ошибка выполнения вставки: " .
								$db->lastErrorMsg();
						}
					} else {
						$error =
							"Ошибка подготовки состояния: " .
							$db->lastErrorMsg();
					}
				}
			} else {
				$error = "Ошибка подготовки состояния: " . $db->lastErrorMsg();
			}
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
    <title>Регистрация</title>
</head>
<body>
    <form action="register_form.php" method="post">
        Имя: <input type="text" name="username" required value="<?php echo htmlspecialchars(
        	$username
        ); ?>"><br />
        Номер телефона: <input type="tel" name="number" required value="<?php echo htmlspecialchars(
        	$phone
        ); ?>"><br />
        Почта: <input type="email" name="email" required value="<?php echo htmlspecialchars(
        	$email
        ); ?>"><br />
        Пароль: <input type="password" name="password" required><br />
        Повторите пароль: <input type="password" name="repeat_password" required><br />
        <input type="submit" name="register" value="Регистрация" />

        <?php if ($error) {
        	echo "<p style='color: red;'>$error</p>";
        } ?>
    </form>
</body>
</html>
