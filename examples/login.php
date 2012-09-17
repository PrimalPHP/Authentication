<?php

use \DB\User;

$ERROR = array();

if ($_POST['login']) {
	switch (User::LoginWithEmail($_POST['login']['email'], $_POST['login']['password'], $_POST['login']['remember'])) {
		case User::ERR_LOGIN_OK:
			header("Location: /");
			exit;
			
		case User::ERR_LOGIN_BADUSER:
			$ERROR['BAD_USERNAME'] = "Unknown Email.";
			break;
			
		case User::ERR_LOGIN_BADPASS:
			$ERROR['BAD_PASSWORD'] = "Incorrect Password.";
			break;
	}
}


$login = $_POST['login']?:array('remember'=>1);


?><!DOCTYPE HTML>
<html lang="en">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>Primal Authentication Example</title>
</head>
<body>
	<form method="post" accept-charset="utf-8" id="login_form">
		<?php if (!empty($ERROR)) { ?><div class="error"><?php foreach ($ERROR as $err) if (is_string($err)) { ?><p><?php echo $err ?></p><?php } ?></div><?php } ?>

		<div class="email">
			<label>Email:</label>
			<input type="text" name="login[email]" value="<?php echo htmlentities($login['email']) ?>">
		</div>
		<div class="password">
			<label>Password:</label>
			<input type="password" name="login[password]" value="<?php echo htmlentities($login['password']) ?>">
		</div>
		<div class="remember">
			<label><input type="checkbox" name="login[remember]" value="1" <?php if ($login['remember']) echo 'checked' ?>> Remember Me</label>
		</div>
		<div class="submit">
			<input type="submit" class="" value="Sign In">
		</div>
	</form>
</body>
</html>