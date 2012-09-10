PHP Authentication Library
==========================
A simple PHP authentication library.

Example:
```php
// To check if a user is logged in
include('auth.php');
if(!isLoggedIn())
	redirect('/login.php');
	
// super secret PHP code goes here
```
```php
// To login a user
include('auth.php');
$username = $_POST['username'];
$password = $_POST['password'];
if(login($username, $password))
	redirect('/account.php');
	
echo "Login Unsuccessful";
```