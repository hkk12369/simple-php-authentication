<?php

/**
* Author: Hitesh Kumar, IIT Delhi.
* License: http://en.wikipedia.org/wiki/WTFPL
*/

function fatalError($error)
{
	die($error);
}

function filter($str)
{
	$str = trim(htmlentities(strip_tags($str)));
	if(get_magic_quotes_gpc ())
		$str = stripslashes($str);
	$str = mysql_real_escape_string($str);
	return $str;
}

function isLoggedIn()
{
	global $CFG, $USER;
	session_start();
	if(isset($_SESSION['HTTP_USER_AGENT']))
	{
		if($_SESSION['HTTP_USER_AGENT'] != md5($_SERVER['HTTP_USER_AGENT']))
		{
			logout();
			return false;
		}
	}

	if(!isset($_SESSION['userid']))
	{
		if(isset($_COOKIE['authcookie']))
		{
			$cookie = decodeAuthCookie($_COOKIE['authcookie']);
			$cookie->userid = filter($cookie->userid);
			$ckeytime = getFields('users', 'ckey, ctime', 'id', $cookie->userid);
			if(time() - $ckeytime->ctime > $CFG->cookieTimeOut)
			{
				logout();
				return false;
			}
			if(!empty($ckeytime->ckey) && is_numeric($cookie->userid) && $cookie->ckey == sha1($ckeytime->ckey))
			{
				session_regenerate_id();
				$_SESSION['userid'] = $cookie->userid;
				$_SESSION['HTTP_USER_AGENT'] = md5($_SERVER['HTTP_USER_AGENT']);
				setField('users', 'lastaccess', time(), 'id', $cookie->userid);
			}
			else
			{
				logout();
				return false;
			}
		}
		else
		{
			logout();
			return false;
		}
		$USER = getRecord('users', 'id', filter($_SESSION['userid']));
		return true;
	}
	$USER = getRecord('users', 'id', filter($_SESSION['userid']));
	return true;
}

function login($username, $password, $remember=false)
{
	global $CFG, $ERR;
	$user = getRecord('users', 'username', $username);
	if($user)
	{
		if(!$user->approved)
		{
			$ERR[] = "Account Not Activated.";
			return false;
		}
		if($user->banned)
		{
			$ERR[] = "Your Ass Is Banned.";
			return false;
		}
		if(!hashPassword($password, $user->password))
		{
			$ERR[] = "Password Incorrect.";
			return false;
		}
		if($user->ctime && time() - $user->ctime > $CFG->cookieTimeOut) logout();
		session_start();
		session_regenerate_id(true);
		$_SESSION['userid'] = $user->id;
		$_SESSION['HTTP_USER_AGENT'] = md5($_SERVER['HTTP_USER_AGENT']);
		setField('users', 'lastaccess', time(), 'id', $user->id);
		if($remember)
		{
			if(!$user->ckey)
			{
				$ctime = time();
				$ckey = genRandomKey();
				setFields('users', "ckey='$ckey', ctime='$ctime'", 'id', $user->id);
				setcookie("authcookie", encodeAuthCookie($user->id, $ckey), time()+$CFG->cookieTimeOut, "/");
			}
			else setcookie("authcookie", encodeAuthCookie($user->id, $user->ckey), time()+$CFG->cookieTimeOut, "/");
		}
		return true;
	}
	else
	{
		$ERR[] = "Username Incorrect";
		return false;
	}
}

function logout($redirect='')
{
	session_start();
	if(isset($_SESSION['userid']) || isset($_COOKIE['authcookie']))
	{
		$cookie = decodeAuthCookie($_COOKIE['authcookie']);
		$cookie->userid = filter($cookie->userid);
		setFieldsWhere('users', "ckey='', ctime=''", "id='$_SESSION[userid]' OR id='$cookie->userid'");
	}
	unset($_SESSION['userid']);
	unset($_SESSION['HTTP_USER_AGENT']);
	session_unset();
	session_destroy();
	setcookie('authcookie', '', time()-1000, "/");
	if($redirect) redirect($redirect);
}

function redirect($redirect)
{
	if(headers_sent())
		echo "<script type='text/javascript'> window.location = '$redirect'; </script>";
	else header("Location: $redirect");
	exit;
}

function param($param, $default='', $method='')
{
	if(isset($_POST[$param]))
	{
		if(!strcasecmp($method, 'post')) return $default;
		return filter($_POST[$param]);
	}
	else if(isset($_GET[$param]))
	{
		if(!strcasecmp($method, 'get')) return $default;
		return filter($_GET[$param]);
	}
	return $default;
}

function encodeAuthCookie($cookie_userid, $cookie_ckey)
{
	$ckey = sha1($cookie_ckey);
	$pos = mt_rand(5, 25);
	$userid = '%'.$cookie_userid.'$';
	return substr($ckey, 0, $pos).$userid.substr($ckey, $pos);
}

function decodeAuthCookie($str)
{
	$cookie = new stdClass();
	$cookie->userid = substr(strstr(strstr($str, '%'), '$', true), 1);
	$cookie->ckey = strstr($str, '%', true).substr(strstr($str, '$'), 1);
	return $cookie;
}

function genRandomKey($length=9)
{
	$key = "";
	while($length > 5)
	{
		$temp = sha1(uniqid(mt_rand(), true));
		$key .= substr($temp, mt_rand(0, strlen($temp)-6), 5);
		$length -= 5;
	}
	$temp = sha1(uniqid(mt_rand(), true));
	$key .= substr($temp, mt_rand(0, strlen($temp)-6), $length);
	return $key;
}

function getUser($userid='')
{
	if($userid) return getRecord('users', 'id', $userid);
	if(!isLoggedIn()) return false;
	$userid = filter($_SESSION['userid']);
	return getRecord('users', 'id', $userid);
}

function getUserInfo($info, $userid='')
{
	if($userid) return getField('users', $info, 'id', $userid);
	if(!isLoggedIn()) return false;
	$userid = filter($_SESSION['userid']);
	return getField('users', $info, 'id', $userid);
}

function hasLevel($level)
{
	global $CFG;
	if($level == 'admin') $level = $CFG->adminLevel;
	//if(!is_numeric($level)) $level = getLevelNumber($level);
	return $level == getUserInfo('level');
}

function hashPassword($password, $hashed = null)
{
	//echo "$password $hashed"; exit;
	$salt = sha1(uniqid(mt_rand(), true));
	$saltlen = strlen($salt);
	$saltlen = max($saltlen >> 2, ($saltlen >> 1) - strlen($password));
	if($hashed)
	{
		//----------EXTRACT SALT FROM THE HASH--------------------------
		if(strlen($hashed) <= $saltlen) return false;
		$k = strlen($password);
		$j = $k = $k > 0 ? $k : 1;
		$p = 0;
		$index = array();
		$out = "";
		for ($i = 0; $i < $saltlen; $i++)
		{
			$c = substr($password, $p, 1);
			$j = pow($j + ($c !== false ? ord($c) : 0), 2) % strlen($hashed);
			while (in_array($j, $index))
			$j = ++$j % strlen($hashed);
			$index[$i] = $j;
			$p = ++$p % $k;
		}
		for ($i = 0; $i < $saltlen; $i++)
		$out .= $hashed[$index[$i]];
		$salt = $out;
		//-----------------END-----------------------------------------
	}
	else $salt = substr($salt, 0, $saltlen);
	$hash = sha1($password);
	$hash = substr($hash, 0, strlen($password)).$salt.substr($hash, strlen($password));
	$hash = sha1($hash);
	$hash = substr($hash, $saltlen);
	//------INSERT THE SALT IN THE HASH--------------------------------
	$k = strlen($password);
	$j = $k = $k > 0 ? $k : 1;
	$p = 0;
	$index = array();
	$out = "";
	$m = 0;
	for ($i = 0; $i < strlen($salt); $i++)
	{
		$c = substr($password, $p, 1);
		$j = pow($j + ($c !== false ? ord($c) : 0), 2) % (strlen($hash) + strlen($salt));
		while (array_key_exists($j, $index))
		$j = ++$j % (strlen($hash) + strlen($salt));
		$index[$j] = $i;
		$p = ++$p % $k;
	}
	for ($i = 0; $i < strlen($hash) + strlen($salt); $i++)
    $out .= array_key_exists($i, $index) ? $salt[$index[$i]] : $hash[$m++];
	$hash = $out;
	//------------END--------------------------------------------------------
	if(!$hashed) return $hash;
	else return $hashed == $hash;
}

function calcage($secs, $duration, $count)
{
	return ((floor($secs/$duration))%$count);
}

?>
