<?php
/**
* Secure login/registration User class.
*/

class User{
    /** @var object $pdo Copy of PDO connection */
    private $pdo;
    /** @var object of the logged in user */
    private $user;
    /** @var string error msg */
    private $msg;
    /** @var int number of permitted wrong login attemps */
    private $permitedAttemps = 5;

    /**
    * Connection init function
    * @param string $conString DB connection string.
    * @param string $user DB user.
    * @param string $pass DB password.
    *
    * @return bool Returns connection success.
    */
    public function dbConnect($conString, $user, $pass){
        if(session_status() === PHP_SESSION_ACTIVE){
            try {
                $pdo = new PDO($conString, $user, $pass);
                $this->pdo = $pdo;
                return true;
            }catch(PDOException $e) { 
                $this->msg = 'Connection did not work out!';
                return false;
            }
        }else{
            $this->msg = 'Session did not start.';
            return false;
        }
    }

    /**
    * Return the logged in user.
    * @return user array data
    */
    public function getUser(){
        return $this->user;
    }

    /**
    * Login function
    * @param string $email User email.
    * @param string $password User password.
    *
    * @return bool Returns login success.
    */
    public function login($username,$password){
        if(is_null($this->pdo)){
            $this->msg = 'Connection did not work out!';
            return false;
        }else{
            $pdo = $this->pdo;
            $stmt = $pdo->prepare('SELECT id, name, surname, email, wrong_logins, password, user_role FROM vy48l_users WHERE username = ? and confirmed = 1 limit 1');
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if(password_verify($password,$user['password'])){
                if($user['wrong_logins'] <= $this->permitedAttemps){
                    $this->user = $user;
                    session_regenerate_id();
                    $_SESSION['user']['id'] = $user['id'];
                    $_SESSION['user']['name'] = $user['name'];
                    $_SESSION['user']['surname'] = $user['surname'];
                    $_SESSION['user']['email'] = $user['email'];
                    $_SESSION['user']['user_role'] = $user['user_role'];
                    return true;
                }else{
                    $this->msg = 'This user account is blocked, please contact our support department.';
                    return false;
                }
            }else{
                $this->registerWrongLoginAttemp($email);
                $this->msg = 'Invalid login information or the account is not activated.';
                return false;
            } 
        }
    }

    /**
    * Register a new user account function
    * @param string $email User email.
    * @param string $fname User first name.
    * @param string $lname User last name.
    * @param string $pass User password.
    * @return boolean of success.
    */
    public function registration($email, $name, $surname, $pass, $piva, $codicefiscale, $ddn, $street, $city, $zip, $region, $tel, $cell, $note, $ccon, $refer){
        $pdo = $this->pdo;
        if($this->checkEmail($email)){
            $this->msg = 'This email has already been used!';
            return false;
        }
		if(!(isset($email) && isset($name) && isset($surname) && isset($pass) && filter_var($email, FILTER_VALIDATE_EMAIL))){
            $this->msg = 'Si prega di compilare tutti i campi obbligatori.';
            return false;
        }
		$username = $this->checkNextID();
		$username++;
		$username = $name.$username;
        $pass = $this->hashPass($pass);
        $confCode = $this->hashPass(date('Y-m-d H:i:s').$email);
        $stmt = $pdo->prepare('INSERT INTO YourUserTable (username, email, name, surname, password, piva_cf, cf, birthdate, street, city, zip, region, phone, cellular, notess, comecon, refer, confirm_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        if($stmt->execute([$username,$email,$name,$surname,$pass,$piva,$codicefiscale,$ddn,$street,$city,$zip,$region,$tel,$cell,$note,$ccon,$refer,$confCode])){
            if($this->sendConfirmationEmail($email)){
                return true;
            }else{
                $this->msg = 'Confirmation mail was not sent!';
                return false; 
            }
        }else{
            $this->msg = 'New user creation failed!';
            return false;
        }
    }

    /**
    * Email the confirmation code function
    * @param string $email User email.
    * @return boolean of success.
    */
    private function sendConfirmationEmail($email){
        $pdo = $this->pdo;
        $stmt = $pdo->prepare('SELECT username, confirm_code FROM YourUserTable WHERE email = ? limit 1');
        $stmt->execute([$email]);
        $code = $stmt->fetch();

        $subject = 'Conferma registrazione a Climagratis.it';
        $message = 'Hello!'."\r\n".'Your new username is '.$code['username']."\r\n".'REMEMBER!!!'."\r\n".'You should always use this username to login!!'."\r\n".'Copy the following code into the proper field to confirm your account activation: '.$code['confirm_code']."\r\n".'If this was emailed to you by mistake, we are cordially asking you to ignore it. '."\r\n\r\n" ;
        $headers = 'X-Mailer: PHP/' . phpversion();

        if(mail($email, $subject, $message, $headers)){
            return true;
        }else{
            return false;
        }
    }

    /**
    * Activate a login by a confirmation code and login function
    * @param string $email User email.
    * @param string $confCode Confirmation code.
    * @return boolean of success.
    */
    public function emailActivation($email,$confCode){
        $pdo = $this->pdo;
        $stmt = $pdo->prepare('UPDATE vy48l_users SET confirmed = 1 WHERE email = ? and confirm_code = ?');
        $stmt->execute([$email,$confCode]);
        if($stmt->rowCount()>0){
            $stmt = $pdo->prepare('SELECT id, name, surname, username, email, wrong_logins, user_role FROM YourUserTable WHERE email = ? and confirmed = 1 limit 1');
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            $this->user = $user;
            session_regenerate_id();
            if(!empty($user['email'])){
            	$_SESSION['user']['id'] = $user['id'];
	            $_SESSION['user']['name'] = $user['name'];
				$_SESSION['user']['username'] = $user['username'];
	            $_SESSION['user']['surname'] = $user['surname'];
	            $_SESSION['user']['email'] = $user['email'];
	            $_SESSION['user']['user_role'] = $user['user_role'];
	            return true;
            }else{
            	$this->msg = 'Account activation successful!';
            	return false;
            }            
        }else{
            $this->msg = 'Account activation not successful!';
            return false;
        }
    }

    /**
    * Password change function
    * @param int $id User id.
    * @param string $pass New password.
    * @return boolean of success.
    */
    public function passwordChange($id,$pass){
        $pdo = $this->pdo;
        if(isset($id) && isset($pass)){
            $stmt = $pdo->prepare('UPDATE users SET password = ? WHERE id = ?');
            if($stmt->execute([$id,$this->hashPass($pass)])){
                return true;
            }else{
                $this->msg = 'Password change failed.';
                return false;
            }
        }else{
            $this->msg = 'Provide an ID and a password.';
            return false;
        }
    }


    /**
    * Assign a role function
    * @param int $id User id.
    * @param int $role User role.
    * @return boolean of success.
    */
    public function assignRole($id,$role){
        $pdo = $this->pdo;
        if(isset($id) && isset($role)){
            $stmt = $pdo->prepare('UPDATE users SET role = ? WHERE id = ?');
            if($stmt->execute([$id,$role])){
                return true;
            }else{
                $this->msg = 'Role assign failed.';
                return false;
            }
        }else{
            $this->msg = 'Provide a role for this user.';
            return false;
        }
    }



    /**
    * User information change function
    * @param int $id User id.
    * @param string $fname User first name.
    * @param string $lname User last name.
    * @return boolean of success.
    */
    public function userUpdate($id,$fname,$lname){
        $pdo = $this->pdo;
        if(isset($id) && isset($fname) && isset($lname)){
            $stmt = $pdo->prepare('UPDATE users SET fname = ?, lname = ? WHERE id = ?');
            if($stmt->execute([$id,$fname,$lname])){
                return true;
            }else{
                $this->msg = 'User information change failed.';
                return false;
            }
        }else{
            $this->msg = 'Provide a valid data.';
            return false;
        }
    }

    /**
    * Check if email is already used function
    * @param string $email User email.
    * @return boolean of success.
    */
    private function checkEmail($email){
        $pdo = $this->pdo;
        $stmt = $pdo->prepare('SELECT id FROM vy48l_users WHERE email = ? limit 1');
        $stmt->execute([$email]);
        if($stmt->rowCount() > 0){
            return true;
        }else{
            return false;
        }
    }

	
	public function checkNextID(){
        $pdo = $this->pdo;
        $stmt = $pdo->prepare('SELECT MAX(id) FROM vy48l_users');
        $stmt->execute();
        $id = $stmt->fetch();
		return $id[0];
    }


    /**
    * Register a wrong login attemp function
    * @param string $email User email.
    * @return void.
    */
    private function registerWrongLoginAttemp($email){
        $pdo = $this->pdo;
        $stmt = $pdo->prepare('UPDATE users SET wrong_logins = wrong_logins + 1 WHERE email = ?');
        $stmt->execute([$email]);
    }

    /**
    * Password hash function
    * @param string $password User password.
    * @return string $password Hashed password.
    */
    private function hashPass($pass){
        return password_hash($pass, PASSWORD_DEFAULT);
    }

    /**
    * Print error msg function
    * @return void.
    */
    public function printMsg(){
        print $this->msg;
    }

    /**
    * Logout the user and remove it from the session.
    *
    * @return true
    */
    public function logout() {
        $_SESSION['user'] = null;
        session_regenerate_id();
        return true;
    }



    /**
    * List users function
    *
    * @return array Returns list of users.
    */
    public function listUsers(){
        if(is_null($this->pdo)){
            $this->msg = 'Connection did not work out!';
            return [];
        }else{
            $pdo = $this->pdo;
            $stmt = $pdo->prepare('SELECT id, username, email, name, surname, password, piva_cf, cf, birthdate, street, city, zip, region, phone, cellular, notess, comecon, refer FROM YourUsersTable WHERE confirmed = 1');
            $stmt->execute();
            $result = $stmt->fetchAll(); 
            return $result; 
        }
    }
    /**
    * List users GDPR function
    *
    * @return array Returns list of users.
    */
    public function listUsersGDPR(){
        if(is_null($this->pdo)){
            $this->msg = 'Connection did not work out!';
            return [];
        }else{
            $pdo = $this->pdo;
            $stmt = $pdo->prepare('SELECT ID, username, email, datetime, activity, orig_mail FROM YourGdprTable ORDER BY datetime DESC');
            $stmt->execute();
            $result = $stmt->fetchAll(); 
            return $result; 
        }
    }

    /**
    * Simple template rendering function
    * @param string $path path of the template file.
    * @return void.
    */
    public function render($path,$vars = '') {
        ob_start();
        include($path);
        return ob_get_clean();
    }

    /**
    * Template for index head function
    * @return void.
    */
    public function indexHead() {
        print $this->render(indexHead);
    }

    /**
    * Template for index top function
    * @return void.
    */
    public function indexTop() {
        print $this->render(indexTop);
    }

    /**
    * Template for login form function
    * @return void.
    */
    public function loginForm() {
        print $this->render(loginForm);
    }

    /**
    * Template for activation form function
    * @return void.
    */
    public function activationForm() {
        print $this->render(activationForm);
    }

    /**
    * Template for index middle function
    * @return void.
    */
    public function indexMiddle() {
        print $this->render(indexMiddle);
    }

    /**
    * Template for register form function
    * @return void.
    */
    public function registerForm() {
        print $this->render(registerForm);
    }

    /**
    * Template for index footer function
    * @return void.
    */
    public function indexFooter() {
        print $this->render(indexFooter);
    }

    /**
    * Template for user page function
    * @return void.
    */
    public function userPage() {
	$users = [];
	if($_SESSION['user']['user_role'] == 2){
		$users = $this->listUsers();
		print $this->render(userPage,$users);
	}
        else {
			header('Location: index.php');
		}
    } 
	/**
    * Template for user page GDPR function
    * @return void.
    */
    public function userPageGDPR() {
	$usersGDPR = [];
	if($_SESSION['user']['user_role'] == 2){
		$usersGDPR = $this->listUsersGDPR();
		print $this->render(userPageGDPR,$usersGDPR);
	}
        else {
			header('Location: index.php');
		}
    }
	
	/** addons */
	
	public function titleText() {
		$dict = array("index.php" => "Homepage", "servizi.php" => "Servizi", "contatti.php" => "Contatti", "gruppo.php" => "Il Gruppo",  "utenti.php" => "Lista utenti", "utentiGDPR.php" => "Lista GDPR",  "sociale.php" => "Noi nel sociale", "gallery1.php" => "Galleria",  "gallery2.php" => "Galleria",  "gallery3.php" => "Galleria",  "5E.php" => "Buono 5 Euro" ); 
		$title = explode("/", $_SERVER['REQUEST_URI']);
		$title = end($title);
		if ($title == ''){ return 'Homepage';}
		$title = $dict[$title];
		return $title;
	}
}


