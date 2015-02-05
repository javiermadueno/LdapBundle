<?php

namespace IMAG\LdapBundle\Manager;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use IMAG\LdapBundle\Exception\ConnectionException;
use IMAG\LdapBundle\User;

class LdapManagerUser implements LdapManagerUserInterface {
	private $ldapConnection, $username, $password, $params, $ldapUser, $ldapUserConnection;
	public function __construct(LdapConnectionInterface $conn) {
		$this->ldapConnection = $conn;
		$this->params = $this->ldapConnection->getParameters ();
	}
	
	/**
	 *
	 * @throws inherit
	 */
	public function exists($userName) {
		
		$this->setUsername ($userName)->addLdapUser ();
	}
	
	public function existsPassword($userName, $password) {
		$this->setPassword($password);
		$this->setUsername ($userName)->addLdapUserPassword ();
	}
	/**
	 * return true
	 */
	public function auth() {
		
// 		echo 'LdaManagerUser///auth';
		
		if (strlen ( $this->password ) === 0) {
			
			throw new ConnectionException ( 'Password can\'t be empty' );
		}
		
		if (null === $this->ldapUser) {
			
			echo 'password';
			var_dump($this->password);
			
			
			$this->bindByUsername ();
			$this->doPass ($this->password);
		} else {
			$this->doPass ($this->password);
			$this->bindByDn ();
		}
	}
	
	/**
	 *
	 * @throws inherit
	 */
	public function doPass() {
		$this->addLdapUser ()->addLdapRoles()->addLdapClientes();
	
		return $this;
	}

	public function getDn() {
		return $this->ldapUser ['dn'];
	}

	public function getCn() {
		return $this->ldapUser ['cn'] [0];
	}

	public function getEmail() {
		return isset ( $this->ldapUser ['mail'] [0] ) ? $this->ldapUser ['mail'] [0] : '';
	}

	public function getAttributes() {
		$attributes = array ();
		foreach ( $this->params ['user'] ['attributes'] as $attrName ) {
			if (isset ( $this->ldapUser [$attrName] [0] )) {
				$attributes [$attrName] = $this->ldapUser [$attrName] [0];
			}
		}
		
		return $attributes;
	}

	public function getLdapUser() {
		return $this->ldapUser;
	}

	public function getDisplayName() {
		if (isset ( $this->ldapUser ['displayname'] [0] )) {
			return $this->ldapUser ['displayname'] [0];
		} else {
			return false;
		}
	}

	public function getGivenName() {
		if (isset ( $this->ldapUser ['givenname'] [0] )) {
			return $this->ldapUser ['givenname'] [0];
		} else {
			return false;
		}
	}

	public function getSurname() {
		if (isset ( $this->ldapUser ['sn'] [0] )) {
			return $this->ldapUser ['sn'] [0];
		} else {
			return false;
		}
	}

	public function getUsername() {
		return $this->username;
	}
	
	public function getRoles() {
		return $this->ldapUser ['roles'];
	}
	public function setUsername($username) {
		if ($username === "*") {
			throw new \InvalidArgumentException ( "Invalid username given." );
		}
		$this->username = $username;
		
		return $this;
	}
	public function setPassword($password) {
		$this->password = $password;
		return $this;
	}
	
	function getCategorias()
	{
		return isset($this->ldapUser ['businesscategory'] [0]) ? explode(',', $this->ldapUser ['businesscategory'] [0]) : array ();
	}
	
	function getCliente()
	{
		return isset($this->ldapUser ['cliente'] [0]) ?  $this->ldapUser ['cliente'] [0] : '';
	}
	
	/**
	 *
	 * @return mixed $this
	 * @throws \Symfony\Component\Security\Core\Exception\UsernameNotFoundException | Username not found
	 * @throws \RuntimeException | Inconsistent Fails
	 * @throws \IMAG\LdapBundle\Exception\ConnectionException | Connection error
	 */
	private function addLdapUser() {
		
		if (! $this->username) {
			throw new \InvalidArgumentException ( 'User is not defined, please use setUsername' );
		}
		$entries = $this->ldapConnection->search ( array (
				'base_dn' => $this->params ['user'] ['base_dn'],
				'filter' => sprintf ( '(&(uid=%s))' , $this->ldapConnection->escape ( $this->username ))
		) );

		if ($entries ['count'] > 1) {
			throw new \RuntimeException ( "This search can only return a single user" );
		}
		
		if ($entries ['count'] == 0) {
			throw new UsernameNotFoundException ( sprintf ( 'Username "%s" doesn\'t exists', $this->username ) );
		}
				
		$this->ldapUser = $entries [0];
	
		return $this;
	}
	
	/**
	 *
	 * @return mixed $this
	 * @throws \Symfony\Component\Security\Core\Exception\UsernameNotFoundException | Username not found
	 * @throws \RuntimeException | Inconsistent Fails
	 * @throws \IMAG\LdapBundle\Exception\ConnectionException | Connection error
	 */
	private function addLdapUserPassword() {
	
		if (! $this->username) {
			throw new \InvalidArgumentException ( 'User is not defined, please use setUsername' );
		}
		$entries = $this->ldapConnection->search ( array (
				'base_dn' => $this->params ['user'] ['base_dn'],
				'filter' => sprintf ( '(&(uid=%s))' , $this->ldapConnection->escape ( $this->username ))
		) );
	
		if ($entries ['count'] > 1) {
			throw new \RuntimeException ( "This search can only return a single user" );
		}
	
		if ($entries ['count'] == 0) {
			throw new UsernameNotFoundException ( sprintf ( 'Username "%s" doesn\'t exists', $this->username ) );
		}
	
		$user_dn = $entries[0]['dn'];
		$auth_status = $this->ldapConnection->bind($user_dn, $this->password);
	
		if ($auth_status === FALSE) {
	
			throw new UsernameNotFoundException ("Wrong password");
		}
	
		$this->ldapUser = $entries [0];
	
		return $this;
	}
	
	/**
	 *
	 * @return mixed $this
	 * @throws \RuntimeException | Inconsistent Fails
	 * @throws \InvalidArgumentException | Configuration exception
	 * @throws \IMAG\LdapBundle\Exception\ConnectionException | Connection error
	 */
	private function addLdapRoles() {
		if (null === $this->ldapUser) {
			throw new \RuntimeException ( 'Cannot assign LDAP roles before authenticating user against LDAP' );
		}
		
		$this->ldapUser ['roles'] = array ();
		
		if (true === $this->params ['client'] ['skip_roles']) {
			
			$this->ldapUser ['roles'] = array (
					'ROLE_USER_DEFAULT' 
			);
			
			return;
		}
		
		if (! isset ( $this->params ['role'] ) && false === $this->params ['client'] ['skip_roles']) {
			throw new \InvalidArgumentException ( "If you want to skip getting the roles, set config option imag_ldap:client:skip_roles to true" );
		}
		
		$tab = array ();
		
		$filter = isset ( $this->params ['role'] ['filter'] ) ? $this->params ['role'] ['filter'] : '';
		
		$entries = $this->ldapConnection->search ( array (
				'base_dn' => $this->params ['role'] ['base_dn'],
				'filter' => sprintf ( '(&%s(%s=%s))', $filter, $this->params ['role'] ['user_attribute'], $this->ldapConnection->escape ( $this->getUserId () ) ),
				'attrs' => array (
						$this->params ['role'] ['name_attribute'] 
				) 
		) );
		
		for($i = 0; $i < $entries ['count']; $i ++) {
			array_push ( $tab, sprintf ( 'ROLE_%s', self::slugify ( $entries [$i] [$this->params ['role'] ['name_attribute']] [0] ) ) );
		}
		
		$this->ldapUser ['roles'] = $tab;
		
		return $this;
	}
	
	private function addLdapClientes()
	{
		if (null === $this->ldapUser) {
			throw new \RuntimeException ( 'Cannot assign LDAP roles before authenticating user against LDAP' );
		}
		
		$this->ldapUser ['cliente'] = array ();
		
		
		
		if (! isset ( $this->params ['cliente'] ) ) {
			throw new \InvalidArgumentException ( "Si quieres obtener la empresa a la que pertenece el cliente tienenes que configurarlo." );
		}
		
		$tab = array ();
		
		$filter = isset ( $this->params ['cliente'] ['filter'] ) ? $this->params ['cliente'] ['filter'] : '';
		
		$entries = $this->ldapConnection->search ( array (
				'base_dn' => $this->params ['cliente'] ['base_dn'],
				'filter' => sprintf ( '(&%s(%s=%s))', $filter, $this->params ['cliente'] ['user_attribute'], $this->ldapConnection->escape ( $this->getUserId () ) ),
				'attrs' => array (
						$this->params ['cliente'] ['name_attribute']
				)
		) );
		
		for($i = 0; $i < $entries ['count']; $i ++) {
			array_push ( $tab, sprintf ( '%s', self::slugify ( $entries [$i] [$this->params ['cliente'] ['name_attribute']] [0] ) ) );
		}
		
		$this->ldapUser ['cliente'] = $tab;
		
		return $this;
	}

    private function addIdioma()
    {
        if(null === $this->ldapUser)
        {
            throw new \RuntimeException('No se puede asignar idioma antes de autenticas contra el ldap');
        }

        $this->ldapUser['idioma'] = array();

        if(! isset($this->params['idioma'])){
            throw new \InvalidArgumentException('No se han podido obtener los parametros de configuración del idioma');
        }

        $filter = isset ( $this->params ['idioma'] ['filter'] ) ? $this->params ['idioma'] ['filter'] : '';

        $entries = $this->ldapConnection->search(array(
            'base_dn' => $this->params ['idioma'] ['base_dn'],
            'filter' => sprintf ( '(&%s(%s=%s))', $filter, $this->params ['idioma'] ['user_attribute'], $this->ldapConnection->escape ( $this->getUserId () ) ),
            'attrs' => array(
                $this->params['idioma']['name_attribute']
            )
        ));

    }
	
	private function bindByDn() {
		return $this->ldapConnection->bind ( $this->ldapUser ['dn'], $this->password );
	}
	private function bindByUsername() {
		return $this->ldapConnection->bind ( $this->username, $this->password );
	}
	private static function slugify($role) {
		$role = preg_replace ( '/\W+/', '_', $role );
		$role = trim ( $role, '_' );
		$role = strtoupper ( $role );
		
		return $role;
	}
	private function getUserId() {
		switch ($this->params ['role'] ['user_id']) {
			case 'dn' :
				return $this->ldapUser ['dn'];
				break;
			
			case 'username' :
				return $this->username;
				break;
			
			default :
				throw new \Exception ( sprintf ( "The value can't be retrieved for this user_id : %s", $this->params ['role'] ['user_id'] ) );
		}
	}
	public function setLdapUserConnection() {
		if (! $this->username) {
			throw new \InvalidArgumentException ( 'User is not defined, please use setUsername' );
		}
		
		$dn = "ou=usuarios,dc=relationalmessages,dc=com";
		$uid = "uid=" . $this->username . "," . $dn;
		//TODO Modificado
		//$userPassword = "userPassword" .$this->password. "," . $dn;
		
		$base_dn = "ou=clientes,dc=relationalmessages,dc=com";
		
		$filter = "(member=$uid)";
		$entries = $this->ldapConnection->search ( array (
				'base_dn' => $base_dn,
				'filter' => $filter,
				'attrs' => array (
						"o" 
				) 
		) );
		
		if ($entries ['count'] > 1) {
			throw new \RuntimeException ( "This search can only return a single connection" );
		}
		
		if ($entries ['count'] == 0) {
			throw new UsernameNotFoundException ( sprintf ( 'Username has no conection', $this->username ) );
		}
		$result = $entries [0];
		$connection = $result ['o'] [0];

		$_SESSION["connection"]= $connection;
		 
		
		return $this;
	}
}

