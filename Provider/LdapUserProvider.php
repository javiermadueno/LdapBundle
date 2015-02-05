<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException,
    Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Core\User\UserProviderInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\User\LdapUserInterface;

/**
 * LDAP User Provider
 *
 * @author Boris Morel
 * @author Juti Noppornpitak <jnopporn@shiroyuki.com>
 */
class LdapUserProvider implements UserProviderInterface
{
    /**
     * @var \IMAG\LdapBundle\Manager\LdapManagerUserInterface
     */
    private $ldapManager;

    /**
     * @var string
     */
    private $bindUsernameBefore;

    /**
     * The class name of the User model
     * @var string
     */
    private $userClass;

    /**
     * Constructor
     *
     * @param \IMAG\LdapBundle\Manager\LdapManagerUserInterface $ldapManager
     * @param bool|string                                       $bindUsernameBefore
     * @param string                                            $userClass
     */
    public function __construct(LdapManagerUserInterface $ldapManager, $bindUsernameBefore = false, $userClass)
    {
        $this->ldapManager = $ldapManager;
        $this->bindUsernameBefore = $bindUsernameBefore;
        $this->userClass = $userClass;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
    	if (empty($username)) {
            throw new UsernameNotFoundException('The username is not provided.');
        }
        
        if (true === $this->bindUsernameBefore) {
        	
        	$ldapUser = $this->simpleUser($username);
            
        } else {
        	$ldapUser = $this->anonymousSearch($username);
        }
		
        return $ldapUser;
    }
    
    public function loadUserByUsernamePassword($userName, $password)
    {	
    	if (empty($userName)) {
    		
    		throw new UsernameNotFoundException('The username is not provided.');
    	}
    	if (empty($password)) {
    	
    		throw new UsernameNotFoundException('The password is not provided.');
    	}
    
    	if (true === $this->bindUsernameBefore) {
    		
    		$ldapUser = $this->simpleUserPassword($userName, $password);
    
    	} else {

    		$ldapUser = $this->anonymousSearchPassword($userName, $password);
    	}
    
    	return $ldapUser;
    }
    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
//     	echo '-LdapUserProvider///refreshUser-';
    	if (!$user instanceof LdapUserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

//         echo '-bindUserNameBefore en RefreshUser-';
//         var_dump($this->bindUsernameBefore);
        
        if (false === $this->bindUsernameBefore) {
        	
            return $this->loadUserByUsername($user->getUsername());
        } else {
        	
            return $this->bindedSearch($user->getUsername());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return is_subclass_of($class, '\IMAG\LdapBundle\User\LdapUserInterface');
    }

    private function simpleUser($userName)
    {
        $ldapUser = new $this->userClass;
        $ldapUser->setUsername($userName);

        return $ldapUser;
    }
    
    private function simpleUserPassword($userName, $password)
    {
    	$ldapUser = new $this->userClass;
    	$ldapUser->setUsername($userName);
    
    	return $ldapUser;
    }
    private function anonymousSearch($username)
    {
        $this->ldapManager->exists($username);

        $lm = $this->ldapManager
            ->setUsername($username)
            ->setLdapUserConnection()
            ->doPass();
        
        $ldapUser = new $this->userClass;

        $ldapUser
            ->setUsername($lm->getUsername())
            ->setEmail($lm->getEmail())
            ->setRoles($lm->getRoles())
            ->setDn($lm->getDn())
            ->setCn($lm->getCn())
            ->setAttributes($lm->getAttributes())
            ->setGivenName($lm->getGivenName())
            ->setSurname($lm->getSurname())
            ->setDisplayName($lm->getDisplayName())
            ->setCategorias($lm->getCategorias())
            ->setCliente($lm->getCliente())
            ;

//         echo 'LDAP USER-----';
//         var_dump($ldapUser);		
        return $ldapUser;
    }

    private function anonymousSearchPassword($userName, $password)
    {
    	$this->ldapManager->existsPassword($userName, $password);
    
    	$lm = $this->ldapManager
    	->setUsername($userName)
    	->setLdapUserConnection()
    	->doPass();
    
    	$ldapUser = new $this->userClass;
    
    	$ldapUser
    	->setUsername($lm->getUsername())
    	->setEmail($lm->getEmail())
    	->setRoles($lm->getRoles())
    	->setDn($lm->getDn())
    	->setCn($lm->getCn())
    	->setAttributes($lm->getAttributes())
    	->setGivenName($lm->getGivenName())
    	->setSurname($lm->getSurname())
    	->setDisplayName($lm->getDisplayName())
    	->setCategorias($lm->getCategorias())
    	->setCliente($lm->getCliente())
    	;
    
    	return $ldapUser;
    }
    
    private function bindedSearch($username)
    {
        echo '-LdapUserProvider///bindedSearch-';
    	
    	return $this->anonymousSearch($username);
    }
}
