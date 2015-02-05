<?php

namespace IMAG\LdapBundle\Provider;

use IMAG\LdapBundle\Exception\ConnectionException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface;
use IMAG\LdapBundle\Event\LdapUserEvent;
use IMAG\LdapBundle\Event\LdapEvents;
use IMAG\LdapBundle\User\LdapUserInterface;

class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    private
        $userProvider,
        $ldapManager,
        $dispatcher,
        $providerKey,
        $hideUserNotFoundExceptions
        ;

    /**
     * Constructor
     *
     * Please note that $hideUserNotFoundExceptions is true by default in order
     * to prevent a possible brute-force attack.
     *
     * @param UserProviderInterface    $userProvider
     * @param LdapManagerUserInterface $ldapManager
     * @param EventDispatcherInterface $dispatcher
     * @param string                   $providerKey
     * @param Boolean                  $hideUserNotFoundExceptions
     */
    public function __construct(
        UserProviderInterface $userProvider,
        AuthenticationProviderInterface $daoAuthenticationProvider,
        LdapManagerUserInterface $ldapManager,
        EventDispatcherInterface $dispatcher = null,
        $providerKey,
        $hideUserNotFoundExceptions = true
    )
    {
        $this->userProvider = $userProvider;
        $this->daoAuthenticationProvider = $daoAuthenticationProvider;
        $this->ldapManager = $ldapManager;
        $this->dispatcher = $dispatcher;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token){
    	
//     	echo '-LdapAuthenticationProvider///authenticate-';
    	echo 'TOKEN';
    	var_dump($token);
    	
    	//exit();
    	
    	if (!$this->supports($token)) {
            throw new AuthenticationException('Unsupported token');
        }
        try {
        	//TODO
            $user = $this->userProvider
//                 ->loadUserByUsername($token->getUsername());
            	->loadUserByUsernamePassword($token->getUsername(), $token->getCredentials());
			
//             echo '-User tras la loadUserByUsername-';
//             var_dump($user);
            
            if ($user instanceof LdapUserInterface) {
            	
//             	echo '-User del tipo LdapUserInterface-';
                return $this->ldapAuthenticate($user, $token);
            }
            
        } catch (\Exception $e) {
            if ($e instanceof ConnectionException || $e instanceof UsernameNotFoundException) {
                if ($this->hideUserNotFoundExceptions) {

//                 	echo 'AUTHENTICATE-BAD CREDENTIALS/n';
                    throw new BadCredentialsException('Bad Credentials', 0, $e);
                }
            }
            throw $e;
        }
        
        if ($user instanceof UserInterface) {
//         	echo '-User del tipo de UserInterface-';
            return $this->daoAuthenticationProvider->authenticate($token);
        }
    }
    /**
     * Authentication logic to allow Ldap user
     *
     * @param \IMAG\LdapBundle\User\LdapUserInterface  $user
     * @param TokenInterface $token
     *
     * @return \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken $token
     */
    private function ldapAuthenticate(LdapUserInterface $user, TokenInterface $token)
    {
//         echo 'LdapAuthenticationProvider///ldapAuthenticate()';
    	
    	$userEvent = new LdapUserEvent($user);

//     	echo '-userEvent-';
//     	var_dump($userEvent);
    	
        if (null !== $this->dispatcher) {
            try {
                $this->dispatcher->dispatch(LdapEvents::PRE_BIND, $userEvent);
            } catch (AuthenticationException $expt) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials 1', 0, $expt);
                }
                throw $expt;
            }
        }
        
//         echo '-user->getDn()-';
//         var_dump($user->getDn());

        if (null === $user->getDn()) {
        	
//         	echo '-Llamando a reloadUser()-';
        	
            $user = $this->reloadUser($user);
            
//             echo '-user resultante-';
//             var_dump($user);
        }
        
        if (null !== $this->dispatcher) {
            $userEvent = new LdapUserEvent($user);
            try {
                $this->dispatcher->dispatch(LdapEvents::POST_BIND, $userEvent);
            } catch (AuthenticationException $authenticationException) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials 2', 0, $authenticationException);
                }
                throw $authenticationException;
            }
        }
        
        $token = new UsernamePasswordToken($userEvent->getUser(), null, $this->providerKey, $userEvent->getUser()->getRoles());
//         echo '-token antes de setearle los atributos-';
//         var_dump($token);
        
        $token->setAttributes($token->getAttributes());
        
//         echo '-token seteado-';
//         var_dump($token);
        
        return $token;
    }

    /**
     * Authenticate the user with LDAP bind.
     *
     * @param \IMAG\LdapBundle\User\LdapUserInterface  $user
     * @param TokenInterface $token
     *
     * @return true
     */
    private function bind(LdapUserInterface $user, TokenInterface $token)
    {
//     	echo '-LDAPAUTHENTICATIONPROVIDER///BIND-';
//     	echo '-USER PARA AUTENTICAR-';
//     	var_dump($user->getUsername());
//     	echo '-TOKEN/PASS para autenticar-';
//     	var_dump($token->getCredentials());
    	
    	
    	
    	
    	$this->ldapManager
            ->setUsername($user->getUsername())
            ->setPassword($token->getCredentials());

        $this->ldapManager->auth();

        return true;
    }

    /**
     * Reload user with the username
     *
     * @param \IMAG\LdapBundle\User\LdapUserInterface $user
     * @return \IMAG\LdapBundle\User\LdapUserInterface $user
     */
    private function reloadUser(LdapUserInterface $user)
    {
//         echo 'LdapAuthenticationProvider///reloadUser()';
    	
    	try {
        	
        	echo '-Refrescando el usuario';
            $user = $this->userProvider->refreshUser($user);
        } catch (UsernameNotFoundException $userNotFoundException) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }

        return $user;
    }

    /**
     * Check whether this provider supports the given token.
     *
     * @param TokenInterface $token
     *
     * @return boolean
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken
            && $token->getProviderKey() === $this->providerKey;
    }
}
