<?php

namespace IMAG\LdapBundle\Event\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use IMAG\LdapBundle\Event\LdapUserEvent;

/**
 * Performs logic before the user is found to LDAP
 */
class LdapSecuritySubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents()
    {
        return array(
            \IMAG\LdapBundle\Event\LdapEvents::PRE_BIND => 'onPreBind',
        );
    }

    /**
     * Modifies the User before binding data from LDAP
     *
     * @param \IMAG\LdapBundle\Event\LdapUserEvent $event
     */
    public function onPreBind(LdapUserEvent $event)
    {
        $user = $event->getUser();
        $config = $this->appContext->getConfig();

        $ldapConf = $config['ldap'];

        if (!in_array($user->getUsername(), $ldapConf['allowed'])) {
            throw new \Exception(sprintf('LDAP user %s not allowed', $user->getUsername()));
        }

        $user->addRole('ROLE_LDAP');
        $event->setUser($user);
    }
}