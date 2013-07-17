<?php

namespace IMAG\LdapBundle\User;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;

interface LdapUserInterface
{
    public function getEmail();
    public function setEmail($email);

    public function getDn();
    public function setDn($dn);

    public function getAttributes();
    public function setAttributes(array $attributes);
    public function getAttribute($name);

    public function serialize();
    public function unserialize($serialized);

    public function __toString();
}
