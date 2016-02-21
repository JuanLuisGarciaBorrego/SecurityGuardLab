<?php

namespace AppBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class SecurityController extends Controller
{
    /**
     * @Route("/login", name="login_route")
     */
    public function loginAction(Request $request)
    {
        $authenticationUtils = $this->get('security.authentication_utils');

        return $this->render(
            'security/login.html.twig',
            array(
                'last_username' => $authenticationUtils->getLastUsername(),
                'error'         => $authenticationUtils->getLastAuthenticationError(),
            )
        );
    }

    /**
     * @Route("/login-check", name="login_check_route")
     */
    public function loginCheckAction()
    {

    }

    /**
     * @Route("/logout", name="logout_route")
     */
    public function logoutAction()
    {

    }
}
