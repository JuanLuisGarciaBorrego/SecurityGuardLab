<?php

namespace AppBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoder;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;

class FormAuthenticator extends AbstractFormLoginAuthenticator
{
    /**
     * @var UserPasswordEncoder
     */
    private $encoder;

    /**
     * @var UrlGeneratorInterface
     */
    private $router;

    function __construct(UserPasswordEncoder $encoder, UrlGeneratorInterface $router)
    {
        $this->encoder = $encoder;
        $this->router = $router;
    }

    /**
     * Se llama en cada petición y su trabajo consiste en recibir las credenciales del usuario y devolverlas a getUser en caso de que no sean nulas.
     * Las credenciales pueden ser por ejemplo login/password en un formulario, un token, u otras propiedades personalizadas
     */
    public function getCredentials(Request $request)
    {
        if ($request->getPathInfo() != $this->router->generate('login_check_route')) {
            return;
        }

        $request->getSession()->set(Security::LAST_USERNAME, $request->request->get('_username'));

        return [
            'username' => $request->request->get('_username'),
            'password' => $request->request->get('_password'),
            'condiciones' => $request->request->get('_condiciones'),
        ];
    }

    /**
     * Si getCredentials devuelve credenciales entra en acción este método,
     *
     * Consiste en devolver un objeto que implementa UserInterface.
     *
     * Si lo hace entonces checkCredentials será llamado
     * Si devuelve nulo lanzará un authenticationException
     *
     *
     * En nuestro caso tenemos los usuarios en memoria;
     * Si tuvieramos una entity que implemente UserInterface tendriamos que inyectar el manager de Doctrine
     * y hacer una consulta a nuestro repositorio.
     *
     *
     * return $this->em->getRepository('AppBundle:User')->findOneBy(['username' => $username])
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $username = $credentials['username'];

        return $userProvider->loadUserByUsername($username);
    }

    /**
     * Si getUser devuelve un objeto User se llama a este método.
     *
     * Su trabajo consiste en verificar si las credenciales son correctas; si no lanzamos una AuthenticationException
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        if (!$this->encoder->isPasswordValid($user, $credentials['password'])) {
            throw new BadCredentialsException();
        }

        if (!$credentials['condiciones']) {
            throw new CustomUserMessageAuthenticationException(
                'Eh '.$credentials['username'].'!!.Si no aceptas no entras!!!'
            );
        }

        if (rand(1, 2) != 2) {
            throw new CustomUserMessageAuthenticationException('Mala suerte!! Intentalo otra vez!!! jaja');
        }

        return true;
    }

    /**
     * Devolvemos la ruta del formulario de login
     */
    protected function getLoginUrl()
    {
        return $this->router->generate('login_route');
    }

    /**
     * Devolvemos el destino después de autenticarse
     */
    protected function getDefaultSuccessRedirectUrl()
    {
        return $this->router->generate('admin');
    }
}