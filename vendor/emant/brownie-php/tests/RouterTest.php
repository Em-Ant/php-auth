<?php

namespace Emant\BrowniePhp\Tests;

use Emant\BrowniePhp\Router;
use PHPUnit\Framework\TestCase;

class RouterTest extends TestCase
{
    public function testAddRoute()
    {
        $router = new Router();

        $router->get('/home', 'HomeController@index');
        $router->post('/about', 'AboutController@index');
        $router->patch('/user/{id}', 'UserController@update');

        $routes = $this->getPrivatePropertyValue($router, '_routes');

        $this->assertCount(3, $routes);

        $this->assertEquals('GET', $routes[0]['method']);
        $this->assertEquals('/home', $routes[0]['route']);
        $this->assertEquals(['HomeController@index'], $routes[0]['handlers']);

        $this->assertEquals('POST', $routes[1]['method']);
        $this->assertEquals('/about', $routes[1]['route']);
        $this->assertEquals(['AboutController@index'], $routes[1]['handlers']);

        $this->assertEquals('PATCH', $routes[2]['method']);
        $this->assertEquals('/user/{id}', $routes[2]['route']);
        $this->assertEquals(['UserController@update'], $routes[2]['handlers']);
    }

    public function testMatchRoute()
    {
        $router = new Router();

        $router->get('/home', 'HomeController@index');
        $router->post('/about', 'AboutController@index');
        $router->patch('/user/{id}', 'UserController@update');

        $params = [];
        $matchedRoute = $this->invokePrivateMethod(
            $router,
            'match_helper',
            ['/user/{id}', '/user/42', true, &$params]
        );

        $this->assertTrue($matchedRoute);
        $this->assertEquals(['id' => '42'], $params);
    }

    public function testRunWithMatchingRoute()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['PATH_INFO'] = '/users/123';

        $router = new Router();

        $handlerCalled = false;
        $router->get('/users/{id}', function ($ctx) use (&$handlerCalled) {
            $handlerCalled = true;
            $this->assertSame('/users/123', $ctx['path']);
            $this->assertSame(['id' => '123'], $ctx['params']);
        });

        ob_start();
        $router->run();
        ob_end_clean();

        $this->assertTrue($handlerCalled);
    }

    public function testRunWithNoMatchingRoute()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['PATH_INFO'] = '/invalid-route';

        $router = new Router();

        $handlerCalled = false;
        $router->get('/users/{id}', function ($ctx) use (&$handlerCalled) {
            $handlerCalled = true;
        });

        ob_start();
        $router->run();
        ob_end_clean();

        $this->assertFalse($handlerCalled);
    }

    public function testRunWithMiddleware()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['PATH_INFO'] = '/users/123';

        $router = new Router();

        $middlewareCalled = false;
        $router->use(function ($ctx) use (&$middlewareCalled) {
            $middlewareCalled = true;
            $this->assertSame('/users/123', $ctx['path']);
            $this->assertSame([], $ctx['params']);
        });

        $handlerCalled = false;
        $router->get('/users/{id}', function ($ctx) use (&$handlerCalled) {
            $handlerCalled = true;
            $this->assertSame('/users/123', $ctx['path']);
            $this->assertSame(['id' => '123'], $ctx['params']);
        });

        ob_start();
        $router->run();
        ob_end_clean();

        $this->assertTrue($middlewareCalled);
        $this->assertTrue($handlerCalled);
    }

    public function testParseJsonBody()
    {
        // Create a mock context
        $context = [
            'method' => 'POST',
            'headers' => [
                'content-type' => 'application/json'
            ],
            'body' => []
        ];

        // Create a mock request body
        $GLOBALS['PHPINPUT'] = '{"key":"value"}';

        $serverBackup = $_SERVER;
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['HTTP_CONTENT_TYPE'] = 'application/json';

        $router = new Router();

        $router->parse_json_body($context);

        $expectedBody = ['key' => 'value'];

        $this->assertEquals($expectedBody, $context['body']);

        $_SERVER = $serverBackup;
        $GLOBALS['PHPINPUT'] = null;
    }

    public function testParseBasicAuth()
    {
        // Create a mock context
        $context = [
            'headers' => [
                'authorization' => 'Basic dXNlcjpwYXNzd29yZA==' // base64 encoded "user:password"
            ]
        ];

        $router = new Router();

        $router->parse_basic_auth($context);

        $this->assertEquals('user', $context['basic_auth_user']);
        $this->assertEquals('password', $context['basic_auth_pwd']);
    }

    private function getPrivatePropertyValue($object, $property)
    {
        $reflector = new \ReflectionClass(get_class($object));
        $property = $reflector->getProperty($property);
        $property->setAccessible(true);

        return $property->getValue($object);
    }

    private function invokePrivateMethod($object, $method, array $arguments = [])
    {
        $reflector = new \ReflectionClass(get_class($object));
        $method = $reflector->getMethod($method);
        $method->setAccessible(true);

        return $method->invokeArgs($object, $arguments);
    }
}
