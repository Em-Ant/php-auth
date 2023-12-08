# BrowniePHP

![brownie illustration](brownie.jpeg)

## A tiny PHP Routing Framework

BrowniePHP is a lightweight PHP routing framework, inspired by Express.js, that provides a simple and intuitive way to handle HTTP requests and define routes for your web applications. It aims to be minimalistic yet powerful, allowing you to quickly build RESTful APIs or handle various HTTP methods with ease.

## Features

- Define routes using HTTP methods (GET, POST, PATCH, PUT, DELETE)
- Handle middleware functions for request preprocessing
- Extract parameters from route URLs
- Parse JSON request bodies automatically
- Access request context and headers easily
- Simple and easy to integrate with existing PHP projects

## Installation

You can install BrowniePHP using Composer. Run the following command in your project directory:

```bash
composer require emant/brownie-php
```

## Getting Started

To define a route, create an instance of the `Router` class and use the appropriate method based on the desired HTTP method:

```php
use Emant\BrowniePhp\Router;

$router = new Router();

$router->get('/users', function ($ctx) {
    // Handle GET /users request
});

$router->post('/users', function ($ctx) {
    // Handle POST /users request
});

$router->put('/users/{id}', function ($ctx) {
    // Handle PUT /users/{id} request
    // Access the {id} parameter using $ctx['params']['id']
});

// ... Define more routes
```

You can add global middleware functions using the `use` method:

```php
$router->use(function ($ctx) {
    // Perform preprocessing logic here
    // Access request context via $ctx array
});
```

The `ALL` route allows you to define a route that matches all HTTP methods. This means that any incoming request, regardless of the HTTP method used, will be matched by the `ALL` route. It provides a convenient way to handle common functionality or apply middleware to all routes, regardless of the specific method. By using the `ALL` route, you can define global middleware functions or common logic that needs to be executed for every request, ensuring consistent behavior across your application.

```php
use Emant\BrowniePhp\Router;

$router = new Router();

$router->all('/common-route', function ($ctx) {
    // Common logic or middleware for all routes
});

$router->get('/specific-route', function ($ctx) {
    // Handler for a specific GET route
});
```

To start the routing process, call the run method:

```php
$router->run();
```

This will match the incoming request to the defined routes and execute the corresponding route handler or middleware functions.

Inside the route handler or middleware functions, the request context is available as an associative array named `$ctx`. You can access various request properties such as method, path, query parameters, request body, and headers through this array.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the [GitHub repository](https://github.com/Em-Ant/brownie-php).

## License

BrowniePHP is open-source software licensed under the [MIT license](https://opensource.org/license/mit/).
