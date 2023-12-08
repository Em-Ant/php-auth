<?php

use Emant\BrowniePhp\Utils;
use PHPUnit\Framework\TestCase;

class UtilsTest extends TestCase
{
    public function testSendJson()
    {
        $data = ['key' => 'value'];

        // Test when callback is set
        $_GET['callback'] = 'callbackFunction';
        $expectedOutput = $_GET['callback'] . '(' . json_encode($data) . ');';

        ob_start();
        Utils::send_json($data);
        $actualOutput = ob_get_clean();

        $this->assertEquals($expectedOutput, $actualOutput);
        $this->assertEquals('text/javascript; charset=utf8', $this->getResponseHeader('Content-Type'));


        // Test when callback is not set
        unset($_GET['callback']);
        $expectedOutput = json_encode($data, JSON_UNESCAPED_SLASHES);

        ob_start();
        Utils::send_json($data);
        $actualOutput = ob_get_clean();

        $this->assertEquals($expectedOutput, $actualOutput);
        $this->assertEquals('application/json', $this->getResponseHeader('Content-Type'));
    }

    public function testServerError()
    {
        $errorType = 'internal server error';
        $description = 'unknown error';
        $statusCode = 500;

        $data = [
            'error' => $errorType,
            'error_description' => $description
        ];

        ob_start();
        Utils::server_error($errorType, $description, $statusCode);
        $actualOutput = ob_get_clean();

        $this->assertEquals(json_encode($data, JSON_UNESCAPED_SLASHES), $actualOutput);
        $this->assertEquals($statusCode, http_response_code());
    }

    public function testUnknownError()
    {
        $errorType = 'internal server error';
        $description = 'unknown error';
        $statusCode = 500;

        $data = [
            'error' => $errorType,
            'error_description' => $description
        ];

        ob_start();
        Utils::unknown_error();
        $actualOutput = ob_get_clean();

        $this->assertEquals(json_encode($data, JSON_UNESCAPED_SLASHES), $actualOutput);
        $this->assertEquals($statusCode, http_response_code());
    }

    public function testNotFound()
    {
        $errorType = 'not found';
        $description = 'resource not found';
        $statusCode = 404;

        $data = [
            'error' => $errorType,
            'error_description' => $description
        ];

        ob_start();
        Utils::not_found();
        $actualOutput = ob_get_clean();

        $this->assertEquals(json_encode($data, JSON_UNESCAPED_SLASHES), $actualOutput);
        $this->assertEquals($statusCode, http_response_code());
    }

    public function testReadEnv()
    {
        // Create a mock .env file
        $envFile = '.env.test';
        $envContent = "KEY1=value1\nKEY2=value2";
        file_put_contents($envFile, $envContent);

        $expectedVars = [
            'KEY1' => 'value1',
            'KEY2' => 'value2'
        ];

        $this->assertEquals($expectedVars, Utils::read_env($envFile));

        // Clean up the mock .env file
        unlink($envFile);
    }

    public function testGetGuid()
    {
        $guid = Utils::get_guid();

        $this->assertMatchesRegularExpression('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i', $guid);
    }

    public function testEnableCors()
    {
        $origin = 'example.com';

        ob_start();
        Utils::enable_cors($origin);
        ob_end_clean();

        $this->assertEquals($origin, $this->getResponseHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('true', $this->getResponseHeader('Access-Control-Allow-Credentials'));
        $this->assertEquals('content-type,accept,origin', $this->getResponseHeader('Access-Control-Allow-Headers'));
        $this->assertEquals('GET,POST,OPTIONS', $this->getResponseHeader('Access-Control-Allow-Methods'));
    }

    // Helper method to get the value of a response header
    private function getResponseHeader(string $headerName): ?string
    {
        $headers = xdebug_get_headers();
        foreach ($headers as $header) {
            $parts = explode(': ', $header);
            if ($parts[0] === $headerName) {
                return $parts[1];
            }
        }
        return null;
    }
}
