<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Middleware\AdminMiddleware;
use AuthServer\Repositories\MigrationRepository;
use AuthServer\Services\Database;
use AuthServer\Services\MigrationRunner;
use AuthServer\Controllers\Admin\MigrationsController;
use AuthServer\Tests\Support\IntegrationFlowTrait;
use DI\Bridge\Slim\Bridge;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class MigrationsEndpointTest extends TestCase
{
    use IntegrationFlowTrait;
    private static \Slim\App $app;
    private static string $apiKey = 'test-admin-key';
    private static \PDO $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = Database::connect('sqlite::memory:');

        $migrationRepo = new MigrationRepository(self::$pdo);
        $runner = new MigrationRunner(
            $migrationRepo,
            __DIR__ . '/../../migrations/'
        );
        $controller = new MigrationsController($runner);
        $adminMiddleware = new AdminMiddleware(self::$apiKey);

        $container = new \DI\Container();

        self::$app = Bridge::create($container);

        self::$app->addErrorMiddleware(true, true, true);

        self::$app->group('/db/migrations', function (\Slim\Routing\RouteCollectorProxy $group) use ($controller) {
            $group->post('/migrate', [$controller, 'migrate']);
            $group->post('/rollback', [$controller, 'rollback']);
            $group->post('/go', [$controller, 'go']);
            $group->get('/status', [$controller, 'status']);
            $group->get('/dry-run', [$controller, 'dryRun']);
        })->add($adminMiddleware);
    }

    private function assertResponse(int $expectedStatus, ServerRequestInterface $request): array
    {
        $response = $this->handle($request);
        self::assertSame($expectedStatus, $response->getStatusCode());
        return json_decode((string) $response->getBody(), true) ?? [];
    }

    // ── Auth tests ─────────────────────────────────────────────

    public function testUnauthorizedWithoutToken(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status');
        $response = $this->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testUnauthorizedWithWrongToken(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'Authorization' => 'Bearer wrong-key',
        ]);
        $response = $this->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testAuthorizedViaBearer(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testAuthorizedViaHeader(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'X-Admin-Key' => self::$apiKey,
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }

    // ── Status ─────────────────────────────────────────────────

    public function testStatusReturnsAllMigrationsUnapplied(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertArrayHasKey('migrations', $data);
        self::assertCount(5, $data['migrations']);

        self::assertSame(0, $data['migrations'][0]['version']);
        self::assertFalse($data['migrations'][0]['applied']);

        self::assertSame(1, $data['migrations'][1]['version']);
        self::assertFalse($data['migrations'][1]['applied']);

        self::assertSame(2, $data['migrations'][2]['version']);
        self::assertFalse($data['migrations'][2]['applied']);

        self::assertSame(3, $data['migrations'][3]['version']);
        self::assertFalse($data['migrations'][3]['applied']);

        self::assertSame(4, $data['migrations'][4]['version']);
        self::assertFalse($data['migrations'][4]['applied']);
    }

    // ── Dry-run ────────────────────────────────────────────────

    public function testDryRunShowsPending(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/dry-run', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertArrayHasKey('pending', $data);
        self::assertCount(5, $data['pending']);
        self::assertSame(0, $data['pending'][0]['version']);
    }

    // ── Migrate ────────────────────────────────────────────────

    public function testMigrateAppliesAll(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/migrate', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertArrayHasKey('applied', $data);
        self::assertCount(5, $data['applied']);
        self::assertSame(0, $data['applied'][0]['version']);
        self::assertSame(1, $data['applied'][1]['version']);
        self::assertSame(2, $data['applied'][2]['version']);
        self::assertSame(3, $data['applied'][3]['version']);
        self::assertSame(4, $data['applied'][4]['version']);
        self::assertSame(5, $data['count']);
    }

    public function testMigrateIdempotent(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/migrate', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertSame(0, $data['count']);
        self::assertEmpty($data['applied']);
    }

    // ── Status after migrate ───────────────────────────────────

    public function testStatusAfterMigrate(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertTrue($data['migrations'][0]['applied']);
        self::assertTrue($data['migrations'][1]['applied']);
        self::assertTrue($data['migrations'][2]['applied']);
        self::assertTrue($data['migrations'][3]['applied']);
        self::assertTrue($data['migrations'][4]['applied']);
        self::assertNotNull($data['migrations'][0]['applied_at']);
        self::assertNotNull($data['migrations'][1]['applied_at']);
        self::assertNotNull($data['migrations'][2]['applied_at']);
        self::assertNotNull($data['migrations'][3]['applied_at']);
        self::assertNotNull($data['migrations'][4]['applied_at']);
    }

    // ── Rollback via command ───────────────────────────────────

    public function testRollbackOneStep(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/rollback', ['steps' => 1], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertCount(1, $data['rolled_back']);
        self::assertSame(4, $data['rolled_back'][0]['version']);
        self::assertSame(1, $data['count']);
    }

    public function testStatusAfterRollback(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertTrue($data['migrations'][0]['applied']);
        self::assertTrue($data['migrations'][1]['applied']);
        self::assertTrue($data['migrations'][2]['applied']);
        self::assertTrue($data['migrations'][3]['applied']);
        self::assertFalse($data['migrations'][4]['applied']);
    }

    // ── Go: re-apply 1 then rollback via go ────────────────────

    public function testGoToVersion1(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/go', ['version' => 1], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertSame(1, $data['target']);
        // Current version is 3 (0,1,2,3 applied; 4 rolled back) — go to 1 rolls back 3 and 2
        self::assertCount(2, $data['applied']);
        self::assertSame(3, $data['applied'][0]['version']);
        self::assertSame(2, $data['applied'][1]['version']);
    }

    public function testGoToVersion0RollsBack(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/go', ['version' => 0], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertSame(0, $data['target']);
        self::assertCount(1, $data['applied']);
        self::assertSame(1, $data['applied'][0]['version']);
    }

    public function testStatusAfterGoTo0(): void
    {
        $request = $this->createRequest('GET', '/db/migrations/status', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $data = $this->assertResponse(200, $request);

        self::assertTrue($data['migrations'][0]['applied']);
        self::assertFalse($data['migrations'][1]['applied']);
        self::assertFalse($data['migrations'][2]['applied']);
    }

    // ── Error cases ────────────────────────────────────────────

    public function testGoWithNegativeVersionReturns400(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/go', ['version' => -1], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }

    public function testGoWithoutVersionReturns400(): void
    {
        $request = $this->createRequest('POST', '/db/migrations/go', [], null, [
            'Authorization' => 'Bearer ' . self::$apiKey,
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }
}
