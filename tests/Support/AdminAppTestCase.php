<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

/**
 * Shared bootstrap for Admin API integration tests: temp key store, fully
 * wired Slim app (in-memory SQLite, migrations, seed) and admin key.
 * Children inherit static::$app / static::$pdo / static::$adminKey; each
 * class builds a fresh app in setUpBeforeClass.
 */
abstract class AdminAppTestCase extends TestCase
{
    use AdminApiTrait;
    use TempDirTrait;

    protected static \Slim\App $app;
    protected static \PDO $pdo;
    protected static string $adminKey = 'test-admin-key';
    protected static string $keysRoot;

    public static function setUpBeforeClass(): void
    {
        static::$keysRoot = sys_get_temp_dir() . '/auth-keys-' . getGuid();
        mkdir(static::$keysRoot);

        static::$app = TestAppFactory::createApp([
            'admin_api_key' => static::$adminKey,
            'keys_root' => static::$keysRoot,
        ]);
        static::$pdo = static::$app->getContainer()->get(\PDO::class);
    }

    public static function tearDownAfterClass(): void
    {
        static::removeDir(static::$keysRoot);
    }

    /**
     * Creates a realm with a fresh key set. $extra merges additional realm
     * fields (e.g. password-policy overrides).
     *
     * @param array<string, mixed> $extra
     * @return array<string, mixed>
     */
    protected function createRealmWithKeys(string $name, array $extra = []): array
    {
        $kid = $this->assertStatus(201, $this->adminRequest('POST', '/admin/keys'))['kid'];

        return $this->assertStatus(201, $this->adminRequest(
            'POST',
            '/admin/realms',
            array_merge(['name' => $name, 'keys_id' => $kid], $extra)
        ));
    }
}
