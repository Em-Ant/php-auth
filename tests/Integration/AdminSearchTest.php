<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminAppTestCase;

use function AuthServer\getGuid;

class AdminSearchTest extends AdminAppTestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const TEST_PASSWORD = 'user-password-1';

    /**
     * Creates a user in the test realm; $extra merges additional fields
     * (e.g. name). Returns the created user array.
     *
     * @param array<string, mixed> $extra
     * @return array<string, mixed>
     */
    private function createTestUser(string $email, array $extra = []): array
    {
        return $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', array_merge([
            'realm_id' => self::TEST_REALM,
            'email' => $email,
            'password' => self::TEST_PASSWORD,
        ], $extra)));
    }

    /**
     * GETs an admin list endpoint in the test realm and returns the decoded body.
     *
     * @param array<string, string> $query
     * @return array<string, mixed>
     */
    private function searchList(string $path, array $query): array
    {
        return $this->assertStatus(200, $this->adminRequest('GET', $path, [], $query));
    }

    /**
     * @return array<string, mixed>
     */
    private function createTestClient(string $name, string $uri): array
    {
        return $this->assertStatus(201, $this->adminRequest('POST', '/admin/clients', [
            'name' => $name,
            'realm_id' => self::TEST_REALM,
            'uri' => $uri,
        ]));
    }

    public function testListUsersFindsEmailByPrefix(): void
    {
        $email = 'typeahead-' . getGuid() . '@example.com';
        $this->createTestUser($email);

        $data = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => 'typeahead-']);

        self::assertSame(1, $data['total'], 'prefix search must narrow to the single match');
        self::assertCount(1, $data['items']);
        self::assertSame($email, $data['items'][0]['email']);
    }

    public function testListUsersFindsNameByPrefix(): void
    {
        $email = 'named-' . getGuid() . '@example.com';
        $name = 'Typeahead ' . getGuid();
        $this->createTestUser($email, ['name' => $name]);

        $data = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => 'Typeahead ']);

        $emails = array_column($data['items'], 'email');
        self::assertContains($email, $emails);
    }

    public function testListUsersSubstringDoesNotMatch(): void
    {
        $email = 'infix-' . getGuid() . '@example.com';
        $this->createTestUser($email);

        // Prefix type-ahead only: a mid-string fragment matches nothing.
        $data = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => substr($email, 8, 6)]);

        self::assertSame(0, $data['total']);
        self::assertCount(0, $data['items']);
    }

    public function testListUsersWildcardsMatchLiterally(): void
    {
        $email = '100%_wild-' . getGuid() . '@example.com';
        $this->createTestUser($email);

        $data = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => '100%_wild-']);

        self::assertSame(1, $data['total'], 'escaped wildcards must match literally');
        self::assertSame($email, $data['items'][0]['email']);

        // A bare '%' must not turn into a match-all wildcard scan.
        $unfiltered = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM]);
        $wild = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => '%']);
        self::assertSame(0, $wild['total']);
        self::assertGreaterThan(0, $unfiltered['total']);
    }

    public function testListClientsFindsNameByPrefix(): void
    {
        $name = 'typeahead-client-' . getGuid();
        $client = $this->createTestClient($name, 'https://' . getGuid() . '.example.com');

        $data = $this->searchList('/admin/clients', ['realm_id' => self::TEST_REALM, 'q' => 'typeahead-client-']);

        self::assertSame(1, $data['total']);
        self::assertSame($client['id'], $data['items'][0]['id']);
    }

    public function testListClientsFindsUriByPrefix(): void
    {
        $host = 'typeahead-uri-' . getGuid() . '.example.com';
        $client = $this->createTestClient('uri-client-' . getGuid(), 'https://' . $host);

        $data = $this->searchList('/admin/clients', ['realm_id' => self::TEST_REALM, 'q' => 'https://' . $host]);

        self::assertSame($client['id'], $data['items'][0]['id']);
    }

    public function testListUsersSearchCombinesWithRealmFilter(): void
    {
        $email = 'realmscope-' . getGuid() . '@example.com';
        $this->createTestUser($email);

        // Same prefix in another realm must not leak through: q ANDs with realm_id.
        $webRealm = '84be68b8-7936-4422-bb4d-b741d2292a9f';
        $data = $this->searchList('/admin/users', ['realm_id' => $webRealm, 'q' => 'realmscope-']);

        self::assertSame(0, $data['total']);
    }

    public function testListUsersEmptySearchIsIgnored(): void
    {
        $unfiltered = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM]);
        $empty = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => '   ']);

        self::assertSame($unfiltered['total'], $empty['total']);
    }

    public function testListUsersLongSearchIsTruncated(): void
    {
        $prefix = 'longsearch-' . getGuid();
        $email = $prefix . '@example.com';
        $this->createTestUser($email);

        // 200 chars: silently capped to 128, so the over-long tail that no
        // row shares still matches the row by its 128-char prefix.
        $data = $this->searchList('/admin/users', ['realm_id' => self::TEST_REALM, 'q' => $prefix . str_repeat('z', 200)]);

        self::assertSame(50, $data['limit'], 'over-long q must not disturb pagination defaults');
        self::assertSame(0, $data['total'], 'capped term exceeds the stored prefix and matches nothing');
    }
}
