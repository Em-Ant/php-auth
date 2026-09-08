<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminAppTestCase;
use Psr\Http\Message\ServerRequestInterface;

use function AuthServer\getGuid;

class PasswordPolicyTest extends AdminAppTestCase
{
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';

    public function testCreateRealmWithoutPolicyInheritsGlobal(): void
    {
        $realm = $this->createRealmWithKeys('policy-inherit-' . getGuid());

        self::assertSame(
            ['min_length' => null, 'min_lower' => null, 'min_upper' => null, 'min_digits' => null, 'min_special' => null],
            $realm['password_policy']
        );
    }

    public function testCreateRealmWithPolicyRoundTrips(): void
    {
        $realm = $this->createRealmWithKeys('policy-set-' . getGuid(), [
            'password_min_length' => 12,
            'password_min_digits' => 2,
            'password_min_special' => 0,
        ]);

        self::assertSame(12, $realm['password_policy']['min_length']);
        self::assertSame(2, $realm['password_policy']['min_digits']);
        self::assertSame(0, $realm['password_policy']['min_special']);
        self::assertNull($realm['password_policy']['min_lower']);
    }

    public function testUpdateRealmPolicyAndRejectInvalid(): void
    {
        $realm = $this->createRealmWithKeys('policy-update-' . getGuid());

        $updated = $this->assertStatus(200, $this->adminRequest(
            'PUT',
            '/admin/realms/' . $realm['id'],
            ['password_min_length' => 10]
        ));
        self::assertSame(10, $updated['password_policy']['min_length']);

        foreach ([['password_min_length' => -1], ['password_min_digits' => 'many']] as $invalid) {
            $this->assertStatus(400, $this->adminRequest(
                'PUT',
                '/admin/realms/' . $realm['id'],
                $invalid
            ));
        }
    }

    public function testUpdateRealmWithExplicitNullResetsRuleToInherit(): void
    {
        $realm = $this->createRealmWithKeys('policy-reset-' . getGuid(), [
            'password_min_length' => 10,
            'password_min_digits' => 2,
        ]);

        $updated = $this->assertStatus(200, $this->adminRequest(
            'PUT',
            '/admin/realms/' . $realm['id'],
            ['password_min_length' => null]
        ));

        self::assertNull($updated['password_policy']['min_length']);
        self::assertSame(2, $updated['password_policy']['min_digits']);
    }

    public function testUpdateRealmAbsentPolicyFieldKeepsOverride(): void
    {
        $realm = $this->createRealmWithKeys('policy-keep-' . getGuid(), [
            'password_min_length' => 10,
        ]);

        $updated = $this->assertStatus(200, $this->adminRequest(
            'PUT',
            '/admin/realms/' . $realm['id'],
            ['name' => 'policy-keep-renamed-' . getGuid()]
        ));

        self::assertSame(10, $updated['password_policy']['min_length']);
    }

    public function testCreateUserWithWeakPasswordReturns400(): void
    {
        $response = $this->handle($this->userCreateRequest(self::TEST_REALM, 'short'));

        self::assertSame(400, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString('at least 8 characters', $body);
        self::assertStringContainsString('at least 1 digit', $body);
        self::assertStringContainsString('at least 1 special character', $body);
    }

    public function testCreateUserWithCompliantPasswordReturns201(): void
    {
        $data = $this->assertStatus(201, $this->userCreateRequest(self::TEST_REALM, 'valid-pass-1'));

        self::assertArrayHasKey('id', $data);
    }

    public function testRotateToWeakPasswordReturns400(): void
    {
        $user = $this->assertStatus(201, $this->userCreateRequest(self::TEST_REALM, 'valid-pass-1'));

        $this->assertStatus(400, $this->adminRequest(
            'PUT',
            '/admin/users/' . $user['id'],
            ['password' => 'weak']
        ));
    }

    public function testLaxRealmOverrideAcceptsWeakPassword(): void
    {
        $realm = $this->createRealmWithKeys('policy-lax-' . getGuid(), [
            'password_min_length' => 3,
            'password_min_lower' => 0,
            'password_min_upper' => 0,
            'password_min_digits' => 0,
            'password_min_special' => 0,
        ]);

        $data = $this->assertStatus(201, $this->userCreateRequest($realm['id'], 'abc'));

        self::assertArrayHasKey('id', $data);
    }

    public function testStrictRealmOverrideRejectsGloballyCompliantPassword(): void
    {
        $realm = $this->createRealmWithKeys('policy-strict-' . getGuid(), [
            'password_min_length' => 13,
        ]);

        $response = $this->handle($this->userCreateRequest($realm['id'], 'valid-pass-1'));

        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString(
            'at least 13 characters',
            (string) $response->getBody()
        );
    }

    public function testDuplicateEmailStillReturns409DespiteWeakPassword(): void
    {
        $email = 'dup-' . getGuid() . '@example.com';
        $this->assertStatus(201, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => $email,
            'password' => 'valid-pass-1',
        ]));

        // The duplicate guard runs before the policy check: a conflicting
        // email reports 409 even when the password would fail the policy.
        $this->assertStatus(409, $this->adminRequest('POST', '/admin/users', [
            'realm_id' => self::TEST_REALM,
            'email' => $email,
            'password' => 'pass',
        ]));
    }

    private function userCreateRequest(string $realmId, string $password): ServerRequestInterface
    {
        return $this->adminRequest('POST', '/admin/users', [
            'realm_id' => $realmId,
            'email' => 'policy-' . getGuid() . '@example.com',
            'password' => $password,
        ]);
    }
}
