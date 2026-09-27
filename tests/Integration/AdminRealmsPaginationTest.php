<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminAppTestCase;

class AdminRealmsPaginationTest extends AdminAppTestCase
{
    public function testListRealmsReturnsPaginatedEnvelope(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms'));

        self::assertArrayHasKey('items', $data);
        self::assertArrayHasKey('total', $data);
        self::assertArrayHasKey('limit', $data);
        self::assertArrayHasKey('offset', $data);
        self::assertSame(50, $data['limit']);
        self::assertSame(0, $data['offset']);
        self::assertSame(count($data['items']), $data['total']);

        $names = array_column($data['items'], 'name');
        self::assertContains('web', $names);
        self::assertContains('test', $names);
    }

    public function testListRealmsPaginatesWithinSameTotal(): void
    {
        $page1 = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms', [], [
            'limit' => 1,
            'offset' => 0,
        ]));
        $page2 = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms', [], [
            'limit' => 1,
            'offset' => 1,
        ]));

        self::assertCount(1, $page1['items']);
        self::assertCount(1, $page2['items']);
        self::assertNotSame($page1['items'][0]['id'], $page2['items'][0]['id']);
        self::assertSame($page1['total'], $page2['total'], 'total must be independent of limit/offset');
        self::assertGreaterThanOrEqual(2, $page1['total']);
    }

    public function testListRealmsInvalidPaginationFallsBackToDefaults(): void
    {
        foreach (['abc', '-5', '0', '201'] as $invalid) {
            $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms', [], [
                'limit' => $invalid,
            ]));
            self::assertSame(50, $data['limit'], "invalid limit '$invalid' should fall back to default");
            self::assertSame(0, $data['offset']);
        }

        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/realms', [], [
            'offset' => -3,
        ]));
        self::assertSame(0, $data['offset'], 'negative offset should fall back to default');
    }
}
