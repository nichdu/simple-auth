<?php

namespace SimpleAuth;


class AuthenticatorTest extends \PHPUnit_Framework_TestCase {
    const TEST_SECRET = "AQztHVL2tMUeJJddGV7jFHu7";
    const TEST_RANDOM = "cGYy5gjLTnkUdUdxQ6wuPMbQ";

    /**
     * @covers              \SimpleAuth\Authenticator\__construct
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testCannotBeConstructedWithoutSecret() {
        new Authenticator(null);
    }

    /**
     * @covers              \SimpleAuth\Authenticator\__construct
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testCannotBeConstructedWithInteger() {
        new Authenticator(1);
    }

    /**
     * @covers              \SimpleAuth\Authenticator\__construct
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testAuthenticateCannotBeCalledWithoutHash() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        // Test
        $a->authenticate(new \DateTime, '', null);
    }

    /**
     * @covers              \SimpleAuth\Authenticator\authenticate
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testAuthenticateCannotBeCalledWithoutRandom() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        // Test
        $a->authenticate(new \DateTime, null, '');
    }

    /**
     * @covers              \SimpleAuth\Authenticator\setHashAlgorithm
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testHashAlgorithmCannotBeCalledWithoutHashAlgorithm() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        // Test
        $a->setHashAlgorithm(null);
    }

    /**
     * @covers              \SimpleAuth\Authenticator\setHashAlgorithm
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testSetInvalidHashAlgorithm() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        // Test
        $a->setHashAlgorithm('test');
    }

    /**
     * @covers              \SimpleAuth\Authenticator\createAuthentication
     * @expectedException   \SimpleAuth\InvalidArgumentException
     */
    public function testCreateAuthenticationCannotBeCalledWithoutRandom() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        // Test
        $a->createAuthentication(null);
    }

    /**
     * @covers              \SimpleAuth\Authenticator\createAuthentication
     */
    public function testCreateAuthentication() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        $date = \DateTime::createFromFormat('U', '1431346677');
        $random = self::TEST_RANDOM;

        // Test
        $this->assertEquals("e940999a0c89d89636f8f318c6928ae8778b0593ac56f8746899380f13bfbcb9",
            $a->createAuthentication($random, $date));
    }

    /**
     * @covers              \SimpleAuth\Authenticator\authenticate
     */
    public function testAuthenticateWithWrongHash() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        $date = \DateTime::createFromFormat('U', '1431346677');
        $random = self::TEST_RANDOM;
        $hash = "36a9e7f1c95b82ffb99743e0c5c4ce95d83c9a430aac59f84ef3cbfab6145068";

        // Test
        $this->assertFalse($a->authenticate($date, $random, $hash));
    }

    public function testAuthenticateWithExpiredDate() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        $date = \DateTime::createFromFormat('U', '1431346677');
        $random = self::TEST_RANDOM;
        $hash = "e940999a0c89d89636f8f318c6928ae8778b0593ac56f8746899380f13bfbcb9";

        // Test
        $this->assertFalse($a->authenticate($date, $random, $hash));
    }

    public function testAuthenticate() {
        // Construct
        $a = new Authenticator(self::TEST_SECRET);

        $date = new \DateTime;
        $random = self::TEST_RANDOM;
        $hash = $a->createAuthentication($random, $date);

        // Test
        $this->assertTrue($a->authenticate($date, $random, $hash));
    }
}
