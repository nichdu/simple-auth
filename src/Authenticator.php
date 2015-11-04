<?php
/*
 * This file is part of the SimpleAuth package.
 *
 * (c) Tjark Saul <php@tjarksaul.de>
 *§
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
declare(strict_types=1);

namespace SimpleAuth;
/**
 * This class represents an authenticator to authenticate users
 *
 * @package    SimpleAuth
 * @author     Tjark Saul <php@tjarksaul.de>
 * @copyright  Tjark Saul <php@tjarksaul.de>
 * @license    https://spdx.org/licenses/BSD-4-Clause  The BSD 4-Clause License
 * @link       http://www.github.com/nichdu/simple-auth
 */
class Authenticator {
    /**
     * @var string
     */
    private static $defaultHashAlgorithm   = 'sha256';
    /**
     * @var int
     */
    private static $defaultTimeDiff        = 60;
    /**
     * @var int
     */
    private static $defaultHashRounds      = 10;

    /**
     * Gets the default hash algorithm for creation and comparison of authentication hashes.
     * @return string
     */
    public static function getDefaultHashAlgorithm() : string {
        return self::$defaultHashAlgorithm;
    }

    /**
     * Sets the default hash algorithm for creation and comparison of authentication hashes.
     * @param string $algorithm a hash algorithm from hash_algos()
     */
    public static function setDefaultHashAlgorithm(string $algorithm) {
        if (!in_array($algorithm, \hash_algos())) {
            throw new InvalidArgumentException('$hashAlgorithm must be a valid hash algorithm from hash_algos()');
        }
        self::$defaultHashAlgorithm = $algorithm;
    }

    /**
     * Returns the default time difference within an authentication hash is valid.
     * @return int
     */
    public static function getDefaultTimeDifference() : int {
        return self::$defaultTimeDiff;
    }

    /**
     * Sets the default maximum time difference a request may have to be authenticated
     * @param int $timeDiff maximum time difference in seconds
     */
    public static function setDefaultTimeDifference(int $timeDiff) {
        if ($timeDiff < 0) {
            throw new InvalidArgumentException('$timeDifference must be a positive integer (including 0)');
        }
        self::$defaultTimeDiff = $timeDiff;
    }

    /**
     * Returns the default number of hash rounds.
     * @return int
     */
    public static function getDefaultHashRounds() : int {
        return self::$defaultHashRounds;
    }

    /**
     * Sets the default number of hash rounds to run through. Higher numbers are more secure.
     * @param int $rounds the number of hash rounds log 2
     */
    public static function setDefaultHashRounds(int $rounds) {
        if ($rounds < 0) {
            throw new InvalidArgumentException('$hashRounds must be a positive integer (including 0)');
        }
        self::$defaultHashRounds = $rounds;
    }

    /**
     * @var string
     */
    private $secret;
    /**
     * @var string
     */
    private $hashAlgorithm;
    /**
     * @var int
     */
    private $timeDiff;
    /**
     * @var int
     */
    private $hashRounds;

    /**
     * Creates an authenticator using the given secret
     * @param string $secret
     */
    public function __construct(string $secret) {
        if (empty($secret)) {
            throw new InvalidArgumentException('$secret must be a non-empty string');
        }
        $this->secret = $secret;
        $this->hashAlgorithm = self::getDefaultHashAlgorithm();
        $this->hashRounds = self::getDefaultHashRounds();
        $this->timeDiff = self::getDefaultTimeDifference();
    }

    /**
     * Sets the hash algorithm for creation and comparison
     * @param string $hashAlgorithm a hash algorithm from hash_algos()
     */
    public function setHashAlgorithm(string $hashAlgorithm) {
        if (!in_array($hashAlgorithm, \hash_algos())) {
            throw new InvalidArgumentException('$hashAlgorithm must be a valid hash algorithm from hash_algos()');
        }
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * Sets the maximum time difference a request may have to be authenticated
     * @param int $timeDifference maximum time difference in seconds
     */
    public function setTimeDifference(int $timeDifference) {
        if ($timeDifference < 0) {
            throw new InvalidArgumentException('$timeDifference must be a positive integer (including 0)');
        }
        $this->timeDiff = $timeDifference;
    }

    /**
     * Sets the number of hash rounds to run through. Higher numbers are more secure.
     * @param int $hashRounds the number of hash rounds log 2
     */
    public function setHashRounds(int $hashRounds) {
        if ($hashRounds < 0) {
            throw new InvalidArgumentException('$hashRounds must be a positive integer (including 0)');
        }
        $this->hashRounds = $hashRounds;
    }

    /**
     * tries to authenticate by the given random and hash from the given DateTime
     * @param \DateTime $date date and time from the request
     * @param string $random random from the request
     * @param string $hash given hash
     * @return bool true if the authentication was successful, false otherwise
     */
    public function authenticate(\DateTime $date, string $random, string $hash) {
        // setting date's time zone to UTC and setting format to ISO8601
        $date->setTimezone(new \DateTimeZone('UTC'));
        $dateString = $date->format('c');

        // creating the expected string
        $expected = $random . $dateString . $this->secret;
        // hashing for at least one round
        for ($i = 0; $i < pow(2, $this->hashRounds); ++$i) {
            $expected = hash($this->hashAlgorithm, $expected);
        }

        // checking if the given hash is correct
        if (!function_exists('hash_equals')) { require __DIR__ . '/functions.php'; } // PHP < 5.6 compatibility
        if (hash_equals($expected, $hash)) {
            // wir müssen das Datum checken
            $diff = abs($date->getTimestamp() - (new \DateTime)->getTimestamp());
            if ($diff <= $this->timeDiff) {
                return true;
            }
        }
        return false;
    }

    /**
     * creates an authentication from the given random and DateTime
     * @param string $random a random string
     * @param \DateTime $date the date and time to be used, defaults to now
     * @return string the hash to send
     */
    public function createAuthentication(string $random, \DateTime $date = null) {
        if (is_null($date)) { $date = new \DateTime; }

        // setting date's time zone to UTC and setting format to ISO8601
        $date->setTimezone(new \DateTimeZone('UTC'));
        $dateString = $date->format('c');

        $hash = $random . $dateString . $this->secret;
        // hashing for at least one round
        for ($i = 0; $i < pow(2, $this->hashRounds); ++$i) {
            $hash = hash($this->hashAlgorithm, $hash);
        }

        return $hash;
    }
}