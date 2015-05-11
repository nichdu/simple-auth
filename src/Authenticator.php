<?php
/*
 * This file is part of the SimpleAuth package.
 *
 * (c) Tjark Saul <php@tjarksaul.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
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
    private $secret;
    /**
     * @var string
     */
    private $hashAlgorithm = 'sha256';
    /**
     * @var int
     */
    private $timeDiff = 60;
    /**
     * @var int
     */
    private $hashRounds = 10;

    /**
     * Creates an authenticator using the given secret
     * @param $secret string
     */
    public function __construct($secret) {
        if (!is_string($secret)) {
            throw new InvalidArgumentException('$secret must be a string');
        }

        $this->secret = $secret;
    }

    /**
     * Sets the hash algorithm for creation and comparison
     * @param $hashAlgorithm string a hash algorithm from hash_algos()
     */
    public function setHashAlgorithm($hashAlgorithm) {
        if (!is_string($hashAlgorithm)) {
            throw new InvalidArgumentException('$hashAlgorithm must be a string');
        }
        if (!in_array($hashAlgorithm, \hash_algos())) {
            throw new InvalidArgumentException('$hashAlgorithm must be a valid hash algorithm from hash_algos()');
        }
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * Sets the maximum time difference a request may have to be authenticated
     * @param $timeDifference int maximum time difference in seconds
     */
    public function setTimeDifference($timeDifference) {
        if (!is_integer($timeDifference)) {
            throw new InvalidArgumentException('$timeDifference must be an integer');
        }
        if ($timeDifference < 0) {
            throw new InvalidArgumentException('$timeDifference must be a positive integer (including 0)');
        }
        $this->timeDiff = $timeDifference;
    }

    /**
     * Sets the number of hash rounds to run through. Higher numbers are more secure.
     * @param $hashRounds int the number of hash rounds log 2
     */
    public function setHashRounds($hashRounds) {
        if (!is_integer($hashRounds)) {
            throw new InvalidArgumentException('$hashRounds must be an integer');
        }
        if ($hashRounds < 0) {
            throw new InvalidArgumentException('$hashRounds must be a positive integer (including 0)');
        }
        $this->hashRounds = $hashRounds;
    }

    /**
     * tries to authenticate by the given random and hash from the given DateTime
     * @param \DateTime $date date and time from the request
     * @param $random string random from the request
     * @param $hash string given hash
     * @return bool true if the authentication was successful, false otherwise
     */
    public function authenticate(\DateTime $date, $random, $hash) {
        if (!is_string($random)) {
            throw new InvalidArgumentException('$random must be a string');
        }
        if (!is_string($hash)) {
            throw new InvalidArgumentException('$hash must be a string');
        }

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
        if (\hash_equals($expected, $hash)) {
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
     * @param $random string a random string
     * @param \DateTime $date the date and time to be used, defaults to now
     * @return string the hash to send
     */
    public function createAuthentication($random, \DateTime $date = null) {
        if (!is_string($random)) {
            throw new InvalidArgumentException('$random must be a string');
        }
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