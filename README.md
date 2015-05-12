# SimpleAuth - a simple PHP authentication library
[![Build Status](https://travis-ci.org/nichdu/simple-auth.svg?branch=master)](https://travis-ci.org/nichdu/simple-auth)

This is a simple PHP authentication library if you don't want to mess around with user names and passwords.

## Usage
Here is a basic usage example:
```php
<?php

require '/path/to/SimpleRoute/src/autoload.php';

$a = new SimpleRoute\Authenticator('verysecret');

// to create a hash to send to a server
$date = new DateTime;
$random = 'veryrandom';
$hash = $a->createAuthentication($random, $date);

// to check a received hash against the secret
$isValid = $a->authenticate($date, $random, $hash);
```

### Setting parameters
Parameter | Method | Explanation
--------- | ------ | -----------
Hash algorithm | `setHashAlgorithm` (instance method) | Setting the hash algorithm for hash creation and validation. The algorithm must be in `hash_algos()`.
Default hash algorithm | `setDefaultHashAlgorithm` (class method) | Setting the default hash algorithm. 
Hash rounds | `setHashRounds` (instance method) | Setting the number of hash rounds (log 2).
Default hash rounds | `setDefaultHashRounds` (class method) | Setting the default number of hash rounds (log 2). 
Time difference | `setTimeDifference` (instance method) | Setting the maximum time difference between creation of the authentication hash and its validation. If the time difference is longer than this value the authentication hash will be rejected. Keep in mind that people could have slow internet connections and wrong system clocks which can influence the hash's time.
Default time difference | `setDefaultTimeDifference` (class method) | Setting the default maximum time difference between creation of the authentication hash and its validation. See above for more information. 

Please note that all `default` methods will only influence future instances of `Authenticator`. Existing ones will keep their current values.

## How does it work?
To create your own authentication hash, you must do the following:

1. Use the same secret as the server
2. Generate a random string
3. Get the current date and time and format as string formatted according to PHP's [c-format][php-c-format] (ISO 8601)
4. Concatenate the random string, the date string, and the secret (in this order, without seperators)
5. Run the hash function you set the set number of times (e.g. in default settings: run sha-256 2^10 times.
6. The result is the authentication hash.

## Todos
- none, currently

[php-c-format]: https://php.net/manual/en/function.date.php "PHP: date - Manual"