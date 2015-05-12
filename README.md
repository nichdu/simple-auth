# SimpleAuth - a simple PHP authentication library
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
You can influence all used parameters by instance methods. If you want to change the secret you should create a new instance of `Authenticator`. To set the hash algorithm call `setHashAlgorithm($algo)`. Please note that the algorithm must be contained in `hash_algos()`. You can change the number of hash rounds (base 2) by calling `setHashRounds($rounds)`. To change the maximum time difference between the given DateTime and now in `authenticate` you can use `setTimeDifference($diff)`.

## How does it work?
To create your own authentication hash, you must do the following:
1. Use the same secret as the server
2. Generate a random string
3. Get the current date and time and format as string formatted according to PHP's [c-format][php-c-format] (ISO 8601)
4. Concatenate the random string, the date string, and the secret (in this order, without seperators)
5. Run the hash function you set the set number of times (e.g. in default settings: run sha-256 2^10 times.
6. The result is the authentication hash.

## Todos
- allow preference setting as static methods to change for all instances

[php-c-format]: https://php.net/manual/en/function.date.php "PHP: date - Manual"