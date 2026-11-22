<?php

namespace App\Services;

use RuntimeException;

/** A sign-in through Signari that did not complete, in words for the operator. */
class SignInRefused extends RuntimeException {}
