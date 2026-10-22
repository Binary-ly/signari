<?php

use App\Http\Controllers\SignariSignInController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

// Signing in to the console through Signari (6.06): 404 until it is configured.
Route::get('/signari/login', [SignariSignInController::class, 'redirect'])->name('signari.login');
Route::get('/signari/callback', [SignariSignInController::class, 'callback'])->name('signari.callback');
