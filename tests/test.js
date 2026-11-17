const assert = require('assert');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const { app } = require('../src/index');
const prisma = require('../src/db/prisma');

const PORT = 3999;
let server;
const BASE_URL = `http://localhost:${PORT}`;

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  let body;
  const text = await res.text();
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, headers: res.headers, body };
}

async function runTests() {
  console.log('--- Starting Comprehensive Test Suite ---');
  
  // Clean up test users from previous runs
  await prisma.user.deleteMany({
    where: {
      email: {
        in: [
          'alice@example.com',
          'bob@example.com',
          'short@example.com',
          'testnorm@example.com'
        ]
      }
    }
  });

  // Start temporary server for testing
  server = app.listen(PORT);
  console.log(`Test server running on port ${PORT}`);

  try {
    // ==========================================
    // A. POST /signup Scenarios
    // ==========================================
    console.log('\n[A] Testing POST /signup...');

    // 1. Successful registration with name & email normalization check
    const signupAlice = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({
        email: '   Alice@Example.com   ',
        password: 'password123',
        name: 'Alice'
      })
    });
    assert.strictEqual(signupAlice.status, 201, 'Signup Alice should return 201');
    assert.strictEqual(signupAlice.body.user.email, 'alice@example.com', 'Email should be normalized');
    assert.strictEqual(signupAlice.body.user.name, 'Alice', 'Name should match');
    assert.strictEqual(signupAlice.body.user.password, undefined, 'Password must not be returned');
    assert.ok(signupAlice.body.token, 'Signup should return JWT token');
    
    // Verify JWT payload
    const decodedSignupToken = jwt.verify(signupAlice.body.token, process.env.JWTSECRET);
    assert.strictEqual(decodedSignupToken.email, 'alice@example.com');
    assert.strictEqual(decodedSignupToken.id, signupAlice.body.user.id);
    assert.ok(decodedSignupToken.jti, 'Token must contain jti');
    console.log('✓ Successful registration with name and token verification passed');

    // Verify token can access protected routes directly
    const accessWithSignupTokenMe = await request('/me', {
      headers: { Authorization: `Bearer ${signupAlice.body.token}` }
    });
    assert.strictEqual(accessWithSignupTokenMe.status, 200);
    const accessWithSignupTokenDash = await request('/dashboard', {
      headers: { Authorization: `Bearer ${signupAlice.body.token}` }
    });
    assert.strictEqual(accessWithSignupTokenDash.status, 200);
    console.log('✓ JWT issued during signup can access both protected routes');

    // 2. Successful registration without name
    const signupBob = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({
        email: 'bob@example.com',
        password: 'password123'
      })
    });
    assert.strictEqual(signupBob.status, 201);
    assert.strictEqual(signupBob.body.user.name, null);
    console.log('✓ Successful registration without name passed');

    // 3. Missing email
    const missingEmail = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({ password: 'password123' })
    });
    assert.strictEqual(missingEmail.status, 400);
    console.log('✓ Missing email rejected with 400');

    // 4. Missing password
    const missingPassword = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({ email: 'bob2@example.com' })
    });
    assert.strictEqual(missingPassword.status, 400);
    console.log('✓ Missing password rejected with 400');

    // 5. Invalid email type
    const nonStringEmail = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({ email: 12345, password: 'password123' })
    });
    assert.strictEqual(nonStringEmail.status, 400);
    console.log('✓ Non-string email rejected with 400');

    // 6. Password shorter than 6 characters
    const shortPassword = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({ email: 'short@example.com', password: '123' })
    });
    assert.strictEqual(shortPassword.status, 400);
    console.log('✓ Password shorter than 6 characters rejected with 400');

    // 7. Duplicate email (exact and normalized)
    const duplicateEmail = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.com', password: 'password123' })
    });
    assert.strictEqual(duplicateEmail.status, 409);
    console.log('✓ Duplicate email rejected with 409');

    const duplicateEmailCase = await request('/signup', {
      method: 'POST',
      body: JSON.stringify({ email: '  ALICE@EXAMPLE.COM ', password: 'newpassword123' })
    });
    assert.strictEqual(duplicateEmailCase.status, 409);
    console.log('✓ Duplicate normalized email rejected with 409');

    // ==========================================
    // B. POST /login Scenarios
    // ==========================================
    console.log('\n[B] Testing POST /login...');

    // 1. Successful login
    const loginAlice = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ email: '  ALICE@EXAMPLE.COM  ', password: 'password123' })
    });
    assert.strictEqual(loginAlice.status, 200);
    assert.ok(loginAlice.body.token);
    assert.strictEqual(loginAlice.body.user.email, 'alice@example.com');
    assert.strictEqual(loginAlice.body.user.password, undefined);
    
    // Check JWT payload expiration (~1 hour)
    const decodedLoginToken = jwt.verify(loginAlice.body.token, process.env.JWTSECRET);
    const timeToExpire = decodedLoginToken.exp - decodedLoginToken.iat;
    assert.strictEqual(timeToExpire, 3600, 'JWT should expire in exactly 1 hour (3600 seconds)');
    assert.ok(decodedLoginToken.jti, 'JWT must contain jti');
    console.log('✓ Successful login passed with valid 1-hour JWT');

    // 2. Incorrect password
    const wrongPassword = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.com', password: 'wrongpassword' })
    });
    assert.strictEqual(wrongPassword.status, 401);

    // 3. Unknown email
    const unknownEmail = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'nonexistent@example.com', password: 'password123' })
    });
    assert.strictEqual(unknownEmail.status, 401);

    // Verify exact same generic error message
    assert.strictEqual(
      wrongPassword.body.error,
      unknownEmail.body.error,
      'Error message for incorrect password and unknown email must be identical'
    );
    console.log(`✓ Incorrect password and unknown email return identical 401 message: "${wrongPassword.body.error}"`);

    // 4. Missing fields
    const loginMissingFields = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.com' })
    });
    assert.strictEqual(loginMissingFields.status, 400);
    console.log('✓ Missing password on login rejected with 400');

    // ==========================================
    // C. GET /me Scenarios
    // ==========================================
    console.log('\n[C] Testing GET /me...');

    // 1. Valid JWT
    const meAlice = await request('/me', {
      headers: { Authorization: `Bearer ${loginAlice.body.token}` }
    });
    assert.strictEqual(meAlice.status, 200);
    assert.strictEqual(meAlice.body.email, 'alice@example.com');
    assert.strictEqual(meAlice.body.name, 'Alice');
    assert.ok(meAlice.body.id);
    assert.ok(meAlice.body.createdAt);
    assert.strictEqual(meAlice.body.password, undefined);
    console.log('✓ Valid token returns user details without password');

    // 2. Missing token
    const meNoToken = await request('/me');
    assert.strictEqual(meNoToken.status, 401);
    console.log('✓ Missing token returns 401');

    // 3. Invalid token
    const meInvalidToken = await request('/me', {
      headers: { Authorization: 'Bearer this.is.an.invalid.token' }
    });
    assert.strictEqual(meInvalidToken.status, 401);
    console.log('✓ Invalid token returns 401');

    // 4. Malformed header format
    const meMalformed = await request('/me', {
      headers: { Authorization: `Basic ${loginAlice.body.token}` }
    });
    assert.strictEqual(meMalformed.status, 401);
    console.log('✓ Malformed auth header returns 401');

    // 5. Expired token
    const expiredToken = jwt.sign(
      { id: signupAlice.body.user.id, email: 'alice@example.com', jti: crypto.randomUUID() },
      process.env.JWTSECRET,
      { expiresIn: '0s' }
    );
    const meExpired = await request('/me', {
      headers: { Authorization: `Bearer ${expiredToken}` }
    });
    assert.strictEqual(meExpired.status, 401);
    console.log('✓ Expired token returns 401');

    // ==========================================
    // D. GET /dashboard Scenarios
    // ==========================================
    console.log('\n[D] Testing GET /dashboard...');

    // 1. User name available (Alice)
    const dashAlice = await request('/dashboard', {
      headers: { Authorization: `Bearer ${loginAlice.body.token}` }
    });
    assert.strictEqual(dashAlice.status, 200);
    assert.strictEqual(dashAlice.body.message, 'Welcome, Alice!');
    console.log('✓ User with name available returns: Welcome, Alice!');

    // 2. User name unavailable (Bob)
    const loginBob = await request('/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'bob@example.com', password: 'password123' })
    });
    const dashBob = await request('/dashboard', {
      headers: { Authorization: `Bearer ${loginBob.body.token}` }
    });
    assert.strictEqual(dashBob.status, 200);
    assert.strictEqual(dashBob.body.message, 'Welcome, bob@example.com!');
    console.log('✓ User without name returns: Welcome, bob@example.com!');

    // 3. Missing token
    const dashNoToken = await request('/dashboard');
    assert.strictEqual(dashNoToken.status, 401);
    console.log('✓ Missing token on dashboard returns 401');

    // 4. Invalid token
    const dashInvalidToken = await request('/dashboard', {
      headers: { Authorization: 'Bearer totally-invalid-token' }
    });
    assert.strictEqual(dashInvalidToken.status, 401);
    console.log('✓ Invalid token on dashboard returns 401');

    // 5. User not found (valid token but user deleted / doesn't exist)
    const nonExistentUserToken = jwt.sign(
      { id: 'non-existent-user-id', email: 'ghost@example.com', jti: crypto.randomUUID() },
      process.env.JWTSECRET,
      { expiresIn: '1h' }
    );
    const dashGhost = await request('/dashboard', {
      headers: { Authorization: `Bearer ${nonExistentUserToken}` }
    });
    assert.strictEqual(dashGhost.status, 404);
    const meGhost = await request('/me', {
      headers: { Authorization: `Bearer ${nonExistentUserToken}` }
    });
    assert.strictEqual(meGhost.status, 404);
    console.log('✓ Non-existent user returns 404 on both /dashboard and /me');

    console.log('\n==========================================');
    console.log('ALL TESTS PASSED SUCCESSFULLY! (23/23 assertions)');
    console.log('==========================================\n');
  } finally {
    if (server) {
      server.close();
    }
    await prisma.$disconnect();
    process.exit(0);
  }
}

runTests().catch(async (err) => {
  console.error('Test failed:', err);
  if (server) server.close();
  await prisma.$disconnect().catch(() => {});
  process.exit(1);
});
