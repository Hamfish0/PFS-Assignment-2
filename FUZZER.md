# Fuzzer Test Coverage

## suite_login — `POST /api/auth/login`
- Empty password, empty username, both empty, unknown username
- SQL injection in the username field (8 payloads)
- Malformed bodies: empty, invalid JSON, array, integer, bare string, null
- Rate limiting — verifies a 429 is returned after 5 failed attempts

## suite_unauth — all protected endpoints
- Every protected endpoint called with no token, expects 401/403

## suite_bad_tokens — `GET /api/inventory`
- Empty string token
- Whitespace-only token
- Non-JWT string
- `alg=none` bypass attempt
- Truncated JWT
- Null byte in token
- Forged JWT with `role=admin` but invalid signature

## suite_inventory
- All three roles (admin/staff/viewer) can GET the list
- SQL injection in the `?q=` search parameter (8 payloads)
- Boundary strings in `?q=`: empty, whitespace, null bytes, 10,000-char string, path traversal, etc.
- Boundary integer IDs on GET: 0, -1, 999999, 2³¹
- Viewer forbidden on POST (create)
- Fuzz `name` field on POST: all SQL, XSS, SSTI, and boundary string payloads
- Fuzz `quantity` field on POST: negative, overflow, string, empty, null, float, array, object, injection string
- Malformed bodies on POST: empty, invalid JSON, array, integer, bare string, null
- SQL injection and XSS payloads in `name` on PUT
- Bad integer values in `quantity` on PUT
- Viewer forbidden on DELETE

## suite_users
- Viewer forbidden on `GET /api/auth/users`
- Unauthenticated `POST /api/auth/register` blocked
- Viewer `POST /api/auth/register` blocked
- Invalid roles on register: superadmin, root, empty string, null, integer, array, object
- SQL injection in the `username` field on register (8 payloads)
- Boundary strings in `username` on register (6 payloads)
- Self-delete blocked (admin cannot delete their own account)
- Viewer forbidden on `DELETE /api/auth/users`
- Boundary IDs on DELETE: 0, -1, 999999, 2³¹

## suite_misc
- Admin can access `GET /api/audit`
- Admin can access `GET /api/locations` and `GET /api/suppliers`
- HTTP verb tampering: DELETE/PUT on collection endpoints, GET on login, DELETE on user collection, PATCH on item
