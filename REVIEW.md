# Code Review — Taskboard Assessment

## Issue 1: Viewers Can Update Tasks (Security / Data Integrity)

**File:** `src/app/api/tasks/[id]/route.ts:16-38`
**Severity:** Critical
**Category:** Security / Data Integrity

The `PATCH` handler updates any task without checking the user's project membership or role. The `DELETE` handler (lines 49-53) correctly calls `getProjectMembership` and `canEditTasks`, but `PATCH` skips both. Any authenticated user — including viewers — can modify task title, description, status, assignee, and position.

**Recommended fix:** Add membership and role checks before the update:

```typescript
const membership = await getProjectMembership(user.id, existing.projectId);
if (!membership) return forbidden("you are not a member of this project");
if (!canEditTasks(membership.role)) {
  return forbidden("viewers cannot update tasks");
}
```

---

## Issue 2: Password Hashes Exposed in API Responses (Security)

**File:** `src/app/api/projects/[id]/route.ts:25-40`
**Severity:** Critical
**Category:** Security

The `GET /api/projects/[id]` endpoint uses `prisma.project.findUnique` with `include: { owner: true, memberships: { include: { user: true } } }`. Prisma returns the full `User` record including `passwordHash`. The `ApiProjectDetail` type (`src/types/index.ts:35`) explicitly includes `passwordHash?: string` on the owner and membership users.

Every authenticated user who can view a project receives bcrypt password hashes of all project members. An attacker who gains access to any project can extract all members' password hashes and attempt offline brute-force attacks.

**Recommended fix:** Use `select` to explicitly fetch only safe fields on owner and user:

```typescript
owner: { select: { id: true, name: true, email: true } },
memberships: {
  include: { user: { select: { id: true, name: true, email: true } } },
},
```

---

## Issue 3: SQL Injection in Task Search (Security)

**File:** `src/app/api/projects/[id]/tasks/route.ts:27-34`
**Severity:** High
**Category:** Security

The GET handler interpolates the `q` query parameter directly into a raw SQL query. An attacker can inject arbitrary SQL via the `q` parameter.

**Recommended fix:** Use Prisma's built-in filtering instead of raw SQL.

---

## Issue 4: Assignee Assignment Bypasses Project Membership (Data Integrity)

**File:** `src/app/api/tasks/[id]/route.ts:31`
**Severity:** Medium
**Category:** Data Integrity

The PATCH handler accepts an `assigneeId` with no validation that the target user is a member of the task's project. Any user can be assigned to any task, even if they have no membership in the project. The client-side UI (`TaskDetail.tsx:117-121`) restricts the dropdown to project members, but this can be bypassed by calling the API directly.

This creates orphaned data: a task's `assigneeId` references a `User` who is not a member of the task's `projectId`.

**Recommended fix:** Validate assignee membership before updating:

```typescript
if (parsed.data.assigneeId) {
  const memberCheck = await getProjectMembership(parsed.data.assigneeId, existing.projectId);
  if (!memberCheck) return badRequest("assignee is not a member of this project");
}
```

---

## Proof of Bug: Issue 1 (Viewer Updating Task)

**Setup (from `prisma/seed.ts`):** `dev@example.com` is a **viewer** on the Q3 Launch project.

**Steps:**
1. Login as viewer to get a token: `curl -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d '{"email":"dev@example.com","password":"password123"}'`
2. Get a task ID from Q3 Launch: `curl http://localhost:3000/api/projects/<PROJECT_ID>/tasks -H "Authorization: Bearer <VIEWER_TOKEN>"`
3. Attempt to update the task as a viewer:

```bash
curl -X PATCH http://localhost:3000/api/tasks/<TASK_ID> \
  -H "Authorization: Bearer <VIEWER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title": "Updated by viewer"}'
```

**Response (HTTP 200 — should be 403):**
```json
{"task":{"id":"<TASK_ID>","title":"Updated by viewer","description":"Detail for: Finalize launch date with marketing","status":"done","position":0,"projectId":"<PROJECT_ID>","assigneeId":"<meera-id>","createdById":"<meera-id>","createdAt":"...","updatedAt":"..."}}
```

The viewer successfully modified the task despite `canEditTasks("viewer")` returning `false`.
