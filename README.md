# D:\workspace\practice_lab16\README.md
# Lecture 18 - RESTful API (Part 3)


### ป้อนข้อมูลนักศึกษา

รหัส นศ.: 670610723

ชื่อ-สกุล : ภูรินท์ อินทจักร์ (Phurin Inthajak)

### Content

- Current API
- Create route handlers for `/api/v2/users`
- JSON Web Token
- Role-based Access Control (RBAC)
- Token Authentication Middleware
- Check Role Middlewares
- Stores JWTs in User database

---

### Current API

**Route Handlers**

- `/api/v2/students` : CRUD API for Students data (in-memory DB)
- `/api/v3/students` : CRUD API for Students data (JSON file)
- `/api/v2/courses` : CRUD API for Courses data (in-memory DB) **NOT DONE!!**

**TypeScript interfaces**

Interface for main data are defined in `src/libs/types.ts`:

- `Student`
- `Course`
- `Enrollment`
- `User`

There are also other interfaces for JWT and Middleware

- `UserPayload` : Payload that stores authenticated user data
- `CustomRequest` : HTTP Request + some stuff

**In-memory DB**

Variables that stores data is defined in `src/db/db.ts`

- `students: Student[]` : students data
- `courses: Course[]` : courses data
- `enrollments: Entrollment[]` : enrollments data
- `users: User[]` : users data

There are some functions for reset variables above back to the `orignal` values as well.

- `reset_users(), reset_students(), reset_courses(), ...`

**JSON file**

Files that stores persistent data. (Not working in Vercel)

- `src/db/db_courses.json`
- `src/db/db_students.json`

Functions for `read`/`write` JSON file are defined in `src/db/db_transactions.ts`

**Middlewares**

- `express.json()`: extract and parsing JSON from request's body
- `morgan("dev")`: request logging
- `invalidJsonMiddleware`: check invalid JSON format in request's body
- `notFoundMiddleware` : check if endpoint/routes do not exist?

---

### Create Route Handlers for `/api/v2/users`

Create a file `src/routes/usersRoutes.ts`

```typescript
import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, CustomRequest } from "../libs/types.js";

// import database
import { users, reset_users } from "../db/db.js";

const router = Router();

// GET /api/v2/users
router.get("/", (req: Request, res: Response) => {
  try {
    // return all users
    return res.json({
      success: true,
      data: users,
    });
  } catch (err) {
    return res.status(200).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// POST /api/v2/users/login
router.post("/login", (req: Request, res: Response) => {
  // 1. get username and password from body

  // 2. check if user exists (search with username & password in DB)

  // 3. create JWT token (with user info object as payload) using JWT_SECRET_KEY
  //    (optional: save the token as part of User data)

  // 4. send HTTP response with JWT token

  return res.status(500).json({
    success: false,
    message: "POST /api/v2/users/login has not been implemented yet",
  });
});

// POST /api/v2/users/logout
router.post("/logout", (req: Request, res: Response) => {
  // 1. check Request if "authorization" header exists
  //    and container "Bearer ...JWT-Token..."

  // 2. extract the "...JWT-Token..." if available

  // 3. verify token using JWT_SECRET_KEY and get payload (username, studentId and role)

  // 4. check if user exists (search with username)

  // 5. proceed with logout process and return HTTP response
  //    (optional: remove the token from User data)

  return res.status(500).json({
    success: false,
    message: "POST /api/v2/users/logout has not been implemented yet",
  });
});

// POST /api/v2/users/reset
router.post("/reset", (req: Request, res: Response) => {
  try {
    reset_users();
    return res.status(200).json({
      success: true,
      message: "User database has been reset",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;
```

---

### JSON Web Token

- `JWT` is a `special string` that an `API server` generates once a user authenticates successfully.
- `JWT` string contains 3 parts : [ `HEADER`.`Payload`.`Signature` ]
- Client receives the `JWT` and **attachs the token to subsequent HTTP requests**
- Server verify received `JWT` and extracts `Payload` which may contain `user` and `role/permission` information then process them accordingly

[JWT Debugger](https://www.jwt.io/)

To create `JWT`, we can use this code pattern.

```typescript
// Get JWT_SECRET_KEY from .env file
const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";

// Create/sign a JWT with JWT_SECRET_KEY
// The payload is an object containing { username, studentId, role }
const token = jwt.sign(
  {
    // create JWT Payload
    username: "user4@abc.com",
    studentId: null,
    role: "ADMIN",
  },
  jwt_secret,
  { expiresIn: "5m" }
);
```

After that we can send `JWT` back to the client with `HTTP response`

```typescript
return res.status(200).json({
  success: true,
  message: "Login successful",
  token,
});
```

---

### Role-based Access Control (`RBAC`)

To allow only HTTP request from `ADMIN` to access `GET /api/v2/users`, we need to modify this route handler code.

```typescript
// GET /api/v2/users (ADMIN only)
router.get("/", (req: Request, res: Response) => {
  try {
    // 1. check Request if "authorization" header exists
    //    and container "Bearer ...JWT-Token..."

    // 2. extract the "...JWT-Token..." if available

    // 3. verify token using JWT_SECRET_KEY and get payload (username, studentId and role)

    // 4. check if user exists (search with username) and role is ADMIN

    // return all users
    return res.json({
      success: true,
      data: users,
    });
  } catch (err) {
    return res.status(200).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});
```

---

### Token Authentication Middleware

For any endpoint that only allows **authenticated user** to use, there are a few similar steps.

1. Check **HTTP Request** if `authorization` header exists and container `"Bearer ...JWT-Token..."`
2. Extract the `...JWT-Token...` if available
3. Verify `token` using **JWT_SECRET_KEY** and get `JWT payload` (username, studentId and role)

We can create a **middleware** to do this work and `use` the middleware on those endpoints.

Let's create `src/middlewares/authenMiddleware.ts`:

```typescript
import { type Request, type Response, type NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import { type CustomRequest, type UserPayload } from "../libs/types.js";

// interface CustomRequest extends Request {
//   user?: any; // Define the user property
//   token?: string; // Define the token property
// }

export const authenticateToken = (
  req: CustomRequest, // using a custom request
  res: Response,
  next: NextFunction
) => {
  // 1. check Request if "authorization" header exists
  //    and container "Bearer ...JWT-Token..."
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authorization header is required",
    });
  }

  // 2. extract the "...JWT-Token..." if available
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null)
    return res.status(401).json({
      success: false,
      message: "Token is required",
    });

  try {
    // 3. verify token using JWT_SECRET_KEY and
    //    get payload "user" = { username, studentId, role }
    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";
    jwt.verify(token, jwt_secret, (err, user) => {
      if (err)
        return res.status(403).json({
          success: false,
          message: "Invalid or expired token",
        });

      // 4. Attach "user" payload and "other stuffs" to the custom request
      req.user = user as UserPayload;
      req.token = token;

      // 5. Proceed to next middleware or route handler
      next();
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong with authentication process",
      error: err,
    });
  }
};
```

Now we can use the `authenticateToken` middleware with the `GET /api/v2/users`.

```typescript
// GET /api/v2/users (ADMIN only)
router.get("/", authenticateToken, (req: Request, res: Response) => {
  try {
    // After the Request has been processed by 'authenticateToken' middleware
    // 1. Get "user payload" and "token" from (custom) request
    const payload = (req as CustomRequest).user;
    const token = (req as CustomRequest).token;

    // 2. check if user exists (search with username) and role is ADMIN

    // return all users
    return res.json({
      success: true,
      data: users,
    });
  } catch (err) {
    return res.status(200).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});
```

---

### Check Role Middlewares

There are many API endpoints that may require `ADMIN` access, for example:

**Users**

- `POST /api/v2/users`
- `PUT /api/v2/users`
- `DELETE /api/v2/users`

**Courses**

- `POST /api/v2/courses`
- `PUT /api/v2/courses`
- `DELETE /api/v2/courses`

**Students**

- `GET /api/v2/students`
- `POST /api/v2/students`
- `PUT /api/v2/students`
- `DELETE /api/v2/students`

And there are some endpoints that should be accessible by both `ADMIN` and `STUDENT`.

`GET /api/v2/students/:studentId`

- `ADMIN` should be able to access data of all students.
- Only `STUDENT` who has the same `studentId` can access his/her data.

We can create `checkRoleAdmin` middlewares to help checking `ADMIN` role by creating `src/middlewares/checkRoleAdminMiddleware.ts`

```typescript
// src/middlewares/checkRoleAdminMiddleware.ts
import { type Request, type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

// interface CustomRequest extends Request {
//   user?: any; // Define the user property
//   token?: string; // Define the token property
// }

export const checkRoleAdmin = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  // 1. get "user payload" and "token" from (custom) request
  const payload = req.user;
  const token = req.token;

  // 2. check if user exists (search with username) and role is ADMIN
  const user = users.find((u: User) => u.username === payload?.username);
  if (!user || user.role !== "ADMIN") {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user",
    });
  }

  // (optional) check if token exists in user data

  // Proceed to next middleware or route handler
  next();
};
```

We can also create `checkRoles` middlewares to help checking if a user is existed by creating `src/middlewares/checkRolesMiddleware.ts`

```typescript
// src/middlewares/checkRolesMiddleware.ts
import { type Request, type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users, reset_users } from "../db/db.js";

// interface CustomRequest extends Request {
//   user?: any; // Define the user property
//   token?: string; // Define the token property
// }

export const checkRoles = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  // 1. get "user payload" and "token" from (custom) request
  const payload = req.user;
  const token = req.token;

  // 2. check if user exists (search with username)
  const user = users.find((u: User) => u.username === payload?.username);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user",
    });
  }

  // (optional) check if token exists in user data

  // Proceed to next middleware or route handler
  next();
};
```

Let's use `checkRoleAdmin` with `GET /api/v2/users` to allow only ADMIN access.

```typescript
// GET /api/v2/users (ADMIN only)
router.get(
  "/",
  authenticateToken, // verify token and extract "user payload"
  checkRoleAdmin, // check User exists and ADMIN role
  (req: Request, res: Response) => {
    try {
      // return all users
      return res.json({
        success: true,
        data: users,
      });
    } catch (err) {
      return res.status(200).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);
```

For the `GET /api/v2/students/:studentId` endpoint, we will use `checkRoles` middleware.

```typescript
// GET /api/v2/students/{studentId}
router.get(
  "/:studentId",
  authenticateToken,
  checkRoles,
  (req: Request, res: Response) => {
    try {
      ...

      // 1. get "user payload" from (custom) request
      const payload = (req as CustomRequest).user;

      // 2. get "studentId" from endpoint param and validate with Zod
      const studentId = req.params.studentId;
      const parseResult = zStudentId.safeParse(studentId);
      ...

      // if role is STUDENT, user can only access their own data
      if (payload?.role === "STUDENT" && payload?.studentId !== studentId) {
        return res.status(403).json({
          success: false,
          message: "Forbidden access",
        });
      }

      // proceed with search with studentId and return results
      ...

    }
  }
);
```

---

### Stores JWTs in User database

So far, we do not store any `JWT` of any authenticated users.

- We do not know how many `JWT` the server have generated.
- We do not know how many `JWT` belongs to each user.

Let's try storing `JWT` as part of each user's data, for example:

```json
[
  {
    "username": "user3@abc.com",
    "password": "1234",
    "studentId": "650610003",
    "role": "STUDENT",
    "tokens": [
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIzQGFiYy5jb20iLCJzdHVkZW50SWQiOiI2NTA2MTAwMDMiLCJyb2xlIjoiU1RVREVOVCIsImlhdCI6MTc1ODczMjI5MiwiZXhwIjoxNzU4NzMyNTkyfQ.HpZRo8wAC2SrfDcqS8KfgfyPEbAhdwaFeJ0CEy5-i5M",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIzQGFiYy5jb20iLCJzdHVkZW50SWQiOiI2NTA2MTAwMDMiLCJyb2xlIjoiU1RVREVOVCIsImlhdCI6MTc1ODczMjI5NiwiZXhwIjoxNzU4NzMyNTk2fQ.AMAbve9SezmViPBQy9G044g-lXS_anGwlvZa8X8brps"
    ]
  },
  {
    "username": "user4@abc.com",
    "password": "5678",
    "studentId": null,
    "role": "ADMIN",
    "tokens": [
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXI0QGFiYy5jb20iLCJzdHVkZW50SWQiOm51bGwsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc1ODczMjMxMCwiZXhwIjoxNzU4NzMyNjEwfQ.NB435PtafbLgrT-FizbLi_9Bpo7TG8ACL2LVaSDFmbs"
    ]
  }
]
```

We will create and store a `JWT` when a client authenticates user successfully with `POST /api/v2/users/login` endpoint.

```typescript
// src/routes/usersRouters.ts
import { users, reset_users } from "../db/db.js";

// POST /api/v2/users/login
router.post("/login", (req: Request, res: Response) => {
  try {

    // create/sign JWT and the user exists

    // store the new token in user.tokens
    user.tokens = user.tokens ? [...user.tokens, token] : [token];

    // return HTTP response with token
  }
  ...
});

```

And after successfully logout with `POST /api/v2/users/logout` endpoint, we will remove the attached with the request from user's data.

Note that, we use `authenticateToken` with this endpoint.

```typescript
// src/routes/usersRouters.ts

// POST /api/v2/users/logout
router.post("/logout", authenticateToken, (req: Request, res: Response) => {
  try {
    ...

    // get token

    // check if token exists in user.tokens
    if (!user.tokens || !user.tokens.includes(token)) {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    // if token exists, remove the token from user.tokens
    user.tokens = user.tokens?.filter((t) => t !== token);

    // return HTTP response with successful message
  }
  ...
});
```































































































ได้เลย! ผมใส่ “คอมเมนต์แบบละเอียดทุกบรรทัด” ลงให้แล้วในแคนวาสข้างๆ ชื่อไฟล์ว่า

**API Labs 15–16: โค้ดพร้อมคอมเมนต์ทุกบรรทัด (เวอร์ชันติวสอบ)**

รอบนี้ครอบคลุมไฟล์สำคัญของ **Lab16** (ที่มักจะงงที่สุด):

* `src/index.ts` (จุดเริ่มระบบ)
* `src/libs/types.ts` (ชนิดข้อมูลทั้งหมด)
* `src/libs/zodValidators.ts` (ตัวตรวจสอบข้อมูลด้วย Zod)
* `src/db/db.ts` (mock DB + reset)
* `src/middlewares/*` (ตรวจ JWT และ RBAC ครบ 4 ตัว)
* `src/routes/usersRoutes.ts` (login / logout / list users แบบ ADMIN)
* `src/routes/enrollmentsRoutes_v2.ts` (GET/POST/DELETE enrollments ตาม RBAC)

ทุกไฟล์ “คอมเมนต์บรรทัดต่อบรรทัด” อธิบายว่า

* import นี้คืออะไร ใช้ทำไม
* ตัวแปร/ฟังก์ชันแต่ละตัวทำหน้าที่อะไร
* แต่ละ `status code` ถูกเลือกเพราะอะไร
* ลอจิก RBAC ตรวจสิทธิ์อย่างไรในแต่ละเงื่อนไข

ถ้าต้องการให้ผมทำ **Lab15 (student/course)** แบบละเอียดทุกบรรทัดในสไตล์เดียวกันต่อเลย ก็บอกมาได้ทันที เดี๋ยวผมเติมให้ครบชุด (เช่น `courseRoutes.ts`, `studentRoutes.ts`, และ validator ฝั่ง Lab15 ที่ใช้ `number` 6 หลัก) เพื่อให้พร้อมซ้อมก่อนสอบครับ 💪


```typescript
// =============================================================
// FILE: src/index.ts  — จุดเริ่มต้นของแอป (Lab16 โครงรวม)
// =============================================================

import express, { type Request, type Response } from "express"; // นำเข้า Express (ตัวสร้างเว็บเซิร์ฟเวอร์) และชนิด TypeScript ของ Request/Response เพื่อให้โค้ดมี type safety
import morgan from "morgan";                                     // นำเข้า morgan (middleware สำหรับ log รายการ request แบบสั้น ๆ ใน console)

import invalidJsonMiddleware from "./middlewares/invalidJsonMiddleware.js"; // middleware จับ error เมื่อ body JSON ของ request มีรูปแบบพัง/พิมพ์ผิด

import usersRoutes        from "./routes/usersRoutes.js";        // เส้นทางที่เกี่ยวกับผู้ใช้ (login/logout, list users)
import enrollmentsRoutes  from "./routes/enrollmentsRoutes_v2.js"; // เส้นทางลงทะเบียนเรียน (ดูทั้งระบบ, ดูเฉพาะคน, add/drop ฯลฯ)

const app  = express();                                           // สร้าง instance ของ Express app ("หัวใจ" ของเซิร์ฟเวอร์ HTTP ทั้งหมด)
const port = Number(process.env.PORT) || 3000;                    // กำหนดพอร์ตจากตัวแปรแวดล้อม (.env) ถ้าไม่มีให้ใช้ 3000 เป็นค่าเริ่มต้น

app.use(express.json());                                          // ติดตั้ง body parser เพื่อให้ req.body สามารถอ่าน JSON ได้ (สำคัญกับ POST/PUT/DELETE)
app.use(morgan("dev"));                                          // ติดตั้ง logger — จะแสดง method, path, status code, response time
app.use(invalidJsonMiddleware);                                   // ติดตั้ง middleware จับ JSON พัง — ถ้า body ไม่ใช่ JSON ถูกต้อง จะตอบ 400 โดยไม่ไปต่อ

app.get("/", (req: Request, res: Response) => {                  // สร้าง endpoint GET / (เช็คว่าเซิร์ฟเวอร์ออนไลน์)
  res.status(200).send("Lab 16 API services");                   // ตอบ 200 OK พร้อมข้อความสั้น ๆ
});

app.use("/api/v2/users",        usersRoutes);                    // เมาท์กลุ่มเส้นทางผู้ใช้ไว้ใต้ /api/v2/users (เช่น POST /api/v2/users/login)
app.use("/api/v2/enrollments",  enrollmentsRoutes);              // เมาท์กลุ่มเส้นทางลงทะเบียนไว้ใต้ /api/v2/enrollments

// fallback เมื่อหา endpoint ไม่เจอ — ควรอยู่ท้ายสุดเสมอ
app.use((req, res) => res.status(404).json({ success:false, message:"Endpoint not found" })); // ถ้าไม่มี route ใด match ให้ตอบ 404 JSON มาตรฐาน

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`)); // สั่งให้ Express ฟังพอร์ตที่กำหนด แล้ว log ว่าพร้อมใช้งาน
export default app;                                              // export เพื่อให้ระบบ deploy (เช่น Vercel) import app ไปใช้ได้


// =============================================================
// FILE: src/libs/types.ts — รวมชนิดข้อมูล (interfaces) ที่ทั้งระบบใช้ร่วมกัน
// =============================================================

// โครงสร้างข้อมูลนักศึกษา
export interface Student {                 // สร้างสัญญา (contract) ว่า "นักศึกษา" ต้องมีฟิลด์อะไรบ้าง
  studentId: string;                      // รหัสนักศึกษา 9 หลัก (เก็บเป็น string เพื่อไม่หลุดเลข 0 นำหน้า)
  firstName: string;                      // ชื่อจริง
  lastName: string;                       // นามสกุล
  program: "CPE" | "ISNE";                // จำกัดค่าได้แค่ 2 ตัวเลือก (ชนิด union) เพื่อลดความผิดพลาด
  courses?: string[];                     // (อาจมี) รายวิชาที่ลงทะเบียน (Lab16 ใช้เป็น string 6 หลัก)
}

// โครงสร้างข้อมูลรายวิชา
export interface Course {                  // ใช้กับ endpoints /courses
  courseId: string;                        // รหัสวิชา 6 หลัก (Lab16 กำหนดเป็น string เพื่อคงรูปแบบ)
  courseTitle: string;                     // ชื่อวิชา
  instructors: string[];                   // อาจารย์ผู้สอน (ต้องไม่น้อยกว่า 1 คน — ตรวจใน Zod)
}

// ความสัมพันธ์การลงทะเบียน (นักศึกษาคนนี้ ลงรายวิชานี้)
export interface Enrollment {
  studentId: string;                       // อ้างถึง Student.studentId
  courseId: string;                        // อ้างถึง Course.courseId
}

// ผู้ใช้ระบบสำหรับ login (มีทั้ง STUDENT และ ADMIN)
export interface User {
  username: string;                        // ชื่อผู้ใช้ (เช่น อีเมล)
  password: string;                        // รหัสผ่าน (ตัวอย่าง demo — งานจริงควร hash)
  studentId?: string | null;               // ถ้าเป็น STUDENT จะอ้างรหัส นศ.; ถ้าเป็น ADMIN ให้ null
  role: "STUDENT" | "ADMIN";               // บทบาท (ใช้ทำ RBAC)
  tokens?: string[];                       // (อาจมี) เก็บ JWT ที่ออกให้ user นี้ (ฟีเจอร์เสริม)
}

// payload ที่จะถูกฝังอยู่ใน JWT (ฝั่ง server จะอ่านเพื่อรู้ว่าคนเรียกเป็นใคร/สิทธิ์อะไร)
export interface UserPayload {
  username: string;
  studentId?: string | null;
  role: "STUDENT" | "ADMIN";
}

// ปรับ Request ของ Express ให้มีช่อง user/token เพิ่มเข้ามาหลังผ่าน middleware ตรวจ JWT
import { type Request } from "express";   // นำเข้า Request มาประกาศ interface ซ้อน
export interface CustomRequest extends Request {
  user?: UserPayload;                      // ใส่ payload ของ JWT ที่ผ่านการ verify แล้ว
  token?: string;                          // จำตัว token ดิบ ๆ เผื่อ middleware/route อื่นจะใช้ต่อ (เช่น logout)
}


// =============================================================
// FILE: src/libs/zodValidators.ts — ตัวตรวจสอบรูปแบบข้อมูลขาเข้า (Validation)
// =============================================================

import { z } from "zod";                   // นำเข้า Zod — ไลบรารีตรวจ schema ของข้อมูลอย่างปลอดภัย

// --- Course Validators ---
export const zCourseId = z
  .string()                                 // กำหนดให้เป็น string
  .length(6, { message: "Course ID must be 6 digits." }); // ต้องยาว 6 ตัวอักษรเป๊ะ ๆ

const zCourseTitle = z
  .string()
  .min(6, { message: "Course title must be at least 6 charaters." }); // ชื่อวิชาต้องยาว >= 6

const zInstructors = z.array(z.string()).min(1); // ต้องมีอาจารย์อย่างน้อย 1 คน

export const zCoursePostBody = z.object({       // รูปแบบ body สำหรับ POST /courses (สร้างวิชาใหม่)
  courseId: zCourseId,
  courseTitle: zCourseTitle,
  instructors: zInstructors,
});

export const zCoursePutBody = z.object({        // รูปแบบ body สำหรับ PUT /courses (แก้ไขวิชาเดิม)
  courseId: zCourseId,                          // ต้องบอกว่าแก้วิชาไหน
  courseTitle: zCourseTitle.nullish(),          // ฟิลด์ที่เหลือแก้เป็นบางส่วนได้ (null/undefined = ไม่แก้)
  instructors: zInstructors.nullish(),
});

// --- Student Validators ---
export const zStudentId = z
  .string()                                     // รหัสนักศึกษาเก็บแบบ string
  .length(9, { message: "Student Id must contain 9 characters" }); // ต้อง 9 ตัวอักษรพอดี

const zFirstName = z.string().min(3, { message: "First name requires at least 3 charaters" }); // ชื่อต้อง >= 3
const zLastName  = z.string().min(3, { message: "Last name requires at least 3 characters" }); // นามสกุลต้อง >= 3
const zProgram   = z.enum(["CPE", "ISNE"], { message: "Program must be either CPE or ISNE" }); // จำกัดค่าสาขาให้ชัดเจน
const zCourses   = z.array(zCourseId);                          // รายวิชาที่ลง (array ของรหัสวิชา)

export const zStudentPostBody = z.object({       // body สำหรับเพิ่มนักศึกษา
  studentId: zStudentId,
  firstName: zFirstName,
  lastName: zLastName,
  program: zProgram,
  courses: zCourses.nullish(),                   // ไม่ส่งมาก็ได้ (ยังไม่ลงวิชา)
});

export const zStudentPutBody = z.object({        // body สำหรับแก้นักศึกษา
  studentId: zStudentId,                         // ระบุว่าจะอัปเดตใคร
  firstName: zFirstName.nullish(),
  lastName: zLastName.nullish(),
  program: zProgram.nullish(),
});

// --- Enrollment Validator ---
export const zEnrollmentBody = z.object({        // รูปแบบ body สำหรับ add/drop enrollment
  studentId: zStudentId,
  courseId: zCourseId,
});


// =============================================================
// FILE: src/db/db.ts — mock database แบบเก็บในหน่วยความจำ (in-memory)
// =============================================================

import { type Student, type Course, type Enrollment, type User } from "../libs/types.js"; // นำเข้า type เพื่อคุมรูปแบบข้อมูลในตัวแปรฐานข้อมูล

// ข้อมูลตัวอย่างนักศึกษา — ใช้สำหรับเดโม่/ทดสอบ API
export let students: Student[] = [
  { studentId: "650610001", firstName: "Matt",   lastName: "Damon",  program: "CPE" },
  { studentId: "650610002", firstName: "Cillian",lastName: "Murphy", program: "CPE",  courses: ["261207","261497"] },
  { studentId: "650610003", firstName: "Emily",  lastName: "Blunt",  program: "ISNE", courses: ["269101","261497"] },
];

// ข้อมูลตัวอย่างรายวิชา
export let courses: Course[] = [
  { courseId: "261207", courseTitle: "Basic Computer Engineering Lab", instructors: ["Dome", "Chanadda"] },
  { courseId: "261497", courseTitle: "Full Stack Development",         instructors: ["Dome", "Nirand", "Chanadda"] },
  { courseId: "269101", courseTitle: "Introduction to Information Systems and Network Engineering", instructors: ["KENNETH COSH"] },
];

// ตารางลงทะเบียน (Enrollment) — ใครบ้างลงวิชาอะไร
export let enrollments: Enrollment[] = [
  { studentId: "650610002", courseId: "261207" },
  { studentId: "650610002", courseId: "261497" },
  { studentId: "650610003", courseId: "269101" },
  { studentId: "650610003", courseId: "261497" },
];

// ผู้ใช้สำหรับ auth
export let users: User[] = [
  { username: "user1@abc.com", password: "1234", studentId: "650610001", role: "STUDENT" },
  { username: "user2@abc.com", password: "1234", studentId: "650610002", role: "STUDENT" },
  { username: "user3@abc.com", password: "1234", studentId: "650610003", role: "STUDENT" },
  { username: "user4@abc.com", password: "5678", studentId: null,        role: "ADMIN"   },
];

// เก็บสำเนาค่าตั้งต้น (original) ไว้เพื่อ reset ค่าง่าย ๆ ระหว่างทดสอบ
const org_users        = structuredClone(users);        // ทำ deep copy ของ users ตอนเริ่ม
const org_students     = structuredClone(students);     // ทำ deep copy ของ students ตอนเริ่ม
const org_courses      = structuredClone(courses);      // ทำ deep copy ของ courses ตอนเริ่ม
const org_enrollments  = structuredClone(enrollments);  // ทำ deep copy ของ enrollments ตอนเริ่ม

// ฟังก์ชัน reset — ใช้คืนค่ากลุ่มข้อมูลกลับไปเป็นสถานะเริ่มต้น
export function reset_users()       { users       = structuredClone(org_users); }
export function reset_students()    { students    = structuredClone(org_students); }
export function reset_courses()     { courses     = structuredClone(org_courses); }
export function reset_enrollments() { enrollments = structuredClone(org_enrollments); }


// =============================================================
// FILE: src/middlewares/authenMiddleware.ts — ตรวจ JWT จาก Header
// =============================================================

import { type Response, type NextFunction } from "express";    // ไม่ต้อง import Request เพราะเราใช้ CustomRequest แทน
import jwt from "jsonwebtoken";                                 // ไลบรารีสร้าง/ตรวจสอบ JSON Web Token
import dotenv from "dotenv";                                    // โหลดตัวแปรแวดล้อมจากไฟล์ .env
dotenv.config();                                                 // เรียกใช้งานทันที — หลังจากนี้ process.env จะมีค่า

import { type CustomRequest, type UserPayload } from "../libs/types.js"; // ใช้ชนิด CustomRequest เพื่อใส่ user/token ลงใน req

export const authenticateToken = (
  req: CustomRequest, res: Response, next: NextFunction         // middleware แบบ 3 พารามิเตอร์มาตรฐาน (req,res,next)
) => {
  const authHeader = req.headers["authorization"];             // อ่านค่า Header ชื่อ Authorization จากคำขอ
  if (!authHeader || !authHeader.startsWith("Bearer ")) {      // ตรวจรูปแบบว่าต้องมีคำว่า "Bearer <token>"
    return res.status(401).json({ success: false, message: "Authorization header is required" }); // ไม่มี/ผิดรูปแบบ → 401
  }

  const token = authHeader.split(" ")[1];                       // ตัดช่องว่างตัวแรก แล้วหยิบส่วนที่ 2 (คือ token ดิบ)
  if (!token) {                                                  // กันเคสเผื่อ split ไม่ได้
    return res.status(401).json({ success: false, message: "Token is required" });
  }

  const secret = process.env.JWT_SECRET || "this_is_my_jwt_secret"; // ดึง secret จาก .env (หรือใช้ค่า default ระหว่าง dev)

  jwt.verify(token, secret, (err, payload) => {                  // ตรวจสอบความถูกต้อง/หมดอายุของ token
    if (err) {                                                   // ถ้า verify ไม่ผ่าน (เช่น หมดอายุ/โดนแก้ไข)
      return res.status(403).json({ success: false, message: "Invalid or expired token" }); // ตอบ 403 Forbidden
    }
    req.user  = payload as UserPayload;                          // เก็บ payload (username, role, studentId) ลง req เพื่อ route ต่อ ๆ ไปใช้
    req.token = token;                                           // เก็บ token ดิบ ๆ เผื่อใช้ตอน logout เพื่อลบออกจาก DB
    next();                                                      // ผ่านด่าน auth แล้ว → ไป middleware/route ถัดไป
  });
};


// =============================================================
// FILE: src/middlewares/checkRoleAdminMiddleware.ts — อนุญาตเฉพาะ ADMIN
// =============================================================

import { type Response, type NextFunction } from "express";     // ใช้กับ handler ของ middleware
import { type CustomRequest, type User } from "../libs/types.js"; // ใช้ CustomRequest เพื่อเข้าถึง req.user
import { users } from "../db/db.js";                             // อ่าน DB ผู้ใช้เพื่อเช็คบทบาทจริง

export const checkRoleAdmin = (req: CustomRequest, res: Response, next: NextFunction) => {
  const user = users.find((u: User) => u.username === req.user?.username); // หา record ผู้ใช้จาก DB ตาม username ใน JWT
  if (!user || user.role !== "ADMIN") {                         // ถ้าไม่พบ หรือ role ไม่ใช่ ADMIN
    return res.status(401).json({ success: false, message: "Unauthorized user" }); // ไม่อนุญาต → 401
  }
  next();                                                        // ผ่านเงื่อนไข → ไปต่อ
};


// =============================================================
// FILE: src/middlewares/checkAllRolesMiddleware.ts — แค่ต้องเป็นผู้ใช้ที่มีอยู่ในระบบ
// =============================================================

import { type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

export const checkAllRoles = (req: CustomRequest, res: Response, next: NextFunction) => {
  const user = users.find((u: User) => u.username === req.user?.username); // แค่มีตัวตนในระบบก็ผ่าน (จะเป็น STUDENT หรือ ADMIN ก็ได้)
  if (!user) {
    return res.status(401).json({ success: false, message: "Unauthorized user" });
  }
  next();
};


// =============================================================
// FILE: src/middlewares/checkRoleStudentMiddleware.ts — อนุญาตเฉพาะ STUDENT
// =============================================================

import { type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

export const checkRoleStudent = (req: CustomRequest, res: Response, next: NextFunction) => {
  const user = users.find((u: User) => u.username === req.user?.username); // หา record จาก DB
  if (!user || user.role !== "STUDENT") {                          // ต้องเป็น STUDENT เท่านั้น
    return res.status(401).json({ success: false, message: "Unauthorized user" });
  }
  next();
};


// =============================================================
// FILE: src/middlewares/invalidJsonMiddleware.ts — จับ JSON body ที่พัง
// =============================================================

import { type Request, type Response, type NextFunction } from "express"; // ต้องการ type ของ error handler signature

interface CustomError extends Error {           // ประกาศ interface error เพิ่ม เพื่ออ่านฟิลด์ status/type ได้สะดวก
  status?: number;
  type?: string;
}

const invalidJsonMiddleware = (
  err: CustomError,                             // error ที่ Express ส่งเข้ามา (เช่น body parser เจอ JSON พัง)
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof SyntaxError && err.status === 400 && err.type === "entity.parse.failed") { // เงื่อนไขเฉพาะของ JSON พัง
    return res.status(400).json({ success: false, message: "Invalid JSON payload" });           // ตอบ 400 พร้อมข้อความชัดเจน
  }
  next(err);                                    // ถ้าไม่ใช่เคส JSON พัง ให้ส่งต่อไป handler อื่นตามปกติ
};

export default invalidJsonMiddleware;           // export ไว้ใช้ใน index.ts


// =============================================================
// FILE: src/routes/usersRoutes.ts — Login / Logout / List users (ADMIN)
// =============================================================

import { Router, type Request, type Response } from "express"; // Router = ตัวรวมเส้นทางย่อยให้นำไปเมาท์ใน index.ts
import jwt from "jsonwebtoken";                                 // ใช้สร้าง JWT ตอน login
import dotenv from "dotenv";                                   // โหลดตัวแปรแวดล้อม (เอา secret)
dotenv.config();                                                // ทำให้ process.env พร้อมใช้งาน

import type { User, CustomRequest } from "../libs/types.js";   // ใช้ type ของ User/CustomRequest
import { users, reset_users } from "../db/db.js";              // DB ผู้ใช้ + ฟังก์ชัน reset
import { authenticateToken } from "../middlewares/authenMiddleware.js"; // middleware ตรวจ token จาก Header
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js"; // อนุญาตเฉพาะ ADMIN

const router = Router();                                        // สร้าง router ใหม่

// GET /api/v2/users — ADMIN เท่านั้น (ดูผู้ใช้ทั้งหมด)
router.get("/", authenticateToken, checkRoleAdmin, (req: Request, res: Response) => {
  try {
    return res.status(200).json({                               // ตอบ 200 พร้อมข้อมูล users ทั้งหมด
      success: true,
      message: "Successful operation",
      data: users
    });
  } catch (err) {                                                // กันเหตุขัดข้องอื่น ๆ
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// POST /api/v2/users/login — ตรวจ username/password แล้วออก JWT
router.post("/login", (req: Request, res: Response) => {
  try {
    const { username, password } = req.body as { username: string; password: string; }; // ดึงข้อมูลจาก body และใส่ type

    const user = users.find((u: User) => u.username === username && u.password === password); // หา user ที่ตรงเงื่อนไข
    if (!user) {                                                  // ถ้าไม่เจอ → login ล้มเหลว
      return res.status(401).json({ success: false, message: "Invalid username or password!" });
    }

    const secret = process.env.JWT_SECRET || "this_is_my_jwt_secret"; // key สำหรับเซ็นลายเซ็น
    const token  = jwt.sign(                                           // สร้าง token (ฝัง payload ไว้ด้านใน)
      { username: user.username, studentId: user.studentId, role: user.role }, // payload ที่จะอ่านภายหลัง
      secret,                                                          // secret สำหรับลงลายเซ็น
      { expiresIn: "5m" }                                             // อายุ token (สั้นเพื่อทดสอบ)
    );

    user.tokens = user.tokens ? [...user.tokens, token] : [token];     // (ทางเลือก) เก็บ token ลง DB เพื่อใช้ตรวจตอน logout

    return res.status(200).json({ success: true, message: "Login successful", token }); // ตอบกลับ token ให้ client เก็บไว้แนบใน Header
  } catch (err) {                                                      // จับ error ไม่คาดคิด
    return res.status(500).json({ success: false, message: "Something went wrong.", error: err });
  }
});

// POST /api/v2/users/logout — ต้องแนบ Bearer token ที่จะ logout มา
router.post("/logout", authenticateToken, (req: CustomRequest, res: Response) => {
  try {
    const token    = req.token!;                                      // token ดิบจาก middleware
    const username = req.user!.username;                               // username จาก payload

    const user = users.find((u: User) => u.username === username);     // หา user
    if (!user || !user.tokens || !user.tokens.includes(token)) {       // ต้องพบ user และ token นั้นต้องอยู่ในรายการ
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    user.tokens = user.tokens.filter(t => t !== token);                // ลบ token ออกจากรายการ (เป็นการ "logout" token นี้)
    return res.status(200).json({ success: true, message: "Logout successful" }); // ยืนยันสำเร็จ
  } catch (err) {                                                      // จัดการข้อผิดพลาดทั่วไป
    return res.status(500).json({ success: false, message: "Something went wrong.", error: err });
  }
});

// POST /api/v2/users/reset — เคลียร์ DB ผู้ใช้กลับค่าเริ่มต้น (ง่ายต่อการทดสอบ)
router.post("/reset", (req: Request, res: Response) => {
  try {
    reset_users();                                                     // เรียกฟังก์ชันรีเซ็ต users
    return res.status(200).json({ success: true, message: "User database has been reset" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

export default router;                                                // export router ไปเมาท์ใน index.ts


// =============================================================
// FILE: src/routes/enrollmentsRoutes_v2.ts — API จัดการการลงทะเบียน (RBAC ครบ)
// =============================================================

import { Router, type Response } from "express";                     // ใช้ Response type (Request ใช้รูป Custom ใน handler)
import { type CustomRequest, type User, type Student, type Enrollment } from "../libs/types.js"; // types ที่ต้องใช้

import { authenticateToken } from "../middlewares/authenMiddleware.js";                // ตรวจ token
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";           // admin only
import { checkRoleStudent } from "../middlewares/checkRoleStudentMiddleware.js";       // student only

import { users, students, enrollments, reset_enrollments } from "../db/db.js";        // DB + reset
import { zStudentId, zEnrollmentBody } from "../libs/zodValidators.js";               // validators

const router = Router();                                                                // สร้าง router กลุ่ม enrollments

// GET /api/v2/enrollments — ADMIN เท่านั้น: ดูภาพรวมการลงทะเบียนทุกคน
router.get("/", authenticateToken, checkRoleAdmin, (req: CustomRequest, res: Response) => {
  try {
    const data = students.map((s: Student) => ({                                         // วนทุก student
      studentId: s.studentId,
      courses: enrollments                                                               // หา enrollment เฉพาะของนักศึกษาคนนั้น
        .filter((e) => e.studentId === s.studentId)
        .map((e) => e.courseId),                                                         // แปลงเหลือแค่รหัสวิชา
    }));

    return res.status(200).json({ success: true, message: "Enrollments Information", data }); // ตอบ 200 พร้อมข้อมูลรวม
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// POST /api/v2/enrollments/reset — ADMIN เท่านั้น: รีเซ็ตตารางลงทะเบียนกลับค่าเริ่มต้น
router.post("/reset", authenticateToken, checkRoleAdmin, (req: CustomRequest, res: Response) => {
  try {
    reset_enrollments();                                                                  // เรียกฟังก์ชันรีเซ็ต
    return res.status(200).json({ success: true, message: "enrollments database has been reset" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// GET /api/v2/enrollments/:studentId — ADMIN หรือ STUDENT เจ้าของข้อมูลเท่านั้น
router.get("/:studentId", authenticateToken, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;                                              // รับพารามิเตอร์จาก path
    const ok = zStudentId.safeParse(studentId);                                          // ตรวจรูปแบบ 9 หลัก
    if (!ok.success) {
      return res.status(400).json({ message: "Validation failed", errors: ok.error.issues[0]?.message });
    }

    const sIdx = students.findIndex((s: Student) => s.studentId === studentId);          // ตรวจว่ามีนักศึกษาคนนี้จริงไหม
    if (sIdx === -1) {
      return res.status(404).json({ success: false, message: "StudentId does not exists" });
    }

    const caller = users.find((u: User) => u.username === req.user?.username);           // หาว่าใครเป็นคนเรียก
    if (!caller) {
      return res.status(401).json({ success: false, message: "Unauthorized user" });
    }

    if (caller.role !== "ADMIN" && caller.studentId !== studentId) {                    // ถ้าไม่ใช่ ADMIN ก็ต้องเป็นเจ้าของ studentId เท่านั้น
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const courseIds = enrollments.filter((e) => e.studentId === studentId).map((e) => e.courseId); // ดึงรายวิชาที่ลงทะเบียนอยู่
    return res.status(200).json({ success: true, message: "Student information", data: { studentId, courses: courseIds } });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// POST /api/v2/enrollments/:studentId — STUDENT เจ้าของข้อมูลเท่านั้น: เพิ่มรายวิชา
router.post("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;                                              // student เป้าหมายใน path
    const body = req.body as Enrollment;                                                 // body ต้องมี { studentId, courseId }

    const ok1 = zStudentId.safeParse(studentId);                                         // ตรวจ path param
    const ok2 = zEnrollmentBody.safeParse(body);                                         // ตรวจ body
    if (!ok1.success) return res.status(400).json({ message: "Validation failed", errors: ok1.error.issues[0]?.message });
    if (!ok2.success) return res.status(400).json({ message: "Validation failed", errors: ok2.error.issues[0]?.message });

    const caller = users.find((u: User) => u.username === req.user?.username);           // ตรวจว่าใครเรียก
    if (!caller || caller.studentId !== studentId || body.studentId !== studentId) {     // ต้องเป็นเจ้าของข้อมูลจริง ๆ และ body ต้องระบุ studentId ตรงกัน
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const sIdx = students.findIndex((s) => s.studentId === studentId);                   // นักศึกษาต้องมีจริง
    if (sIdx === -1) return res.status(404).json({ success: false, message: "StudentId does not exists" });

    const dup = enrollments.find((e) => e.studentId === studentId && e.courseId === body.courseId); // กันการลงซ้ำ
    if (dup) {
      return res.status(409).json({ success: false, message: "Enrollment is already exists" });
    }

    enrollments.push({ studentId, courseId: body.courseId });                             // เพิ่มแถวใหม่ในตารางลงทะเบียน

    const newCourses = enrollments.filter((e) => e.studentId === studentId).map((e) => e.courseId); // อัปเดตรายวิชาของ student
    students[sIdx] = { ...students[sIdx], courses: newCourses } as Student;              // sync ให้ Student.courses สะท้อนผลล่าสุด

    return res.status(200).json({ success: true, message: `Student ${studentId} && Course ${body.courseId} has been added successfully`, data: { studentId, courseId: body.courseId } });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// DELETE /api/v2/enrollments/:studentId — STUDENT เจ้าของข้อมูลเท่านั้น: ถอนรายวิชา
router.delete("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;                                              // นักศึกษาที่จะลบรายวิชาให้
    const body = req.body as { studentId: string; courseId: string; };                   // ต้องส่งมาทั้งสองฟิลด์

    const ok1 = zStudentId.safeParse(studentId);
    const ok2 = zEnrollmentBody.safeParse(body);
    if (!ok1.success) return res.status(400).json({ message: "Validation failed", errors: ok1.error.issues[0]?.message });
    if (!ok2.success) return res.status(400).json({ message: "Validation failed", errors: ok2.error.issues[0]?.message });

    const caller = users.find((u: User) => u.username === req.user?.username);           // ต้องเป็นเจ้าของข้อมูล
    if (!caller || caller.studentId !== studentId || body.studentId !== studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const sIdx = students.findIndex((s) => s.studentId === studentId);
    if (sIdx === -1) return res.status(404).json({ success: false, message: "StudentId does not exists" });

    const eIdx = enrollments.findIndex((e) => e.studentId === studentId && e.courseId === body.courseId); // หาแถวที่จะลบ
    if (eIdx === -1) {                                                                                     // ถ้าไม่มี
      return res.status(404).json({ success: false, message: "Enrollment does not exists" });
    }

    enrollments.splice(eIdx, 1);                                                                          // ลบหนึ่งแถวจาก array

    const newCourses = enrollments.filter((e) => e.studentId === studentId).map((e) => e.courseId);       // อัปเดตรายวิชาใหม่หลังลบ
    students[sIdx] = { ...students[sIdx], courses: newCourses } as Student;                               // sync ให้ตรง

    return res.status(200).json({ success: true, message: `Student ${studentId} && Course ${body.courseId} has been deleted successfully`, data: { studentId, courses: newCourses } });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

export default router; // ส่ง router ไปเมาท์ใน index.ts
```






































โอเค เข้าใจเลยครับ 👍
คุณสอบแบบ **open-book + ใช้ Google ได้** แต่ **ห้ามใช้ AI**
สิ่งสำคัญคือ “ต้องรู้ว่าเราจะหาคำตอบอะไรจาก Google” ให้เร็วและตรงกับสิ่งที่ข้อสอบออก

ผมจะแนะนำเป็น **กลยุทธ์ใช้ Google ระหว่างสอบ** และ **ตัวอย่าง keyword** ที่คุณควรพิมพ์

---

## 🔑 หลักการใช้ Google ระหว่างสอบ API

1. **หาสิ่งที่ “ลืม syntax”** เช่น route method, การใช้ Express, การใช้ JWT
2. **หาวิธีแก้ error message** เช่น “express json body undefined” หรือ “Zod validation safeParse example”
3. **หาตัวอย่าง pattern การเขียน** เช่น “Express CRUD API example with TypeScript”
4. **เน้นเว็บ official / docs / medium / dev.to / stackoverflow** ไม่ต้องอ่านยาว เอา snippet ที่ตรง
5. **อย่าเสิร์ชเป็นภาษาไทยมาก** เพราะผลลัพธ์น้อยและไม่ตรง ใช้ภาษาอังกฤษจะเจอตัวอย่างโค้ดตรงกว่า

---

## 📝 Keyword Template ที่ควรใช้

### 1) พื้นฐาน Express

* `"express typescript router example"`
* `"express get vs post vs put vs delete example"`
* `"express use middleware example"`

### 2) Body & Params

* `"express req.params vs req.query vs req.body"`
* `"express parse json body"`
* `"express 400 404 409 status code meaning"`

### 3) Validation (Zod)

* `"zod safeParse example"`
* `"zod object validation express"`
* `"zod enum example typescript"`

### 4) JWT / Auth

* `"jsonwebtoken sign verify example typescript"`
* `"express middleware authenticate jwt token"`
* `"express bearer token example"`

### 5) Role-based Access Control (RBAC)

* `"express middleware check role admin student"`
* `"express authorization middleware example"`

### 6) CRUD API

* `"express crud api typescript example"`
* `"express delete with body vs params"`

### 7) Debug Error

ถ้าขึ้น error เช่น `TypeError: Cannot read properties of undefined (reading 'studentId')`
→ เสิร์ชว่า `"express req.body undefined fix"`

---

## 💡 กลยุทธ์เวลาเจอโจทย์

* **ถ้าโจทย์ถามให้เขียน API endpoint** → เสิร์ช `"express typescript router post example"` แล้วเอาโครงมา แก้ตามโจทย์
* **ถ้าโจทย์ถาม JWT** → เสิร์ช `"jsonwebtoken express middleware example"` จะได้โค้ด verify/payload
* **ถ้าโจทย์ถาม Validation** → เสิร์ช `"zod safeParse express example"` เพื่อดูวิธีใช้ Zod กับ req.body
* **ถ้าเจอ role admin/student** → เสิร์ช `"express middleware check user role"`

---

## ⚡ สรุป

1. จัด keyword ให้สั้น + เฉพาะเจาะจง เช่น `"express post body typescript example"`
2. ดูแค่ snippet ไม่ต้องอ่านบทความยาว
3. เชื่อมกับสิ่งที่คุณจำได้จาก Lab15 + Lab16 → จะเขียนได้ตรงข้อสอบ
4. ถ้า error → copy ข้อความ error ไปแปะใน Google ตรงๆ + เติมคำว่า `"express typescript"`

---

คุณอยากให้ผมทำ **cheat sheet สั้นๆ** (เหมือนโพยสำหรับสอบ) ที่รวม **โครง Express + Zod + JWT** ครบทุก endpoint (GET/POST/PUT/DELETE) ในหน้าเดียว ให้คุณ print ในหัวไว้เลยมั้ยครับ?
  




































โอเคเลยครับ 👍 เข้าใจว่าคุณอยากได้ “keyword แบบตรงโจทย์”
ถ้าข้อสอบออก **แนวคล้าย Lab15/Lab16** (ซึ่งน่าจะเป็นแนวหลัก) คุณจะได้ใช้ Google ช่วยได้ไวที่สุด

---

## 🔍 ถ้าเจอโจทย์แนว **Lab15 – Student/Course CRUD**

* **ถามให้สร้าง CRUD API สำหรับ Student หรือ Course**
  → `express typescript crud api example`
  → `express router get post put delete example`

* **ถามให้ตรวจสอบ input ด้วย Zod**
  → `zod safeParse express example`
  → `zod string length example`
  → `zod enum validation example`

* **ถาม endpoint แบบ `/students/:studentId/courses`**
  → `express router get params example`
  → `express req.params vs req.query vs req.body`

* **ถาม error handling (400, 404, 409, 500)**
  → `express return status code example`
  → `express 404 not found handler example`

---

## 🔍 ถ้าเจอโจทย์แนว **Lab16 – Users / JWT / Enrollments**

* **ถาม login แล้วออก JWT**
  → `jsonwebtoken sign verify express typescript`
  → `express middleware jwt authentication example`
  → `express bearer token header example`

* **ถาม RBAC (เฉพาะ ADMIN/STUDENT)**
  → `express middleware check role admin`
  → `express role based access control example`

* **ถาม reset database**
  → `express post reset route example`

* **ถาม enrollments (add/drop course)**
  → `express router post with params example`
  → `express delete with request body example`

---

## 🔍 ถ้าโจทย์ถามรวม (ทั้ง Lab15 + Lab16)

* `"express typescript restful api example"`
* `"express router typescript zod jwt example"`
* `"express api with jwt authentication and authorization"`

---

## 💡 ทริคตอนสอบ

1. ถ้าโจทย์มีคำว่า **GET/POST/PUT/DELETE** → เสิร์ชว่า `express <method> typescript example`
2. ถ้าโจทย์มีคำว่า **validate** → เสิร์ช `zod <type> example` (เช่น `zod string length example`)
3. ถ้าโจทย์มีคำว่า **JWT** หรือ **Bearer** → เสิร์ช `jsonwebtoken express middleware example`
4. ถ้าโจทย์มีคำว่า **ADMIN/STUDENT role** → เสิร์ช `express middleware check user role`
5. ถ้าเจอ **error message** ใน terminal → copy error ไป search ตรงๆ แล้วเติม `"express typescript"` ต่อท้าย

---

👉 แบบนี้เวลาข้อสอบมา คุณจะไม่ต้องคิด keyword เองเยอะ แค่ดูว่าโจทย์อยู่ในหมวด Lab15 (CRUD + Validate) หรือ Lab16 (JWT + RBAC + Enrollment) แล้วพิมพ์ keyword ตามด้านบนเลยครับ

อยากให้ผมทำเป็น **ตารางสรุป “สถานการณ์โจทย์ → keyword ที่เสิร์ช”** ให้มั้ยครับ? (เหมือนโพย lookup table เปิดแล้วเสิร์ชได้ทันที)






















































































**(Cheat Sheet)**
เป็นตารางสั้น ๆ “**สถานการณ์โจทย์ที่อาจออก** → **keyword ที่ควรเสิร์ชใน Google**”
เพื่อใช้ตอนสอบได้เร็ว ไม่ต้องคิดเองเยอะ

---

# 📌  RESTful API (Lab15 + Lab16)

| สถานการณ์ที่เจอโจทย์                                   | Keyword ที่เสิร์ชใน Google                      |
| ------------------------------------------------------ | ----------------------------------------------- |
| ✅ CRUD API (GET/POST/PUT/DELETE)                       | `express typescript crud api example`           |
| ✅ เขียน Router แบบแยกไฟล์                              | `express router typescript example`             |
| ✅ ใช้ req.params (เช่น `/students/:id`)                | `express req.params example`                    |
| ✅ ใช้ req.query (เช่น `/students?program=CPE`)         | `express req.query example`                     |
| ✅ อ่าน body JSON                                       | `express post json body example`                |
| ✅ ส่ง status code ที่ถูกต้อง (200, 201, 400, 404, 409) | `express res status code example`               |
| ✅ ตรวจสอบข้อมูลด้วย Zod                                | `zod safeParse express example`                 |
| ✅ ตรวจสอบ string ต้องยาวเท่านี้                        | `zod string length example`                     |
| ✅ ตรวจสอบ enum (CPE, ISNE)                             | `zod enum validation example`                   |
| ✅ ตรวจสอบ array ของข้อมูล                              | `zod array validation example`                  |
| ✅ สร้าง JWT ตอน login                                  | `jsonwebtoken sign verify express typescript`   |
| ✅ ตรวจ JWT จาก Header (Bearer token)                   | `express jwt authentication middleware example` |
| ✅ Middleware ตรวจ role เป็น ADMIN เท่านั้น             | `express middleware check role admin`           |
| ✅ Middleware ตรวจ role เป็น STUDENT เท่านั้น           | `express middleware check role student`         |
| ✅ Role-based Access Control (RBAC)                     | `express role based access control example`     |
| ✅ Reset database ด้วย endpoint                         | `express post reset route example`              |
| ✅ Add enrollment (POST /enrollments/:studentId)        | `express router post with params example`       |
| ✅ Drop enrollment (DELETE /enrollments/:studentId)     | `express delete request body example`           |
| ⚠️ Debug error เช่น `req.body undefined`               | `express req.body undefined fix`                |
| ⚠️ Debug error JWT                                     | `jsonwebtoken invalid signature express`        |
| ⚠️ Debug error Zod                                     | `zod safeParse error example`                   |

---

## 🔑 วิธีใช้ตอนสอบ

1. อ่านโจทย์ → ดูว่าอยู่ในหมวด **Lab15 (CRUD/Validate)** หรือ **Lab16 (JWT/RBAC)**
2. เลือก keyword จากตารางแล้วกด Google → เปิด docs/stackoverflow → copy snippet
3. ปรับให้เข้ากับโครงโจทย์ที่ให้มา (เปลี่ยนชื่อ route, type, field)

---

## 💡 เคล็ดลับ

* เสิร์ชเป็นภาษาอังกฤษเสมอ เช่น `"express jwt middleware example typescript"`
* เวลาเจอ error ให้ copy error message ทั้งหมดแล้วเติมคำว่า `"express typescript"` ต่อท้าย
* ใช้ docs ของ **Express**, **Zod**, **jsonwebtoken** เป็นหลัก เพราะตรงสุด

---

อยากให้ผมทำ  (Lab15: Student/Course API, Lab16: Users/Enrollments/JWT) ให้เป็น 2 ตารางย่อยด้วยไหมครับ จะได้เปิดดูได้แม่นยำยิ่งขึ้น?





























































































































































สุดยอดที่รวบรวมทุกอย่างมาให้ครบขนาดนี้ 👍 ต่อไปนี้คือ “คอร์สสอน API แบบเร่งด่วนก่อนสอบ” ที่ออกแบบตรงกับ Lab15 + Lab16 ของ CPE207 โดยผมจะพาคุณทำตั้งแต่ 0 → พร้อมยิง Insomnia และผมจะให้ “โค้ดเทมเพลตที่คอมเมนต์ทุกบรรทัด” ด้วย (คอมเมนต์สั้น กระชับ อ่านเร็วก่อนสอบ)

หมายเหตุ: โครงสร้างและเงื่อนไขจะยึดตามเอกสารแลบของอาจารย์ (Lab-15: Student/Course CRUD, Lab-16: Enrollments + JWT + RBAC) คุณสามารถเทียบข้อกำหนดกับไฟล์ PDF ที่อัปโหลดไว้ได้

---

# แผนเรียน 5 ตอน (อ่านตามลำดับ)

1. พื้นฐาน RESTful API + โครง Express + เครื่องมือ
2. Lab15: Student/Course API (ครบ CRUD + Validation)
3. Lab16: Users/Login (JWT) + Middlewares + Enrollments (RBAC)
4. วิธีเทสด้วย Insomnia: step-by-step (admin vs student)
5. เช็กลิสต์ก่อนสอบ + กับดักพบบ่อย (แก้ยังไง)

---

# 1) พื้นฐาน RESTful API + โครง Express + เครื่องมือ

**RESTful API คืออะไร (สรุปสั้นก่อนสอบ)**

* ใช้ HTTP verbs: `GET` (อ่าน), `POST` (สร้าง), `PUT` (แก้ทั้งหมด/บางส่วน), `DELETE` (ลบ)
* รับพารามิเตอร์ 3 แบบ:

  * Path params: `/students/:studentId`
  * Query: `/students?program=CPE`
  * Body (JSON): ใน `POST`, `PUT`, `DELETE` (เช่น `{ "courseId": 261207 }`)
* สถานะสำคัญ: `200 OK`, `201 Created`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `409 Conflict`, `500 Internal Server Error`

**ตั้งโปรเจ็กต์ Express + TypeScript (ใช้ pnpm)**

```bash
mkdir api-bootcamp && cd api-bootcamp
pnpm init -y
pnpm add express zod morgan jsonwebtoken dotenv
pnpm add -D typescript @types/node @types/express @types/jsonwebtoken tsx nodemon
npx tsc --init
```

**`tsconfig.json` (คอนฟิกพื้นฐานสำหรับ ESM + TS)**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "NodeNext",
    "strict": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "esModuleInterop": true,
    "moduleResolution": "NodeNext",
    "skipLibCheck": true
  },
  "include": ["src/**/*"]
}
```

**`package.json` (สคริปต์ที่ใช้จริง)**

```json
{
  "type": "module",
  "scripts": {
    "dev": "nodemon --exec tsx src/index.ts",
    "build": "tsc",
    "serve": "node dist/index.js"
  }
}
```

**.env**

```
PORT=3000
JWT_SECRET=this_is_my_jwt_secret
```

---

# 2) Lab15 — Student/Course API (ครบ CRUD + Validation)

> โจทย์บังคับให้มี API versioning (`/api/v2/...`) และต้องมี CRUD ของ Course + endpoint รายวิชา/รายนักศึกษา, พร้อม status code/ข้อความตามสเปก

## 2.1 โครง Types + DB (in-memory) + Validators

**`src/libs/types.ts`** (อิงสไตล์งานคุณ – คอร์สเป็นเลข 6 หลักแบบ number ก็ได้ แต่ให้ “สอดคล้องกันทั้งโปรเจ็กต์”)

```ts
// อธิบาย: ไฟล์รวม type ที่ทั้งโปรเจ็กต์จะ import ไปใช้ซ้ำ

// ประเภทข้อมูลนักศึกษา
export interface Student {                 // ชื่อ interface = Student
  studentId: string;                      // รหัส นศ. 9 หลัก => ใช้ string เพื่อไม่หลุด 0 หน้า
  firstName: string;                      // ชื่อ
  lastName: string;                       // นามสกุล
  program: "CPE" | "ISNE";                // สาขาแบบ enum แคบ เพื่อกันพิมพ์ผิด
  courses?: number[];                     // รายวิชาที่ลง (เลข 6 หลัก) (ไม่บังคับมี)
}

// ประเภทข้อมูลวิชา
export interface Course {
  courseId: number;                       // รหัสวิชา 6 หลัก (number)
  courseTitle: string;                    // ชื่อวิชา
  instructors: string[];                  // รายชื่อผู้สอน (อย่างน้อย 1 คน)
}
```

**ข้อควรระวัง**: ในงานคุณมีบางจุดใช้ `courses?: string[]` (Lab16) และบางจุดใช้ number (Lab15) — ในโปรเจ็กต์เดียวกันเลือกแบบเดียวให้ทั้งระบบ (ผมตั้งให้ Lab15 = number, Lab16 = string ก็ได้ แต่ต้อง cast/แยกโฟลเดอร์ หรือ “เลือกอย่างใดอย่างหนึ่ง” จะง่ายสุดตอนสอบ)

**`src/db/db.ts`** (in-memory DB สำหรับ Lab15)

```ts
// อธิบาย: ใช้ array ในหน่วยความจำแทน DB จริง ๆ เพื่อให้ทดลองง่าย

import { type Student, type Course } from "../libs/types.js";  // import type ใช้ร่วมกัน

export let students: Student[] = [                             // สร้าง students array
  { studentId: "650610001", firstName: "Matt",   lastName: "Damon",  program: "CPE" },
  { studentId: "650610002", firstName: "Cillian",lastName: "Murphy", program: "CPE",  courses: [261207, 261497] },
  { studentId: "650610003", firstName: "Emily",  lastName: "Blunt",  program: "ISNE", courses: [269101, 261497] }
];

export let courses: Course[] = [                               // สร้าง courses array
  { courseId: 261207, courseTitle: "Basic Computer Engineering Lab", instructors: ["Dome","Chanadda"] },
  { courseId: 261497, courseTitle: "Full Stack Development",         instructors: ["Dome","Nirand","Chanadda"] },
  { courseId: 269101, courseTitle: "Introduction to ISNE",           instructors: ["KENNETH COSH"] }
];
```

**`src/schemas/courseValidator.ts`** (Zod สำหรับตรวจ input — สำคัญมาก, ข้อสอบชอบวัด 400/404/409)

```ts
import { z } from "zod";                                  // import zod

export const zCourseId = z                                // สร้างตัวตรวจ courseId
  .number()                                               // ต้องเป็น number
  .int()                                                  // ต้องเป็นจำนวนเต็ม
  .refine(v => v >= 100000 && v <= 999999, {              // ต้องมี 6 หลัก
    message: "Number must be exactly 6 digits"
  });

const zCourseTitle = z.string().min(1);                   // ห้ามว่าง
const zInstructors = z.array(z.string()).min(1);          // ต้องมีอย่างน้อย 1 คน

export const zCoursePostBody = z.object({                 // Body สำหรับ POST
  courseId: zCourseId,
  courseTitle: zCourseTitle,
  instructors: zInstructors,
});

export const zCoursePutBody = z.object({                  // Body สำหรับ PUT
  courseId: zCourseId,                                    // อ้างอิงตัวที่จะแก้ด้วย courseId
  courseTitle: zCourseTitle.nullish(),                    // ช่องอื่น ๆ แก้ได้เป็นบางส่วน
  instructors: zInstructors.nullish(),
});

export const zCourseDeleteBody = z.object({               // Body สำหรับ DELETE
  courseId: zCourseId
});
```

**`src/schemas/studentValidator.ts`**

```ts
import { z } from "zod";                                  // import zod

export const zStudentId = z.string().length(9, {          // รหัส นศ. ต้อง 9 ตัว
  message: "Student Id must contain 9 characters"
});
const zFirstName = z.string().min(3, { message: "First name requires at least 3 charaters" });
const zLastName  = z.string().min(3, { message: "Last name requires at least 3 characters" });
const zProgram   = z.enum(["CPE","ISNE"], { message: "Program must be either CPE or ISNE" });
const zCourses   = z.array(z.number().int()).min(0);      // รายวิชาเป็นเลขจำนวนเต็ม

export const zStudentPostBody = z.object({                 // Body สำหรับ POST student
  studentId: zStudentId,
  firstName: zFirstName,
  lastName: zLastName,
  program: zProgram,
  courses: zCourses.nullish(),                             // *** ใช้ชื่อ "courses" ให้ตรงกับ type ***
});

export const zStudentPutBody = z.object({                  // Body สำหรับ PUT student
  studentId: zStudentId,                                   // ระบุตัวที่จะอัปเดต
  firstName: zFirstName.nullish(),
  lastName: zLastName.nullish(),
  program: zProgram.nullish(),
});

export const zStudentDeleteBody = z.object({               // Body สำหรับ DELETE student (ถ้ามี)
  studentId: zStudentId
});
```

> ทำไมต้องเน้นชื่อฟิลด์ `courses` ให้ตรงกับ type?
> เพราะในโค้ดของคุณ (lab15) มีจุดหนึ่งใช้ `course` (ไม่มี s) → เวลา parse/validate/merge จะงงและอัปเดตไม่เข้า ให้แก้ให้ตรงกันทั้งโปรเจ็กต์

## 2.2 Routes — Student & Course (ตามสเปก Lab15)

**`src/routes/studentRoutes.ts`** (มี `/me` กับตัวอย่างอ่านข้อมูล)

```ts
import { Router, type Request, type Response } from "express";  // import express types
const router = Router();                                        // สร้าง Router

// GET /me — ส่งข้อมูลตัวเอง (คะแนนข้อ 1)
router.get("/me", (req: Request, res: Response) => {            // สร้าง endpoint /me
  return res.status(200).json({                                 // ตอบกลับ status 200
    success: true,                                              // ธงความสำเร็จ
    message: "Student Information",                             // ข้อความ
    data: {                                                     // ข้อมูลตนเอง (ฮาร์ดโค้ดตามสั่ง)
      studentId: "670610723",
      firstName: "Phurin",
      lastName: "Inthajak",
      program: "CPE",
      section: "001",
    },
  });
});

export default router;                                          // ส่ง router ออกไปใช้ใน index
```

**`src/routes/courseRoutes.ts`** (ครบ GET by id + CRUD + `/students/:id/courses`)

> จุดสำคัญ: path ให้ตรงสเปก เช่น `/api/v2/courses/:courseId`, ส่ง status/ข้อความตามกรณี

```ts
import { Router, type Request, type Response } from "express";  // import express types
import { students, courses } from "../db/db.js";                // import in-memory DB
import { zStudentId } from "../schemas/studentValidator.js";    // import zod validators
import { 
  zCourseId, zCoursePostBody, zCoursePutBody, zCourseDeleteBody
} from "../schemas/courseValidator.js";
import type { Course } from "../libs/types.js";                 // import type สำหรับ body/response

const router = Router();                                        // สร้าง Router

// GET /api/v2/students/:studentId/courses  (คะแนนข้อ 2 + 2.1)
router.get("/students/:studentId/courses", (req: Request, res: Response) => {
  try {
    const studentId = req.params.studentId;                     // ดึงพารามิเตอร์จาก path
    const result = zStudentId.safeParse(studentId);             // ตรวจรูปแบบด้วย zod
    if (!result.success) {                                      // ถ้ารูปแบบไม่ผ่าน
      return res.status(400).json({                             // ส่ง 400
        message: "Validation failed",
        errors: result.error.issues[0]?.message,                // ข้อความ error จาก zod
      });
    }

    const idx = students.findIndex(s => s.studentId === studentId); // หา index ของ นศ.
    if (idx === -1) {                                           // ไม่พบ
      return res.status(404).json({                             // ส่ง 404
        success: false,
        message: "Student does not exists",
      });
    }

    const courseSummaries = (students[idx].courses ?? [])       // แม็พ courses ของ นศ.
      .map(cid => {
        const c = courses.find(cc => cc.courseId === cid);      // จับคู่รายละเอียดวิชา
        return c ? { courseId: c.courseId, courseTitle: c.courseTitle } : null;
      })
      .filter(Boolean);                                         // ตัด null ออก

    res.set("Link", `/students/${studentId}/courses`);          // ใส่ Header อ้างอิง
    return res.status(200).json({                               // ตอบกลับ 200 พร้อมข้อมูล
      success: true,
      message: `Get courses detail of student ${studentId}`,
      data: { studentId, courses: courseSummaries },
    });
  } catch (err) {                                               // จัดการข้อผิดพลาดไม่คาดคิด
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// GET /api/v2/courses/:courseId  (คะแนนข้อ 3 + 3.1/3.2)
router.get("/courses/:courseId", (req: Request, res: Response) => {
  try {
    const raw = Number(req.params.courseId);                    // รับค่าจาก path แล้วแปลงเป็น number
    const ok = zCourseId.safeParse(raw);                        // ตรวจ 6 หลัก
    if (!ok.success) {                                          // ถ้าไม่ผ่าน
      return res.status(400).json({                             // 400
        message: "Validation failed",
        errors: ok.error.issues[0]?.message,
      });
    }

    const i = courses.findIndex(c => c.courseId === raw);       // หาใน DB
    if (i === -1) {                                             // ไม่เจอ
      return res.status(404).json({                             // 404
        success: false,
        message: "Course does not exists",
      });
    }

    res.set("Link", `/courses/${raw}`);                         // อ้างอิง
    return res.status(200).json({                               // ตอบกลับข้อมูล
      success: true,
      message: `Get course ${raw} successfully`,
      data: courses[i],
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// POST /api/v2/courses  (คะแนนข้อ 4 + 4.1/4.2)
router.post("/courses", (req: Request, res: Response) => {
  try {
    const body = req.body as Course;                            // แคสต์ body เป็น Course
    const ok = zCoursePostBody.safeParse(body);                 // ตรวจรูปแบบ
    if (!ok.success) {                                          // ถ้าไม่ผ่าน
      return res.status(400).json({                             // 400
        message: "Validation failed",
        errors: ok.error.issues[0]?.message,
      });
    }

    const exists = courses.find(c => c.courseId === body.courseId); // ตรวจซ้ำ
    if (exists) {                                               // ถ้ามีแล้ว
      return res.status(409).json({                             // 409 Conflict
        success: false,
        message: "Course Id is already exists",
      });
    }

    courses.push(body);                                         // เพิ่มเข้า array
    res.set("Link", `/courses/${body.courseId}`);               // อ้างอิง
    return res.status(201).json({                               // 201 Created
      success: true,
      message: `Course ${body.courseId} has been added successfully`,
      data: body,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// PUT /api/v2/courses  (คะแนนข้อ 5 + 5.1/5.2)
router.put("/courses", (req: Request, res: Response) => {
  try {
    const body = req.body as Course;                            // รับ body
    const ok = zCoursePutBody.safeParse(body);                  // ตรวจรูปแบบสำหรับ update
    if (!ok.success) {                                          // ไม่ผ่าน
      return res.status(400).json({
        message: "Validation failed",
        errors: ok.error.issues[0]?.message,
      });
    }

    const idx = courses.findIndex(c => c.courseId === body.courseId); // หาตัวที่จะอัปเดต
    if (idx === -1) {                                           // ไม่เจอ
      return res.status(404).json({
        success: false,
        message: "Course Id does not exists",
      });
    }

    courses[idx] = { ...courses[idx], ...body };                // อัปเดตแบบ merge
    res.set("Link", `/courses/${body.courseId}`);               // อ้างอิง
    return res.status(200).json({
      success: true,
      message: `Course ${body.courseId} has been updated successfully`,
      data: courses[idx],
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// DELETE /api/v2/courses  (คะแนนข้อ 6 + 6.1/6.2)
router.delete("/courses", (req: Request, res: Response) => {
  try {
    const body = req.body as { courseId: number };              // รับ body มีแค่ courseId
    const ok = zCourseDeleteBody.safeParse(body);               // ตรวจรูปแบบ
    if (!ok.success) {                                          // ไม่ผ่าน
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        error: ok.error.issues[0]?.message,
      });
    }

    const idx = courses.findIndex(c => c.courseId === body.courseId); // หาเป้าหมาย
    if (idx === -1) {                                           // ไม่เจอ
      return res.status(404).json({
        success: false,
        message: "Course Id does not exists",
      });
    }

    const removed = courses[idx];                               // เก็บสำเนา
    courses.splice(idx, 1);                                     // ลบ

    return res.status(200).json({                               // หรือใช้ 204 No Content ก็ได้
      success: true,
      message: `Course ${removed.courseId} has been deleted successfully`,
      data: removed,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;                                          // ส่ง router ออก
```

**`src/index.ts`** (ประกอบทุกอย่างเข้าด้วยกัน)

```ts
import express, { type Request, type Response } from "express"; // import express + types
import morgan from "morgan";                                     // logger

import studentRoutes from "./routes/studentRoutes.js";           // routes: /me
import courseRoutes from "./routes/courseRoutes.js";             // routes: course + student/courses

const app = express();                                           // สร้าง app instance

app.use(express.json());                                         // body parser JSON
app.use(morgan("dev"));                                          // logger (method url status ms)

app.get("/", (req: Request, res: Response) => {                  // GET /
  return res.status(200).json({                                  // ส่ง alive message
    success: true,
    message: "Lab 15 API service successfully",
  });
});

app.use("/api/v2", courseRoutes);                                // เมาท์ /api/v2/* -> courseRoutes
app.use("/", studentRoutes);                                     // เมาท์ /me -> studentRoutes

app.listen(3000, () =>                                           // เปิดพอร์ต 3000
  console.log("🚀 Server running on http://localhost:3000")
);

export default app;                                              // สำหรับ deploy ที่ต้อง import app
```

---

# 3) Lab16 — Users/Login (JWT) + Middlewares + Enrollments (RBAC)

> โจทย์บังคับ:
>
> * `POST /api/v2/users/login` สร้าง JWT
> * RBAC: ADMIN เท่านั้นถึงจะดู enrollments ทั้งหมด + reset
> * ADMIN หรือ STUDENT เจ้าของข้อมูลถึงจะดูผลลงทะเบียนของ studentId นั้นได้
> * STUDENT เจ้าของเท่านั้นถึง add/drop ได้
>   (สรุป endpoint ตรงกับที่คุณทำไว้แล้ว)

## 3.1 Types + DB + Reset

**`src/libs/types.ts` (ส่วนที่เพิ่มเพื่อ Lab16)**

```ts
export interface Enrollment {                  // ความสัมพันธ์ (studentId, courseId)
  studentId: string;
  courseId: string;                            // *** Lab16 ผมใช้ string 6 หลัก เพื่อ match ตัวอย่าง
}

export interface User {                         // ผู้ใช้สำหรับ login
  username: string;
  password: string;                             // demo เท่านั้น (จริงต้อง hash)
  studentId?: string | null;                    // นักศึกษามีรหัส, admin เป็น null
  role: "STUDENT" | "ADMIN";
  tokens?: string[];                            // เก็บ JWT ที่ออกให้
}

// payload ที่จะเก็บไว้ใน token
export interface UserPayload {
  username: string;
  studentId?: string | null;
  role: "STUDENT" | "ADMIN";
}

// request แบบ custom (ให้ middleware ใส่ user, token เข้าไป)
import { type Request } from "express";
export interface CustomRequest extends Request {
  user?: UserPayload;
  token?: string;
}
```

**`src/db/db.ts`** (ฉบับ Lab16 – โปรดเลือก “type เดียวกันทั้งระบบ” ให้ชัด; ตัวอย่างนี้ผมใช้ string 6 หลัก)

```ts
import { type Student, type Course, type Enrollment, type User } from "../libs/types.js";

export let students: Student[] = [
  { studentId: "650610001", firstName: "Matt",   lastName: "Damon",  program: "CPE" },
  { studentId: "650610002", firstName: "Cillian",lastName: "Murphy", program: "CPE",  courses: ["261207","261497"] as any }, // ถ้าจะใช้ string ทั้งระบบ ปรับ type Student ให้ courses?: string[]
  { studentId: "650610003", firstName: "Emily",  lastName: "Blunt",  program: "ISNE", courses: ["269101","261497"] as any }
];

export let courses: Course[] = [
  { courseId: "261207" as any, courseTitle: "Basic Computer Engineering Lab", instructors: ["Dome","Chanadda"] },
  { courseId: "261497" as any, courseTitle: "Full Stack Development",         instructors: ["Dome","Nirand","Chanadda"] },
  { courseId: "269101" as any, courseTitle: "Introduction to ISNE",           instructors: ["KENNETH COSH"] }
] as any;

export let enrollments: Enrollment[] = [
  { studentId: "650610002", courseId: "261207" },
  { studentId: "650610002", courseId: "261497" },
  { studentId: "650610003", courseId: "269101" },
  { studentId: "650610003", courseId: "261497" },
];

export let users: User[] = [
  { username: "user1@abc.com", password: "1234", studentId: "650610001", role: "STUDENT" },
  { username: "user2@abc.com", password: "1234", studentId: "650610002", role: "STUDENT" },
  { username: "user3@abc.com", password: "1234", studentId: "650610003", role: "STUDENT" },
  { username: "user4@abc.com", password: "5678", studentId: null,        role: "ADMIN"   },
];

// clone เก็บ original เพื่อ reset
const org_users        = structuredClone(users);
const org_students     = structuredClone(students);
const org_courses      = structuredClone(courses);
const org_enrollments  = structuredClone(enrollments);

export function reset_users()       { users       = structuredClone(org_users); }
export function reset_students()    { students    = structuredClone(org_students); }
export function reset_courses()     { courses     = structuredClone(org_courses); }
export function reset_enrollments() { enrollments = structuredClone(org_enrollments); }
```

> Tip กับดักที่คุณเจอในงานจริง
>
> * อย่าเผลอสะกดตัวแปร/พร็อพเพอร์ตี้ผิด เช่น `zInstructors` ใน `zCoursePutBody` (ควรเป็น `instructors`)
> * รหัสนักศึกษาหลุดเป็น “650615003” ในบางไฟล์ → ให้統一เป็น “650610003”

**`src/libs/zodValidators.ts`** (เลือก string 6 หลักสำหรับ Lab16)

```ts
import { z } from "zod";

export const zCourseId = z.string().length(6);                 // รหัสวิชา 6 ตัว (string)
export const zStudentId = z.string().length(9);                // รหัส นศ. 9 ตัว (string)

const zCourseTitle = z.string().min(6);
const zInstructors = z.array(z.string()).min(1);

export const zCoursePostBody = z.object({
  courseId: zCourseId,
  courseTitle: zCourseTitle,
  instructors: zInstructors,
});

export const zCoursePutBody = z.object({
  courseId: zCourseId,
  courseTitle: zCourseTitle.nullish(),
  instructors: zInstructors.nullish(),                         // *** แก้ชื่อให้ตรง ***
});

const zFirstName = z.string().min(3);
const zLastName  = z.string().min(3);
const zProgram   = z.enum(["CPE","ISNE"]);
const zCourses   = z.array(zCourseId);

export const zStudentPostBody = z.object({
  studentId: zStudentId,
  firstName: zFirstName,
  lastName: zLastName,
  program: zProgram,
  courses: zCourses.nullish(),                                  // ใช้ชื่อ courses ให้ตรง
});

export const zStudentPutBody = z.object({
  studentId: zStudentId,
  firstName: zFirstName.nullish(),
  lastName: zLastName.nullish(),
  program: zProgram.nullish(),
});

export const zEnrollmentBody = z.object({
  studentId: zStudentId,
  courseId: zCourseId,
});
```

## 3.2 Middlewares: `authenticateToken` + RBAC

**`src/middlewares/authenMiddleware.ts`** — ดึง Bearer token, verify, ใส่ payload ใน req

```ts
import { type Response, type NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import { type CustomRequest, type UserPayload } from "../libs/types.js";

export const authenticateToken = (
  req: CustomRequest, res: Response, next: NextFunction
) => {
  const authHeader = req.headers["authorization"];            // ดึง Authorization header
  if (!authHeader || !authHeader.startsWith("Bearer ")) {     // ต้องเป็นรูปแบบ Bearer <token>
    return res.status(401).json({ success: false, message: "Authorization header is required" });
  }

  const token = authHeader.split(" ")[1];                     // ตัดเอา token
  if (!token) {
    return res.status(401).json({ success: false, message: "Token is required" });
  }

  const secret = process.env.JWT_SECRET || "this_is_my_jwt_secret"; // โหลด secret
  jwt.verify(token, secret, (err, payload) => {               // verify token
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }
    req.user = payload as UserPayload;                        // แนบ payload ให้ req
    req.token = token;                                        // แนบ token ให้ req
    next();                                                   // ไปต่อ
  });
};
```

**`src/middlewares/checkRoleAdminMiddleware.ts`** — ADMIN เท่านั้น

```ts
import { type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

export const checkRoleAdmin = (req: CustomRequest, res: Response, next: NextFunction) => {
  const user = users.find((u: User) => u.username === req.user?.username); // หา user ใน DB
  if (!user || user.role !== "ADMIN") {                                     // ต้องมีและเป็น ADMIN
    return res.status(401).json({ success: false, message: "Unauthorized user" });
  }
  next();                                                                   // ผ่าน
};
```

**`src/middlewares/checkAllRolesMiddleware.ts`** — แค่ “ต้องเป็น user ที่มีตัวตน”

```ts
import { type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

export const checkAllRoles = (req: CustomRequest, res: Response, next: NextFunction) => {
  const user = users.find((u: User) => u.username === req.user?.username); // ต้องเจอใน DB
  if (!user) {
    return res.status(401).json({ success: false, message: "Unauthorized user" });
  }
  next();
};
```

**`src/middlewares/checkRoleStudentMiddleware.ts`** — STUDENT เท่านั้น

```ts
import { type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

export const checkRoleStudent = (req: CustomRequest, res: Response, next: NextFunction) => {
  const user = users.find((u: User) => u.username === req.user?.username);
  if (!user || user.role !== "STUDENT") {
    return res.status(401).json({ success: false, message: "Unauthorized user" });
  }
  next();
};
```

**`src/middlewares/invalidJsonMiddleware.ts`** — กัน JSON พัง

```ts
import { type Request, type Response, type NextFunction } from "express";

interface CustomError extends Error {
  status?: number;
  type?: string;
}

const invalidJsonMiddleware = (err: CustomError, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof SyntaxError && err.status === 400 && err.type === "entity.parse.failed") {
    return res.status(400).json({ success: false, message: "Invalid JSON payload" });
  }
  next(err);
};

export default invalidJsonMiddleware;
```

## 3.3 Users routes — `login`, `logout`, `GET /users` (ADMIN)

**`src/routes/usersRoutes.ts`**

```ts
import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, CustomRequest } from "../libs/types.js";
import { users, reset_users } from "../db/db.js";
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";

const router = Router();

// GET /api/v2/users (ADMIN only)
router.get("/", authenticateToken, checkRoleAdmin, (req: Request, res: Response) => {
  try {
    return res.status(200).json({ success: true, message: "Successful operation", data: users });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// POST /api/v2/users/login — ออก token + เก็บลง users[i].tokens
router.post("/login", (req: Request, res: Response) => {
  try {
    const { username, password } = req.body as { username: string; password: string; };

    const user = users.find((u: User) => u.username === username && u.password === password);
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid username or password!" });
    }

    const secret = process.env.JWT_SECRET || "this_is_my_jwt_secret";
    const token = jwt.sign({ username: user.username, studentId: user.studentId, role: user.role }, secret, { expiresIn: "5m" });

    user.tokens = user.tokens ? [...user.tokens, token] : [token]; // เก็บ token ลง DB (ฟีเจอร์เสริม)

    return res.status(200).json({ success: true, message: "Login successful", token });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something went wrong.", error: err });
  }
});

// POST /api/v2/users/logout — remove token ออกจาก users[i].tokens
router.post("/logout", authenticateToken, (req: CustomRequest, res: Response) => {
  try {
    const token = req.token!;
    const username = req.user!.username;

    const user = users.find((u: User) => u.username === username);
    if (!user || !user.tokens || !user.tokens.includes(token)) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    user.tokens = user.tokens.filter(t => t !== token); // ลบ token นี้ออก
    return res.status(200).json({ success: true, message: "Logout successful" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something went wrong.", error: err });
  }
});

// POST /api/v2/users/reset — reset users DB
router.post("/reset", (req: Request, res: Response) => {
  try {
    reset_users();
    return res.status(200).json({ success: true, message: "User database has been reset" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

export default router;
```

## 3.4 Enrollments routes — (ตาม RBAC ของ Lab16)

**`src/routes/enrollmentsRoutes.ts`**

```ts
import { Router, type Response } from "express";
import { type CustomRequest, type User, type Student, type Enrollment } from "../libs/types.js";

import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";
import { checkRoleStudent } from "../middlewares/checkRoleStudentMiddleware.js";

import { users, students, enrollments, reset_enrollments } from "../db/db.js";
import { zStudentId, zEnrollmentBody } from "../libs/zodValidators.js";

const router = Router();

// GET /api/v2/enrollments (ADMIN only) — ดูทั้งหมด
router.get("/", authenticateToken, checkRoleAdmin, (req: CustomRequest, res: Response) => {
  try {
    const data = students.map((s: Student) => ({
      studentId: s.studentId,
      courses: enrollments.filter(e => e.studentId === s.studentId).map(e => e.courseId)
    }));
    return res.status(200).json({ success: true, message: "Enrollments Information", data });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// POST /api/v2/enrollments/reset (ADMIN only)
router.post("/reset", authenticateToken, checkRoleAdmin, (req: CustomRequest, res: Response) => {
  try {
    reset_enrollments();
    return res.status(200).json({ success: true, message: "enrollments database has been reset" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// GET /api/v2/enrollments/:studentId (ADMIN หรือ STUDENT เจ้าของข้อมูล)
router.get("/:studentId", authenticateToken, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;
    const ok = zStudentId.safeParse(studentId);
    if (!ok.success) {
      return res.status(400).json({ message: "Validation failed", errors: ok.error.issues[0]?.message });
    }

    const studentIdx = students.findIndex(s => s.studentId === studentId);
    if (studentIdx === -1) {
      return res.status(404).json({ success: false, message: "StudentId does not exists" });
    }

    const caller = users.find((u: User) => u.username === req.user?.username);
    if (!caller) {
      return res.status(401).json({ success: false, message: "Unauthorized user" });
    }

    if (caller.role !== "ADMIN" && caller.studentId !== studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const courseIds = enrollments.filter(e => e.studentId === studentId).map(e => e.courseId);
    return res.status(200).json({ success: true, message: "Student information", data: { studentId, courses: courseIds } });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// POST /api/v2/enrollments/:studentId (STUDENT เจ้าของเท่านั้น) — add ลงทะเบียน
router.post("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;
    const body = req.body as Enrollment;

    const ok1 = zStudentId.safeParse(studentId);
    const ok2 = zEnrollmentBody.safeParse(body);
    if (!ok1.success) return res.status(400).json({ message: "Validation failed", errors: ok1.error.issues[0]?.message });
    if (!ok2.success) return res.status(400).json({ message: "Validation failed", errors: ok2.error.issues[0]?.message });

    const caller = users.find((u: User) => u.username === req.user?.username);
    if (!caller || caller.studentId !== studentId || body.studentId !== studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const sIdx = students.findIndex(s => s.studentId === studentId);
    if (sIdx === -1) return res.status(404).json({ success: false, message: "StudentId does not exists" });

    const dup = enrollments.find(e => e.studentId === studentId && e.courseId === body.courseId);
    if (dup) {
      return res.status(409).json({ success: false, message: "Enrollment is already exists" });
    }

    enrollments.push({ studentId, courseId: body.courseId }); // insert enrollment

    const newCourses = enrollments.filter(e => e.studentId === studentId).map(e => e.courseId);
    students[sIdx] = { ...students[sIdx], courses: newCourses as any }; // sync ฟิลด์ courses ใน Student (optional)

    return res.status(200).json({
      success: true,
      message: `Student ${studentId} && Course ${body.courseId} has been added successfully`,
      data: { studentId, courseId: body.courseId }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

// DELETE /api/v2/enrollments/:studentId (STUDENT เจ้าของเท่านั้น) — drop รายวิชา
router.delete("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;
    const body = req.body as { studentId: string; courseId: string; };

    const ok1 = zStudentId.safeParse(studentId);
    const ok2 = zEnrollmentBody.safeParse(body);
    if (!ok1.success) return res.status(400).json({ message: "Validation failed", errors: ok1.error.issues[0]?.message });
    if (!ok2.success) return res.status(400).json({ message: "Validation failed", errors: ok2.error.issues[0]?.message });

    const caller = users.find((u: User) => u.username === req.user?.username);
    if (!caller || caller.studentId !== studentId || body.studentId !== studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const sIdx = students.findIndex(s => s.studentId === studentId);
    if (sIdx === -1) return res.status(404).json({ success: false, message: "StudentId does not exists" });

    const eIdx = enrollments.findIndex(e => e.studentId === studentId && e.courseId === body.courseId);
    if (eIdx === -1) {
      return res.status(404).json({ success: false, message: "Enrollment does not exists" });
    }

    enrollments.splice(eIdx, 1); // ลบ enrollment
    const newCourses = enrollments.filter(e => e.studentId === studentId).map(e => e.courseId);
    students[sIdx] = { ...students[sIdx], courses: newCourses as any }; // sync ให้ตรง

    return res.status(200).json({
      success: true,
      message: `Student ${studentId} && Course ${body.courseId} has been deleted successfully`,
      data: { studentId, courses: newCourses }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

export default router;
```

## 3.5 Index (รวมทุกอย่าง)

```ts
import express, { type Request, type Response } from "express";
import morgan from "morgan";

import invalidJsonMiddleware from "./middlewares/invalidJsonMiddleware.js";

import usersRoutes        from "./routes/usersRoutes.js";
import enrollmentsRoutes  from "./routes/enrollmentsRoutes.js";

const app  = express();
const port = Number(process.env.PORT) || 3000;

app.use(express.json());
app.use(morgan("dev"));
app.use(invalidJsonMiddleware);

app.get("/", (req: Request, res: Response) => {
  res.status(200).send("Lab 16 API services");
});

app.use("/api/v2/users",        usersRoutes);
app.use("/api/v2/enrollments",  enrollmentsRoutes);

// not-found fallback
app.use((req, res) => res.status(404).json({ success:false, message:"Endpoint not found" }));

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
export default app;
```

---

# 4) ทดสอบด้วย Insomnia (ทีละขั้น)

## A) เตรียมข้อมูล

1. `POST /api/v2/users/reset` (ไม่บังคับ แต่ดีเวลาซ้อม)
2. `POST /api/v2/enrollments/reset` (ต้องแนบ Bearer token ของ ADMIN ในข้อ B ก่อน)

## B) Login

* **Admin**: `POST /api/v2/users/login`
  Body:

  ```json
  { "username": "user4@abc.com", "password": "5678" }
  ```

  ได้ `token` → ตั้งใน Insomnia: Auth → Bearer → ใส่ token

* **Student (เช่น user2)**:

  ```json
  { "username": "user2@abc.com", "password": "1234" }
  ```

## C) เรียก Endpoints ตามสิทธิ์

* **Admin เท่านั้น**

  * `GET /api/v2/enrollments` → ควรเห็นทุกคน
  * `POST /api/v2/enrollments/reset` → เคลียร์กลับ default

* **Admin + Student เจ้าของข้อมูล**

  * `GET /api/v2/enrollments/650610002`

    * Admin เรียกได้ทุกคน
    * Student เรียกได้เฉพาะของตนเองเท่านั้น มิฉะนั้น 403

* **Student เจ้าของข้อมูลเท่านั้น**

  * เพิ่ม: `POST /api/v2/enrollments/650610002`

    ```json
    { "studentId": "650610002", "courseId": "261207" }
    ```

    *ถ้าซ้ำ* → 409
  * ลบ: `DELETE /api/v2/enrollments/650610002`

    ```json
    { "studentId": "650610002", "courseId": "261207" }
    ```

    *ถ้าไม่พบ* → 404

---

# 5) เช็กลิสต์ก่อนสอบ + กับดักพบบ่อย

**เช็กลิสต์ (Lab15)**

* `/me` ตอบ JSON ตัวเองครบฟิลด์
* `GET /api/v2/students/:id/courses`

  * 400 เมื่อ id รูปแบบผิด
  * 404 เมื่อไม่พบ นศ.
  * 200 คืนชื่อวิชาตามรหัส
* `GET /api/v2/courses/:courseId`

  * 400 เมื่อไม่ใช่ 6 หลัก
  * 404 เมื่อไม่พบ
* `POST /api/v2/courses`

  * 400 เมื่อ body ไม่ตรง schema
  * 409 เมื่อซ้ำ
  * 201 เมื่อสำเร็จ
* `PUT /api/v2/courses`

  * 400 body ผิด, 404 ไม่เจอ, 200 สำเร็จ
* `DELETE /api/v2/courses`

  * 400 body ผิด, 404 ไม่เจอ, 200/204 สำเร็จ

**เช็กลิสต์ (Lab16)**

* `POST /api/v2/users/login` ได้ token (หมดอายุได้)
* ใช้ middleware ตรวจ Bearer token ทุก endpoint ที่ต้อง auth
* RBAC:

  * ADMIN: ดู enrollments ทั้งหมด + reset
  * ADMIN/STUDENT: ดูของ studentId ตามเงื่อนไข
  * STUDENT เจ้าของข้อมูลเท่านั้น: add/drop
* ลำดับตรวจสอบที่ดี: **validate** → **auth** → **role** → **process** → **respond**

**กับดักแก้ง่าย ๆ ที่ผมเห็นในโค้ดเดิมคุณ**

* ใช้ชื่อฟิลด์ไม่ตรงกัน (`course` vs `courses`, `zInstructors` vs `instructors`) → ให้ “ตั้งชื่อเดียว” ทุกที่
* Path ไม่ตรงสเปก (`/api/v2/course/:id` ควรเป็น `/api/v2/courses/:id`)
* รหัส นศ./วิชา เผลอเป็นคนละชนิด (string vs number) → **เลือกอย่างเดียวทั้งระบบ**
* ลืม `return` เวลา response → โค้ดไหลต่อแล้วยิงซ้ำ
* ลืม `try/catch` → error ไม่สวย, ได้ 500 โดยไม่ตั้งใจ
* ลืมเช็กซ้ำก่อน push (POST) → กลายเป็นซ้ำซ้อนไม่ตั้งใจ

---

# mini-cheatsheet (พกในหัวเวลาเข้าห้อง)

* **Status**: 200 OK / 201 Created / 400 Bad / 401 Unauth / 403 Forbidden / 404 Not Found / 409 Conflict / 500 Server
* **REST รูปแบบ**:

  * อ่าน: `GET /res`, `GET /res/:id`
  * สร้าง: `POST /res`  (body JSON)
  * แก้: `PUT /res`     (body มี id + fields)
  * ลบ: `DELETE /res`  (body มี id)
* **Zod pattern**:

  ```ts
  const ok = schema.safeParse(input);
  if (!ok.success) return res.status(400).json({ errors: ok.error.issues[0]?.message });
  ```
* **JWT flow**:

  1. `/login` → เซ็น token ด้วย `JWT_SECRET`
  2. Client แนบ `Authorization: Bearer <token>`
  3. Middleware `jwt.verify` → ผูก `req.user`
  4. RBAC: ตรวจ `user.role` และ “เจ้าของข้อมูล” ก่อนทำงาน

---

ถ้าคุณเปิดโปรเจ็กต์เดิมใน VSCode ให้ตรวจ **diff** ตามไฟล์ตัวอย่างด้านบนและแก้ชื่อฟิลด์/เส้นทาง/ตัวสะกดให้ “คงเส้นคงวา” ทั้งระบบ แล้วใช้ Insomnia ทดสอบตาม Step ที่ให้ คุณจะครอบคลุม rubric ของทั้ง Lab15 และ Lab16 ได้ครบถ้วน

อยากให้ผมเช็กไฟล์ของคุณ “แบบเทียบทีละบรรทัด” จุดไหนควรแก้ยังไง บอกได้เลย—ผมจะไล่รีวิวให้แบบรวดเร็ว พร้อมแก้ให้คอมเมนต์ทุกบรรทัดเหมือนตัวอย่างข้างบนครับ 🚀


