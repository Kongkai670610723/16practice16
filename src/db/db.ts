//D:\workspace\practice_lab16\src\db\db.ts
import {
  type Student,
  type Course,
  type Enrollment,
  type User,
} from "../libs/types.js";

// In-memory "database"
export let students: Student[] = [
  {
    studentId: "650610001",
    firstName: "Matt",
    lastName: "Damon",
    program: "CPE",
  },
  {
    studentId: "650610002",
    firstName: "Cillian",
    lastName: "Murphy",
    program: "CPE",
    courses: ["261207", "261497"],
  },
  {
    studentId: "650615003",
    firstName: "Emily",
    lastName: "Blunt",
    program: "ISNE",
    courses: ["269101", "261497"],
  },
];

export let courses: Course[] = [
  {
    courseId: "261207",
    courseTitle: "Basic Computer Engineering Lab",
    instructors: ["Dome", "Chanadda"],
  },
  {
    courseId: "261497",
    courseTitle: "Full Stack Development",
    instructors: ["Dome", "Nirand", "Chanadda"],
  },
  {
    courseId: "269101",
    courseTitle: "Introduction to Information Systems and Network Engineering",
    instructors: ["KENNETH COSH"],
  },
];

export let enrollments: Enrollment[] = [
  {
    studentId: "650610002",
    courseId: "261207",
  },
  {
    studentId: "650610002",
    courseId: "261497",
  },
  {
    studentId: "650610003",
    courseId: "269101",
  },
  {
    studentId: "650610003",
    courseId: "261497",
  },
];

export let users: User[] = [
  {
    username: "user1@abc.com",
    password: "1234",
    studentId: "650610001",
    role: "STUDENT",
  },
  {
    username: "user2@abc.com",
    password: "1234",
    studentId: "650610002",
    role: "STUDENT",
  },
  {
    username: "user3@abc.com",
    password: "1234",
    studentId: "650610003",
    role: "STUDENT",
  },
  {
    username: "user4@abc.com",
    password: "5678",
    studentId: null,
    role: "ADMIN",
  },
];

export const DB = {
  students,
  courses,
  enrollments,
  users,
};

// For resetting the database to its original state
const org_users = structuredClone(users);
const org_students = structuredClone(students);
const org_courses = structuredClone(courses);
const org_enrollments = structuredClone(enrollments);

export function reset_db() {
  users = structuredClone(org_users);
  students = structuredClone(org_students);
  courses = structuredClone(org_courses);
  enrollments = structuredClone(org_enrollments);
}

export function reset_users() {
  users = structuredClone(org_users);
}
export function reset_students() {
  students = structuredClone(org_students);
}
export function reset_courses() {
  courses = structuredClone(org_courses);
}
export function reset_enrollments() {
  enrollments = structuredClone(org_enrollments);
}
