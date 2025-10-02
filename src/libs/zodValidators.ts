//D:\workspace\practice_lab16\src\libs\zodValidators.ts
import { z } from "zod";

////// Course Validators //////

export const zCourseId = z
  .string()
  .length(6, { message: "Course ID must be 6 digits." });
const zCourseTitle = z
  .string()
  .min(6, { message: "Course title must be at least 6 charaters." });
const zInstructors = z.array(z.string()).min(1);

export const zCoursePostBody = z.object({
  courseId: zCourseId,
  courseTitle: zCourseTitle,
  instructors: zInstructors,
});

export const zCoursePutBody = z.object({
  courseId: zCourseId,
  courseTitle: zCourseTitle.nullish(),
  zInstructors: zInstructors.nullish(),
});

//////  Student Validators //////

export const zStudentId = z
  .string()
  .length(9, { message: "Student Id must contain 9 characters" });
const zFirstName = z
  .string()
  .min(3, { message: "First name requires at least 3 charaters" });
const zLastName = z
  .string()
  .min(3, { message: "Last name requires at least 3 characters" });
const zProgram = z.enum(["CPE", "ISNE"], {
  message: "Program must be either CPE or ISNE",
});
const zCourses = z.array(zCourseId);

export const zStudentPostBody = z.object({
  studentId: zStudentId,
  firstName: zFirstName,
  lastName: zLastName,
  program: zProgram,
  course: zCourses.nullish(),
});

export const zStudentPutBody = z.object({
  studentId: zStudentId,
  firstName: zFirstName.nullish(), //firstName can be null or undefined
  lastName: zLastName.nullish(), //lastName can be null or undefined
  program: zProgram.nullish(), //program can be null or undefined
});

////// Enrollment Validators //////

export const zEnrollmentBody = z.object({
  studentId: zStudentId,
  courseId: zCourseId,
});
