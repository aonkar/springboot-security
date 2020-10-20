package api.spring.security.springsecurity.controllers;

import api.spring.security.springsecurity.models.Student;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("${version}/api/management/students")
public class StudentManagementController {

    @GetMapping("")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public ResponseEntity<List<Student>> getAllStudents() {
        List<Student> students = new ArrayList<>();
        students.add(new Student("1", "Abhishek"));
        students.add(new Student("2", "Vaishnavi"));
        students.add(new Student("3", "Bhargavi"));
        return new ResponseEntity<>(students, HttpStatus.OK);
    }

    @PostMapping("")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public ResponseEntity registerStudent(@RequestBody final Student student) {
        return new ResponseEntity<>(student, HttpStatus.OK);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public ResponseEntity updateStudent(@PathVariable("studentId") final String studentId,
                                        @RequestBody final Student student) {
        return new ResponseEntity<>(student, HttpStatus.OK);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public ResponseEntity deleteStudent(@PathVariable("studentId") final String studentId) {
        return new ResponseEntity<>("Deleted StudentId: " + studentId, HttpStatus.OK);
    }
}
