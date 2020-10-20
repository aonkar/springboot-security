package api.spring.security.springsecurity.controllers;


import api.spring.security.springsecurity.models.Student;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("${version}/api/students")
public class StudentController {

    @GetMapping("")
    public ResponseEntity<List<Student>> getStudents() {
        List<Student> students = new ArrayList<>();
        students.add(new Student("1", "Abhishek"));
        students.add(new Student("2", "Vaishnavi"));
        students.add(new Student("3", "Bhargavi"));
        return new ResponseEntity<>(students, HttpStatus.OK);
    }
}
