package springboot.springsecurity.auth.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/managment")
public class ManagementController {
    @GetMapping
    public String get(){
        return "GET:: management controller";
    }
    @PostMapping
    public String post(){
        return "POST:: management controller";
    }
    @PutMapping
    public String put(){
        return "PUT:: managment controller";
    }
    @DeleteMapping
    public String delete(){
        return "DELETE:: managment controller";
    }
}
