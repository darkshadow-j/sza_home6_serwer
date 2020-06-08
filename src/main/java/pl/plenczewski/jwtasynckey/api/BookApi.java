package pl.plenczewski.jwtasynckey.api;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/book")
public class BookApi {

    private List<String> bookList;

    public BookApi() {
        bookList = new ArrayList<>();
        bookList.add("One");
        bookList.add("Two");
    }


    @GetMapping
    public List<String> getBookList(){
        return bookList;
    }


}
