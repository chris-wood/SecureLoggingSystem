package controllers;

import play.*;
import play.mvc.*;

import views.html.*;

public class Application extends Controller {
  
  public static Result index() {
	  System.out.println("received a request for the root, processing now.");
	  return ok("Your new application is ready.");
  }
  
}