/*
 * Copyright 2012  Georgia Tech Research Institute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.gfipm.trustfabric;

/**
 *
 * @author http://stackoverflow.com/questions/861500/url-to-load-resources-from-the-classpath-in-java
 */
import java.io.IOException; 
import java.net.URL; 
import java.net.URLConnection; 
import java.net.URLStreamHandler; 
 
/** A {@link URLStreamHandler} that handles resources on the classpath. */ 
public class Handler extends URLStreamHandler { 
    /** The classloader to find resources from. */ 
    private final ClassLoader classLoader; 
 
    public Handler() { 
//        this.classLoader = getClass().getClassLoader(); 
        this.classLoader = Thread.currentThread().getContextClassLoader();
    } 
 
    public Handler(ClassLoader classLoader) { 
        this.classLoader = classLoader; 
    } 
 
    @Override 
    protected URLConnection openConnection(URL u) throws IOException { 
        final URL resourceUrl = classLoader.getResource(u.getPath()); 
        return resourceUrl.openConnection(); 
    } 
} 

/*
 * 
http://docs.oracle.com/javase/tutorial/networking/urls/readingURL.html
* 
import java.net.*;
import java.io.*;

public class URLReader {
    public static void main(String[] args) throws Exception {
  URL oracle = new URL("http://www.oracle.com/");
  BufferedReader in = new BufferedReader(
        new InputStreamReader(
        oracle.openStream()));

  String inputLine;

  while ((inputLine = in.readLine()) != null)
      System.out.println(inputLine);

  in.close();
    }
}
* 
* URL url = getClass().getClassLoader().getResource("someresource.xxx"); 
* URL resourceUrl = ClassLoader.getSystemClassLoader().getResource(u.getPath());
* 
 */
