/*
 *    Jay Mundrawala
 *    Jordan Wilberding
 *    For now, no use of the code is permitted without written request.
 */

package edu.iit.ir.lucene.util;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.IllegalBlockSizeException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/*
 * This class is used to encrypt the contents of a directory
 */
public class Encrypt{
   static
   {   
      Security.addProvider(new BouncyCastleProvider());
   }
   private static final int BUFSIZE = (1 << 24);
   private static final String USAGE = "java edu.iit.ir.lucene.util.Encrypt input_dir out_dir";
   public static void main(String[] args) throws Exception
   {
      SecretKeySpec key;
      File in_dir;
      File out_dir;
      Cipher ecipher;

      if(args.length != 2){
         System.out.println(USAGE);
         System.exit(1);
      }

      in_dir = new File(args[0]);
      out_dir = new File(args[1]);

      if(!in_dir.isDirectory() && ((in_dir.exists() 
                  && !in_dir.isDirectory()) || !in_dir.exists()))
      {
         System.out.println(USAGE);
         System.exit(1);
      }

      if(!out_dir.exists()){
         if(!out_dir.mkdir())
            throw new RuntimeException("Unable to create output directory");
      }

      key = new SecretKeySpec(new byte[]{
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 
      },"AES");
      
      ecipher = Cipher.getInstance("AES/ECB/NoPadding");
      ecipher.init(Cipher.ENCRYPT_MODE, key);

      encryptFile(in_dir, out_dir, ecipher); 
      
      
   }
   public static void encryptFile(File efile, File dir, Cipher ecipher) throws Exception
   {
      if(efile.isDirectory()){
         
         File d = new File(dir,efile.getName());
         File[] files = efile.listFiles();
         d.mkdirs();
         for(int i = 0; i < files.length; i++)
         {
            encryptFile(files[i], d, ecipher);
         }

      }else{
         File f = new File(dir,efile.getName());
         InputStream in = new FileInputStream(efile);
         OutputStream out = new FileOutputStream(f);
         byte[] buffer = new byte[BUFSIZE];
         int read;
         long bytesRead = 0;

         while((read = in.read(buffer)) > 0){
            int e = ecipher.update(buffer,0,read,buffer,0);
            out.write(buffer,0,e);
            bytesRead += read;
         }

         int blockSize = ecipher.getBlockSize();
         int padding = (int)(blockSize - (bytesRead % blockSize));

         for(int i = 0; i < padding; i++){
            buffer[i] = (byte)padding;
         }

         /* Add padding */
         buffer = ecipher.update(buffer,0,padding);
         out.write(buffer);

         out.close();
         in.close();
      }
   }
}
