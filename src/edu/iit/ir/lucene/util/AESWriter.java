/*
   Jay Mundrawala
   Jordan Wilberding
   For now, no use of the code is permitted without written request.
*/
package edu.iit.ir.lucene.util;
import java.io.*;
import java.io.DataOutput;
import java.io.DataInput;
import java.io.RandomAccessFile;
import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.IllegalBlockSizeException;
import java.util.*;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESWriter
{
   /* AES using 16 byte block sizes */
   private static final int BLOCKSIZE = 16;

   private RandomAccessFile raf;

   /* Encryption Cipher */
   private Cipher ecipher;

   /* Decryption Cipher. This is needed if a seek occurs and entire blocks are not
    *  overwritten. */
   private Cipher dcipher;
   
   /* Encryption pending buffer. If there is a block that is not entirly filled, this buffer
    * will be used. */
   private byte[] buffer;
   
   /* Current byte in the buffer */
   private int bufferSize;

   /* Length of the encrypted file */ 
   private long end;

   /* Current Position in the file */
   private long curFP;

   /* Contains the state of the padding */
   private boolean isPadded;
   
   static
   {
      Security.addProvider(new BouncyCastleProvider());
   }


   public AESWriter(File file, SecretKeySpec key) throws Exception
   {
      this.raf = new RandomAccessFile(file,"rw");

      /* Only allow writing on new files. Lucene specifies that a new writer
       * will be created only for new files.
       */
      if(raf.length() != 0)
         throw new RuntimeException("File already Exists");

      /* unpadding with dcipher does not work for some reason.
       * It seems that it wants the last 2 blocks of memory before it
       * decrypts. That is why unpadding is done manually */
      this.ecipher = Cipher.getInstance("AES/ECB/NoPadding","BC");
      this.dcipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

      /* Initialize the ciphers. We should clean this up depending on the mode.
       * We need 2 only if the mode is allows reading and writing
       */
      this.ecipher.init(Cipher.ENCRYPT_MODE, key);
      this.dcipher.init(Cipher.DECRYPT_MODE, key);

      /* Initialize the internal buffer. Decrypted blocks are stored here */
      this.buffer = new byte[BLOCKSIZE];

      /* Is there padding. This is false if the padding block bytes are all 16.
       * If they are all 16, there is no data in the last block. Dont this this
       * info is ever used.
       */
      this.isPadded = false;
      this.curFP = 0;
   }

   public AESWriter(String name, SecretKeySpec key) throws Exception
   {
      this(new File(name),key);
   }

   public void close() throws java.io.IOException, javax.crypto.ShortBufferException
   {
      synchronized(this){
         _flush();
         if(!this.isPadded){
            if(this.end % BLOCKSIZE != 0){
               throw new RuntimeException("should not happen");
            }else{
               byte[] b = new byte[BLOCKSIZE];
               for(int i = 0; i < b.length; i++)
                  b[i] = 16;
               this.ecipher.update(b,0,BLOCKSIZE,b);
               writeBlock(b);
            }
         }
      }
   }

   public void flush() throws java.io.IOException, javax.crypto.ShortBufferException
   {
      synchronized(this){
         _flush();
      }
   }

   private void _flush() throws java.io.IOException, javax.crypto.ShortBufferException
   {
      if(this.curFP > this.end)
         return;

      if(bufferSize > 0)
      {
         if(this.curFP/BLOCKSIZE == this.end/BLOCKSIZE){
            /* add padding */
            byte[] tmpBuf = new byte[BLOCKSIZE];
            byte padding = (byte)(BLOCKSIZE - (this.end % BLOCKSIZE));

            if(this.curFP != this.end)
            {
               /* Fill in remaining bytes from file. There will be bytes on disk
                * because the only way to get to this point is from a seek. A seek
                * will flush out bytes to the disk */
               this.raf.seek(this.curFP/BLOCKSIZE*BLOCKSIZE);
               this.raf.readFully(tmpBuf);
               this.dcipher.update(tmpBuf,0,BLOCKSIZE,tmpBuf);
               System.out.println("Byte 5 = " + this.buffer[5]);
               for(int i = (int)(this.curFP % BLOCKSIZE); i < this.end % BLOCKSIZE; i++)
               {
                  System.out.println("Filling in byte " + i + " from file");
                  buffer[i] = tmpBuf[i];
               }
            }

            for(int i = (int)(this.end % BLOCKSIZE); i < BLOCKSIZE; i++)
            {
               buffer[i] = padding;
            }
            this.ecipher.update(buffer,0,BLOCKSIZE,tmpBuf);
            writeBlock(tmpBuf);
            this.isPadded = true;
         }else{
            /* Fill all remaining bytes from disk. There will be no padding here */
            byte[] tmpBuf = new byte[BLOCKSIZE];
            this.raf.seek(this.curFP/BLOCKSIZE*BLOCKSIZE);
            this.raf.readFully(tmpBuf);
            this.dcipher.update(tmpBuf,0,BLOCKSIZE,tmpBuf);

            for(int i = (int)(this.curFP % BLOCKSIZE); i < BLOCKSIZE; i++)
            {
               buffer[i] = tmpBuf[i];
            }
            this.ecipher.update(buffer,0,BLOCKSIZE,tmpBuf);
            writeBlock(tmpBuf);
         }
      }
   }

   public long getFilePointer() throws java.io.IOException
   {
      return curFP;
   }

   public long length()
   {
      return end;
   }

  public void seek(long pos) throws java.io.IOException, javax.crypto.ShortBufferException
   {
      /* flush buffer */
      synchronized(this){
         if(this.bufferSize > 0)
         {
            /* We need to flush out the buffer */
            _flush();
         }
         /* update position of next write */
         this.curFP = pos;
         if(this.curFP < end){
            this.raf.seek(this.curFP/BLOCKSIZE*BLOCKSIZE);
            this.bufferSize = 0;
            int iter = (int)(this.curFP % BLOCKSIZE);
            /*Fill byte 0 to curFP with bytes from file */
            byte[] tmpBuf = new byte[BLOCKSIZE];
            this.raf.readFully(tmpBuf);
            this.dcipher.update(tmpBuf,0,BLOCKSIZE,tmpBuf);

            for(int i = 0; i < iter; i++)
            {
               buffer[i] = tmpBuf[i]; 
               System.out.println("copied " + buffer[i]);
            }
            this.bufferSize = iter;
         }else{
            throw new RuntimeException("Cannot seek past end");
         }
         assert this.bufferSize == this.curFP % BLOCKSIZE : this.bufferSize + " " + this.curFP;
      }
   }

   public void write(byte[] b, int off, int len) throws java.io.IOException, javax.crypto.ShortBufferException
   {
      byte[] tmpBuf = null;
      System.out.println("Writing " + len + " bytes at " + this.curFP + ". this.bufferSize = " + this.bufferSize);

      synchronized(this){
         if(this.bufferSize > 0)
         {
            int filler = BLOCKSIZE - this.bufferSize;
            int negboff = this.bufferSize;

            /* Fill in buffered block */
            for(int i = this.bufferSize; i < BLOCKSIZE && i < off + len + negboff ; i++, 
                  this.bufferSize++){
               buffer[i] = b[off + i - negboff];
               System.out.println("buffer[" + i + "]=" + buffer[i]);

            }
            if(this.bufferSize > BLOCKSIZE)
               throw new RuntimeException("BufferSize larger than expected");
            if(this.bufferSize == BLOCKSIZE){
               int w = this.ecipher.update(buffer,0,BLOCKSIZE,buffer);
               if(w != BLOCKSIZE)
                  throw new RuntimeException("Buffer in size does not equal buffer out size");
               /* Commit block to file */
               writeBlock(buffer);
               this.curFP += filler;
               this.bufferSize = 0;

               /* encrypt and write remaining bytes */
               int limit = (len - filler)/BLOCKSIZE*BLOCKSIZE;
               int remaining = (len - filler) - limit;

               if(limit > 0)
               {
                  /* Have at least one full block */
                  tmpBuf = this.ecipher.update(b,off + filler,limit);
                  if(tmpBuf.length != limit)
                     throw new RuntimeException("Buffer in size does not equal buffer out size");
                  writeBlock(tmpBuf);
               }

               if(remaining != 0)
               {
                  for(int i = 0; i < remaining; i++){
                     this.buffer[i] = b[off + i + limit + filler];
                     System.out.println("buffer[" + i + "]=" + buffer[i]);
                  }
                  this.bufferSize = remaining;
               }
               /* Check if padding could have been overwritten */
               if(this.curFP > this.end)
                  isPadded = false;
               /* Write tmpBuf to raf */
               this.curFP += len - filler;
            }else{
               this.curFP += len;
            }
         }else{
            /* Number of bytes to send straight to cipher */
            int limit = (len)/BLOCKSIZE*BLOCKSIZE;
            int remaining = len - limit;
            if(limit > 0)
            {
               /* Have at least one full block */
               tmpBuf = this.ecipher.update(b,off,limit);
               if(tmpBuf.length != limit)
                  throw new RuntimeException("Buffer in size does not equal buffer out size");
               writeBlock(tmpBuf);
            }

            /* Copy remaining bytes into buffer */
            if(remaining != 0)
            {
               for(int i = 0; i < remaining; i++)
                  this.buffer[i] = b[off + i + limit];
               this.bufferSize = remaining;
            }
            /* Check if padding could have been overwritten */
            if(this.curFP > this.end)
               isPadded = false;
            /* Write tmpBuf to raf */
            this.curFP = len;
         }
         this.end = Math.max(this.curFP,this.end);
      }
   }

   private void writeBlock(byte[] b) throws java.io.IOException
   {
      if(b.length % BLOCKSIZE != 0)
         throw new RuntimeException("Invalid buffer size");
      this.raf.seek(this.curFP/BLOCKSIZE*BLOCKSIZE);
      this.raf.write(b);
   }

   public static void main(String[] args) throws Exception
   {
      SecretKeySpec key = new SecretKeySpec(new byte[]{
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 
      },"AES");


      {
         File f = new File("tests/001");
         AESWriter aes = new AESWriter(f,key);
         byte[] b = new byte[15];
         byte[] t = new byte[15];
         for(int i = 0; i < b.length; i++)
         {
            b[i] = (byte)i;
         }
         aes.write(b,0,b.length);
         aes.close();

         AESRandomAccessFile reader = new AESRandomAccessFile(f,"r",key);
         
         reader.read(t);
         
         if(Arrays.equals(b,t) && reader.length() == 15)
            System.out.println("001 PASSED");
         else
            System.out.println("001 FAILED");

         
      }
      {
         File f = new File("tests/002");
         AESWriter aes = new AESWriter(f,key);
         byte[] b = new byte[16];
         byte[] t = new byte[16];
         for(int i = 0; i < b.length; i++)
         {
            b[i] = (byte)i;
         }
         aes.write(b,0,b.length);
         aes.close();

         AESRandomAccessFile reader = new AESRandomAccessFile(f,"r",key);
         
         reader.read(t);
         
         if(Arrays.equals(b,t))
            System.out.println("002 PASSED");
         else
            System.out.println("002 FAILED");

         
      }
      {
         File f = new File("tests/003");
         AESWriter aes = new AESWriter(f,key);
         byte[] b = new byte[15];
         byte[] t = new byte[15];
         for(int i = 0; i < b.length; i++)
         {
            b[i] = (byte)i;
         }
         aes.write(b,0,b.length);
         aes.seek(5);
         aes.write(b,0,1);
         b[5] = 0;
         aes.close();

         AESRandomAccessFile reader = new AESRandomAccessFile(f,"r",key);
         
         reader.read(t);
         
         if(Arrays.equals(b,t) && reader.length() == 15)
            System.out.println("003 PASSED");
         else{
            System.out.println("003 FAILED: b.length=" + b.length + " t.length=" + t.length);
            for(int i = 0; i < b.length; i++)
            {
               System.out.println(i + ": " + b[i] + " " + t[i]);
            }
         }

         
      }
      {
         File f = new File("tests/004");
         AESWriter aes = new AESWriter(f,key);
         byte[] b = new byte[20];
         byte[] t = new byte[20];
         for(int i = 0; i < 16; i++)
         {
            b[i] = (byte)i;
         }
         aes.write(b,0,b.length-1);
         aes.seek(5);
         aes.write(b,0,15);
         for(int i = 5; i < 20; i++)
         {
            b[i] = (byte)(i-5);
         }
         aes.close();

         System.out.println("Reading");
         AESRandomAccessFile reader = new AESRandomAccessFile(f,"r",key);
         System.out.println(reader.length());
         reader.read(t);
         
         System.out.println("done");

         if(Arrays.equals(b,t) && reader.length() == 20)
            System.out.println("004 PASSED");
         else{
            System.out.println("004 FAILED: b.length=" + b.length + " reader.length=" + reader.length());
            for(int i = 0; i < t.length; i++)
            {
               System.out.println(i + ": " + b[i] + " " + t[i]);
            }
         }

         
      }
      {
         File f = new File("tests/005");
         AESWriter aes = new AESWriter(f,key);
         byte[] b = new byte[17];
         byte[] t = new byte[17];
         for(int i = 0; i < b.length; i++)
         {
            b[i] = (byte)i;
         }
         aes.write(b,0,b.length);
         aes.close();

         AESRandomAccessFile reader = new AESRandomAccessFile(f,"r",key);
         
         reader.read(t);
         
         if(Arrays.equals(b,t))
            System.out.println("005 PASSED");
         else
            System.out.println("005 FAILED");

         
      }
      {
         File f = new File("tests/006");
         AESWriter aes = new AESWriter(f,key);
         byte[] b = new byte[32];
         byte[] t = new byte[32];
         for(int i = 0; i < b.length; i++)
         {
            b[i] = (byte)i;
         }
         aes.write(b,0,17);
         aes.write(b,17,15);
         aes.close();

         AESRandomAccessFile reader = new AESRandomAccessFile(f,"r",key);
         
         reader.read(t);
         
         if(Arrays.equals(b,t))
            System.out.println("006 PASSED");
         else
            System.out.println("006 FAILED");

         
      }
   }

}
