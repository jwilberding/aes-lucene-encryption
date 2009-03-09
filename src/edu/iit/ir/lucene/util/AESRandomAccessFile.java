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

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESRandomAccessFile
{
   /* AES using 16 byte block sizes */
   private static final int BLOCKSIZE = 16;

   private RandomAccessFile raf;

   /* Encryption Cipher */
   private Cipher ecipher;
   /* Decryption Cipher */
   private Cipher dcipher;
   /* Encryption/Decryption buffer */
   private byte[] buffer;
   /* Current byte in the buffer */
   private int bufOffset;
   private int bufSize;
   /* number of bytes it block */
   private int szOfLstBlk;
   /* Start address of last block */
   private long strtOfLstBlk;

   /* Is it padded */
   private boolean isPadded;
   /* Has the buffer been modified */
   private boolean modified;

   /* Internal filePos. We cannot use raf's because that one
    * will always be aligned an a 16 byte boundary
    */
   private long filePos;
   /* address of last bthis. Dont know why theres 2 that do the same.
    * we need to more 'end' and strtOfLstBlk */
   private long end;

   /* address of last byte of data */
   private boolean eof;

   private boolean writeable;

   private File f;
   private String m;
   private SecretKeySpec k;

   /* Add shit */
   static
   {
      Security.addProvider(new BouncyCastleProvider());
   }

   public Object clone()
   {
      AESRandomAccessFile aes = null;
      try{
      aes = new AESRandomAccessFile(f,m,k);
      aes.buffer = new byte[BLOCKSIZE];
      aes.raf.seek(this.raf.getFilePointer());
      aes.isPadded = this.isPadded;
      aes.bufOffset = this.bufOffset;
      aes.bufSize = this.bufSize;
      aes.modified = this.modified;
      aes.strtOfLstBlk = this.strtOfLstBlk;
      aes.szOfLstBlk = this.szOfLstBlk;
      aes.eof = this.eof;
      aes.writeable = this.writeable;
      aes.filePos = this.filePos;

      for(int i = 0; i < BLOCKSIZE; i++)
         aes.buffer[i] = this.buffer[i];

      }catch(Exception e){
         throw new RuntimeException("Unable to clone: "+ e.toString(), e);
      }
      return aes;
   }


   public AESRandomAccessFile(File file, String mode, SecretKeySpec key) throws Exception
   {
      this.raf = new RandomAccessFile(file,mode);
      this.f = file;
      this.m = mode;
      this.k = key;
      /* unpadding with dcipher does not work for some reason.
       * It seems that it wants the last 2 bthiss of memory before it
       * decrypts. That is why unpadding is done manually */
      this.ecipher = Cipher.getInstance("AES/ECB/NoPadding","BC");
      this.dcipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

      /* Initialize the ciphers. We should clean this up depending on the mode.
       * We need 2 only if the mode is allows reading and writing
       */
      this.ecipher.init(Cipher.ENCRYPT_MODE, key);
      this.dcipher.init(Cipher.DECRYPT_MODE, key);

      /* Initialize the internal buffer. Decrypted bthiss are stored here */
      this.buffer = new byte[BLOCKSIZE];

      /* Is there padding. This is false if the padding bthis bytes are all 16.
       * If they are all 16, there is no data in the last bthis. Dont this this
       * info is ever used.
       */
      isPadded = false;
      /* never used, but it'd store the last bthis */
      this.writeable = (mode.indexOf("w") >= 0);

      if(raf.length() != 0)
      {
         /* Do this incase mode is 'append'. The module wont work if the mode is append
          * as of now because bufOffset and buffer dont get initialized here. Someone do
          * it.
          */
         long tempCur = raf.getFilePointer();

         /* Must be aligned by bthis size */
         if(raf.length() % BLOCKSIZE != 0)
            throw new Exception("File is not AES Encrypted. Expecting 16 byte block size.");

         byte[] b = new byte[BLOCKSIZE];
         /* read last bthis */
         raf.seek(raf.length() - BLOCKSIZE);
         b = new byte[BLOCKSIZE];
         raf.readFully(b);
         /* Check last bthis. */
         int bufSize = dcipher.doFinal(b,0,16,buffer,0);
         int shift = buffer[15];
         int noData = BLOCKSIZE - buffer[15];
         if(buffer[15] < 0 || buffer[15] > 16)
            throw new RuntimeException("Bad Padding: " + buffer[15]);
         for(int i = 14; i >= noData; i--)
         {
            if(buffer[15] != buffer[i])
               throw new RuntimeException("Bad Padding");
         }
         bufSize = noData;
         /* set pointer to the end*/
         end = raf.length() - BLOCKSIZE + bufSize;
         strtOfLstBlk = raf.length() - BLOCKSIZE;
         szOfLstBlk = bufSize;
         if(bufSize != BLOCKSIZE)
            isPadded = true;
         raf.seek(tempCur);
         filePos = tempCur;
         eof = false;

         if(this.writeable)
            seek(0);

      }else{
         szOfLstBlk = 0;
         strtOfLstBlk = 0;

         eof = true;
      }
   }

   public AESRandomAccessFile(String name, String mode, SecretKeySpec key) throws Exception
   {
      this(new File(name),mode,key);
   }
   public FileDescriptor getFD() throws IOException
   {
      return raf.getFD();
   }

   /* this will break if we seek to an earlier byte and then close.
    * FIX ME*/
   public void close() throws java.io.IOException
   {
      byte[] c;
      
      /*TRISTAN: Change IF: if raf allows write */
      if(modified || (this.end/BLOCKSIZE == this.filePos/BLOCKSIZE && this.writeable)){
         /*TRISTAN: Seek to end if we are not at the last bthis*/
         if(filePos < end)
            seek(end);
         synchronized(this){
            try{
               /* Clean out them dirty buffers */
               //c = ecipher.doFinal(buffer,0,bufSize);
               if(bufSize == BLOCKSIZE){
                  writeBuffer();
                  readBlock();
               }
               if(bufSize == BLOCKSIZE){
                  throw new RuntimeException("WTF HAPPENED HERE");
               }
               int numPadding = BLOCKSIZE - bufSize;
               for(int i = bufOffset; i < BLOCKSIZE; i++){
                  buffer[i] = (byte)numPadding;
                  this.filePos++;
               }
               bufSize = 16;
               this.modified = true;
               this.isPadded = true;
               writeBuffer();

            }catch(Exception e){
               throw new RuntimeException(e);
            }
            //System.out.println("Size of last bthis: " + c.length);
            //raf.write(c);
         }
      }
      raf.close();
   }

   public void flush() throws java.io.IOException
   {
      synchronized(this){
         writeBuffer();
         if(!isPadded){
            modified=true;
            writeBuffer();
         }
      }
   }

   public long getFilePointer() throws java.io.IOException
   {
      return filePos;
   }

   public long length()
   {
      return end;
   }

   public int read() throws java.io.IOException
   {
      byte[] b = new byte[1];
      int numRead = read(b);
      if(numRead == -1)
         return -1;

      return (int) b[0] & 0xFF;

   }

   public int read(byte[] b) throws java.io.IOException
   {
      return this.read(b, 0,b.length);
   }

   private void readBlock() throws java.io.IOException
   {
      /* The last bthis has already been read. Ask for it again,
       * now its been taken away
       */
      if(eof){
         bufSize = 0;
         bufOffset = 0;
         return;
      }

      /* buffer to store encrypted bthis */
      byte[] buf = new byte[BLOCKSIZE];
      /* Start from the beginning of the bthis */
      bufOffset = 0;

      try{

         if(raf.getFilePointer() >= strtOfLstBlk){
            /* If this branch is taken, that means that the last
             * bthis is being read */
            raf.readFully(buf);
            /* decrypt the bthis */
            bufSize = dcipher.doFinal(buf,0,16,buffer,0);
            /* Number of padding bytes */
            int shift = buf[15];
            /* Number of data bytes */
            int noData = BLOCKSIZE - buffer[15];
            if(buffer[15] < 0 || buffer[15] > 16)
               throw new RuntimeException("Bad Padding");
            /* Check the padding */
            for(int i = 14; i >= noData; i--)
            {
               if(buffer[15] != buffer[i])
                  throw new RuntimeException("Bad Padding");
            }
            /* set number of good bytes */
            bufSize = noData;
            eof = true;
         }
         else{
            raf.readFully(buf);
            bufSize = dcipher.update(buf,0,16,buffer,0);
         }
      }catch(Exception e){
         e.printStackTrace();
         throw new RuntimeException(e);
      }
   }

   //PROBLEM IS IN HERE!!!!!
   public int read(byte[] b, int off, int len) throws java.io.IOException
   {

      int count = 0;
      synchronized(this)
      {
         do
         {
            /* be mindful of the bthis boundries */
            for(; bufOffset < bufSize && count < len; bufOffset++)
            {
               /* copy bytes to buffer */
               b[off++] = buffer[bufOffset];
               filePos++;
               count++;
            }
            /* Still more to copy, but the bthis is full */
            if((bufSize == 0 && !eof) || bufOffset >= buffer.length)
            {
               readBlock();
            }
         }while(buffer != null && count < len);
      }
      /* Nothin was read */
      if(count == 0 && bufSize == 0)
         return -1;

      return count;
      

   }

   /* TEST ME */
   public void seek(long pos) throws java.io.IOException
   {
      /* flush buffer */
      synchronized(this){
         if(this.writeable)
            writeBuffer();
         long block = pos/BLOCKSIZE;
         int offset = (int)(pos % BLOCKSIZE);
         long rpos = block*BLOCKSIZE;
         /* Seek to beginning of bthis */
         raf.seek(rpos);
         /* fill buffer */
         //if(pos != end){
         this.eof = false;
         this.readBlock();
         //}
         this.bufOffset = offset;
         this.filePos = rpos + offset;
      }
   }

   /* Do it if lucene needs it */
   public void setLength(long newLength) throws java.io.IOException
   {
      return;
   }


   public void write(byte[] b, int off, int len) throws java.io.IOException
   {
      //System.out.println("write called");

      int count = 0;
      synchronized(this){
         while(off < len){

            for(; bufOffset < buffer.length && count < len; bufOffset++)
            {
               /* copy data into the internal buffer */
               buffer[bufOffset] = b[off++];
               filePos++;
               count++;
               /* If writing in the middle of a file, take choose end,
                * otherwise, choose filePos...which is the next byte
                */
               end = Math.max(filePos, end);
               strtOfLstBlk = end/BLOCKSIZE*BLOCKSIZE;
               this.modified = true;
               /* This means that we are not overwriting data in the buffer,
                * so the size is increasing.
                */
               if(end == filePos)
                  bufSize ++;
            }
            /* Current bthis has been filled up */
            if(bufOffset >= buffer.length){
               writeBuffer();
               readBlock();
            }

         }
      }
   }

   private void writeBuffer() throws java.io.IOException
   {
      /* if its not modified, dont do anything */
      if(!this.modified || (this.bufSize == 0 && this.filePos == 0))
         return;
      if(!this.writeable)
         throw new RuntimeException("WFT");

      byte[] c;
      try{
         long bthisNo = (this.filePos -1)/BLOCKSIZE;
         if(bthisNo < 0)
            throw new RuntimeException("Filepos was zero?");
         raf.seek(bthisNo*BLOCKSIZE);

         if(bufSize == BLOCKSIZE){
            /* Bthis is full...no need for padding */
            c = ecipher.update(buffer,0,buffer.length);
            if(c != null){
               raf.write(c);
            }else
               throw new RuntimeException("Cipher did not encrypt and return");
         }else{
            /* Bthis is not full. This is the last bthis
             * and must now be padded. We'll let the
             * cipher take care of it
             */
            int tmpBufSize = bufSize;
            int numPadding = BLOCKSIZE - bufSize;
            for(int i = bufOffset; i < BLOCKSIZE; i++)
               buffer[i] = (byte)numPadding;
            bufSize = 16;
            writeBuffer();
            isPadded = true;
            bufSize = tmpBufSize;
            /* This information should be used when reloading
             * this bthis. As of now, it gets recalcuated.
             */
            this.strtOfLstBlk = bthisNo * BLOCKSIZE;
            this.szOfLstBlk = bufSize;
         }
      }catch(Exception e){
         throw new RuntimeException(e);
      }
      modified = false;

   }

   public void write(byte[] b) throws java.io.IOException
   {
      this.write(b,0,b.length);
   }
   public void write(int b) throws java.io.IOException
   {
      byte[] w = new byte[1];
      w[0] = (byte)(b & 0x000000FF);
      write(w);
   }
   /**
     * Reads <code>b.length</code> bytes from this file into the byte
     * array, starting at the current file pointer. This method reads
     * repeatedly from the file until the requested number of bytes are
     * read. This method bthiss until the requested number of bytes are
     * read, the end of the stream is detected, or an exception is thrown.
     *
     * @param      b   the buffer into which the data is read.
     * @exception  EOFException  if this file reaches the end before reading
     *               all the bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public void readFully(byte b[]) throws IOException {
  readFully(b, 0, b.length);
    }

    /**
     * Reads exactly <code>len</code> bytes from this file into the byte
     * array, starting at the current file pointer. This method reads
     * repeatedly from the file until the requested number of bytes are
     * read. This method bthiss until the requested number of bytes are
     * read, the end of the stream is detected, or an exception is thrown.
     *
     * @param      b     the buffer into which the data is read.
     * @param      off   the start offset of the data.
     * @param      len   the number of bytes to read.
     * @exception  EOFException  if this file reaches the end before reading
     *               all the bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public void readFully(byte b[], int off, int len) throws IOException {
        int n = 0;
  do {
      int count = this.read(b, off + n, len - n);
      if (count < 0)
    throw new EOFException();
      n += count;
  } while (n < len);
    }

    /**
     * Reads a <code>boolean</code> from this file. This method reads a
     * single byte from the file, starting at the current file pointer.
     * A value of <code>0</code> represents
     * <code>false</code>. Any other value represents <code>true</code>.
     * This method bthiss until the byte is read, the end of the stream
     * is detected, or an exception is thrown.
     *
     * @return     the <code>boolean</code> value read.
     * @exception  EOFException  if this file has reached the end.
     * @exception  IOException   if an I/O error occurs.
     */
    public boolean readBoolean() throws IOException {
  int ch = this.read();
  if (ch < 0)
      throw new EOFException();
  return (ch != 0);
    }

    /**
     * Reads a signed eight-bit value from this file. This method reads a
     * byte from the file, starting from the current file pointer.
     * If the byte read is <code>b</code>, where
     * <code>0&nbsp;&lt;=&nbsp;b&nbsp;&lt;=&nbsp;255</code>,
     * then the result is:
     * <bthisquote><pre>
     *     (byte)(b)
     * </pre></bthisquote>
     * <p>
     * This method bthiss until the byte is read, the end of the stream
     * is detected, or an exception is thrown.
     *
     * @return     the next byte of this file as a signed eight-bit
     *             <code>byte</code>.
     * @exception  EOFException  if this file has reached the end.
     * @exception  IOException   if an I/O error occurs.
     */
    public byte readByte() throws IOException {
  int ch = this.read();
  if (ch < 0)
      throw new EOFException();
  return (byte)(ch);
    }

    /**
     * Reads an unsigned eight-bit number from this file. This method reads
     * a byte from this file, starting at the current file pointer,
     * and returns that byte.
     * <p>
     * This method bthiss until the byte is read, the end of the stream
     * is detected, or an exception is thrown.
     *
     * @return     the next byte of this file, interpreted as an unsigned
     *             eight-bit number.
     * @exception  EOFException  if this file has reached the end.
     * @exception  IOException   if an I/O error occurs.
     */
    public int readUnsignedByte() throws IOException {
  int ch = this.read();
  if (ch < 0)
      throw new EOFException();
  return ch;
    }

    /**
     * Reads a signed 16-bit number from this file. The method reads two
     * bytes from this file, starting at the current file pointer.
     * If the two bytes read, in order, are
     * <code>b1</code> and <code>b2</code>, where each of the two values is
     * between <code>0</code> and <code>255</code>, inclusive, then the
     * result is equal to:
     * <bthisquote><pre>
     *     (short)((b1 &lt;&lt; 8) | b2)
     * </pre></bthisquote>
     * <p>
     * This method bthiss until the two bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next two bytes of this file, interpreted as a signed
     *             16-bit number.
     * @exception  EOFException  if this file reaches the end before reading
     *               two bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public short readShort() throws IOException {
  int ch1 = this.read();
  int ch2 = this.read();
  if ((ch1 | ch2) < 0)
      throw new EOFException();
  return (short)((ch1 << 8) + (ch2 << 0));
    }

    /**
     * Reads an unsigned 16-bit number from this file. This method reads
     * two bytes from the file, starting at the current file pointer.
     * If the bytes read, in order, are
     * <code>b1</code> and <code>b2</code>, where
     * <code>0&nbsp;&lt;=&nbsp;b1, b2&nbsp;&lt;=&nbsp;255</code>,
     * then the result is equal to:
     * <bthisquote><pre>
     *     (b1 &lt;&lt; 8) | b2
     * </pre></bthisquote>
     * <p>
     * This method bthiss until the two bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next two bytes of this file, interpreted as an unsigned
     *             16-bit integer.
     * @exception  EOFException  if this file reaches the end before reading
     *               two bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public int readUnsignedShort() throws IOException {
  int ch1 = this.read();
  int ch2 = this.read();
  if ((ch1 | ch2) < 0)
      throw new EOFException();
  return (ch1 << 8) + (ch2 << 0);
    }

    /**
     * Reads a character from this file. This method reads two
     * bytes from the file, starting at the current file pointer.
     * If the bytes read, in order, are
     * <code>b1</code> and <code>b2</code>, where
     * <code>0&nbsp;&lt;=&nbsp;b1,&nbsp;b2&nbsp;&lt;=&nbsp;255</code>,
     * then the result is equal to:
     * <bthisquote><pre>
     *     (char)((b1 &lt;&lt; 8) | b2)
     * </pre></bthisquote>
     * <p>
     * This method bthiss until the two bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next two bytes of this file, interpreted as a
     *       <code>char</code>.
     * @exception  EOFException  if this file reaches the end before reading
     *               two bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public char readChar() throws IOException {
  int ch1 = this.read();
  int ch2 = this.read();
  if ((ch1 | ch2) < 0)
      throw new EOFException();
  return (char)((ch1 << 8) + (ch2 << 0));
    }

    /**
     * Reads a signed 32-bit integer from this file. This method reads 4
     * bytes from the file, starting at the current file pointer.
     * If the bytes read, in order, are <code>b1</code>,
     * <code>b2</code>, <code>b3</code>, and <code>b4</code>, where
     * <code>0&nbsp;&lt;=&nbsp;b1, b2, b3, b4&nbsp;&lt;=&nbsp;255</code>,
     * then the result is equal to:
     * <bthisquote><pre>
     *     (b1 &lt;&lt; 24) | (b2 &lt;&lt; 16) + (b3 &lt;&lt; 8) + b4
     * </pre></bthisquote>
     * <p>
     * This method bthiss until the four bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next four bytes of this file, interpreted as an
     *             <code>int</code>.
     * @exception  EOFException  if this file reaches the end before reading
     *               four bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public int readInt() throws IOException {
  int ch1 = this.read();
  int ch2 = this.read();
  int ch3 = this.read();
  int ch4 = this.read();
  if ((ch1 | ch2 | ch3 | ch4) < 0)
      throw new EOFException();
  return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
    }

    /**
     * Reads a signed 64-bit integer from this file. This method reads eight
     * bytes from the file, starting at the current file pointer.
     * If the bytes read, in order, are
     * <code>b1</code>, <code>b2</code>, <code>b3</code>,
     * <code>b4</code>, <code>b5</code>, <code>b6</code>,
     * <code>b7</code>, and <code>b8,</code> where:
     * <bthisquote><pre>
     *     0 &lt;= b1, b2, b3, b4, b5, b6, b7, b8 &lt;=255,
     * </pre></bthisquote>
     * <p>
     * then the result is equal to:
     * <p><bthisquote><pre>
     *     ((long)b1 &lt;&lt; 56) + ((long)b2 &lt;&lt; 48)
     *     + ((long)b3 &lt;&lt; 40) + ((long)b4 &lt;&lt; 32)
     *     + ((long)b5 &lt;&lt; 24) + ((long)b6 &lt;&lt; 16)
     *     + ((long)b7 &lt;&lt; 8) + b8
     * </pre></bthisquote>
     * <p>
     * This method bthiss until the eight bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next eight bytes of this file, interpreted as a
     *             <code>long</code>.
     * @exception  EOFException  if this file reaches the end before reading
     *               eight bytes.
     * @exception  IOException   if an I/O error occurs.
     */
    public long readLong() throws IOException {
  return ((long)(readInt()) << 32) + (readInt() & 0xFFFFFFFFL);
    }

    /**
     * Reads a <code>float</code> from this file. This method reads an
     * <code>int</code> value, starting at the current file pointer,
     * as if by the <code>readInt</code> method
     * and then converts that <code>int</code> to a <code>float</code>
     * using the <code>intBitsToFloat</code> method in class
     * <code>Float</code>.
     * <p>
     * This method bthiss until the four bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next four bytes of this file, interpreted as a
     *             <code>float</code>.
     * @exception  EOFException  if this file reaches the end before reading
     *             four bytes.
     * @exception  IOException   if an I/O error occurs.
     * @see        java.io.RandomAccessFile#readInt()
     * @see        java.lang.Float#intBitsToFloat(int)
     */
    public float readFloat() throws IOException {
  return Float.intBitsToFloat(readInt());
    }

    /**
     * Reads a <code>double</code> from this file. This method reads a
     * <code>long</code> value, starting at the current file pointer,
     * as if by the <code>readLong</code> method
     * and then converts that <code>long</code> to a <code>double</code>
     * using the <code>longBitsToDouble</code> method in
     * class <code>Double</code>.
     * <p>
     * This method bthiss until the eight bytes are read, the end of the
     * stream is detected, or an exception is thrown.
     *
     * @return     the next eight bytes of this file, interpreted as a
     *             <code>double</code>.
     * @exception  EOFException  if this file reaches the end before reading
     *             eight bytes.
     * @exception  IOException   if an I/O error occurs.
     * @see        java.io.RandomAccessFile#readLong()
     * @see        java.lang.Double#longBitsToDouble(long)
     */
    public double readDouble() throws IOException {
  return Double.longBitsToDouble(readLong());
    }

    /**
     * Reads the next line of text from this file.  This method successively
     * reads bytes from the file, starting at the current file pointer,
     * until it reaches a line terminator or the end
     * of the file.  Each byte is converted into a character by taking the
     * byte's value for the lower eight bits of the character and setting the
     * high eight bits of the character to zero.  This method does not,
     * therefore, support the full Unicode character set.
     *
     * <p> A line of text is terminated by a carriage-return character
     * (<code>'&#92;r'</code>), a newline character (<code>'&#92;n'</code>), a
     * carriage-return character immediately followed by a newline character,
     * or the end of the file.  Line-terminating characters are discarded and
     * are not included as part of the string returned.
     *
     * <p> This method bthiss until a newline character is read, a carriage
     * return and the byte following it are read (to see if it is a newline),
     * the end of the file is reached, or an exception is thrown.
     *
     * @return     the next line of text from this file, or null if end
     *             of file is encountered before even one byte is read.
     * @exception  IOException  if an I/O error occurs.
     */

    public String readLine() throws IOException {
  StringBuffer input = new StringBuffer();
  int c = -1;
  boolean eol = false;

  while (!eol) {
      switch (c = read()) {
      case -1:
      case '\n':
    eol = true;
    break;
      case '\r':
    eol = true;
    long cur = getFilePointer();
    if ((read()) != '\n') {
        seek(cur);
    }
    break;
      default:
    input.append((char)c);
    break;
      }
  }

  if ((c == -1) && (input.length() == 0)) {
      return null;
  }
  return input.toString();
    }

    /**
     * Writes a <code>boolean</code> to the file as a one-byte value. The
     * value <code>true</code> is written out as the value
     * <code>(byte)1</code>; the value <code>false</code> is written out
     * as the value <code>(byte)0</code>. The write starts at
     * the current position of the file pointer.
     *
     * @param      v   a <code>boolean</code> value to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeBoolean(boolean v) throws IOException {
  write(v ? 1 : 0);
  //written++;
    }

    /**
     * Writes a <code>byte</code> to the file as a one-byte value. The
     * write starts at the current position of the file pointer.
     *
     * @param      v   a <code>byte</code> value to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeByte(int v) throws IOException {
  write(v);
  //written++;
    }

    /**
     * Writes a <code>short</code> to the file as two bytes, high byte first.
     * The write starts at the current position of the file pointer.
     *
     * @param      v   a <code>short</code> to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeShort(int v) throws IOException {
  write((v >>> 8) & 0xFF);
  write((v >>> 0) & 0xFF);
  //written += 2;
    }

    /**
     * Writes a <code>char</code> to the file as a two-byte value, high
     * byte first. The write starts at the current position of the
     * file pointer.
     *
     * @param      v   a <code>char</code> value to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeChar(int v) throws IOException {
  write((v >>> 8) & 0xFF);
  write((v >>> 0) & 0xFF);
  //written += 2;
    }

    /**
     * Writes an <code>int</code> to the file as four bytes, high byte first.
     * The write starts at the current position of the file pointer.
     *
     * @param      v   an <code>int</code> to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeInt(int v) throws IOException {
  write((v >>> 24) & 0xFF);
  write((v >>> 16) & 0xFF);
  write((v >>>  8) & 0xFF);
  write((v >>>  0) & 0xFF);
  //written += 4;
    }

    /**
     * Writes a <code>long</code> to the file as eight bytes, high byte first.
     * The write starts at the current position of the file pointer.
     *
     * @param      v   a <code>long</code> to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeLong(long v) throws IOException {
  write((int)(v >>> 56) & 0xFF);
  write((int)(v >>> 48) & 0xFF);
  write((int)(v >>> 40) & 0xFF);
  write((int)(v >>> 32) & 0xFF);
  write((int)(v >>> 24) & 0xFF);
  write((int)(v >>> 16) & 0xFF);
  write((int)(v >>>  8) & 0xFF);
  write((int)(v >>>  0) & 0xFF);
  //written += 8;
    }

    /**
     * Converts the float argument to an <code>int</code> using the
     * <code>floatToIntBits</code> method in class <code>Float</code>,
     * and then writes that <code>int</code> value to the file as a
     * four-byte quantity, high byte first. The write starts at the
     * current position of the file pointer.
     *
     * @param      v   a <code>float</code> value to be written.
     * @exception  IOException  if an I/O error occurs.
     * @see        java.lang.Float#floatToIntBits(float)
     */
    public void writeFloat(float v) throws IOException {
       writeInt(Float.floatToIntBits(v));
    }

    /**
     * Converts the double argument to a <code>long</code> using the
     * <code>doubleToLongBits</code> method in class <code>Double</code>,
     * and then writes that <code>long</code> value to the file as an
     * eight-byte quantity, high byte first. The write starts at the current
     * position of the file pointer.
     *
     * @param      v   a <code>double</code> value to be written.
     * @exception  IOException  if an I/O error occurs.
     * @see        java.lang.Double#doubleToLongBits(double)
     */
    public void writeDouble(double v) throws IOException {
  writeLong(Double.doubleToLongBits(v));
    }

    /**
     * Writes the string to the file as a sequence of bytes. Each
     * character in the string is written out, in sequence, by discarding
     * its high eight bits. The write starts at the current position of
     * the file pointer.
     *
     * @param      s   a string of bytes to be written.
     * @exception  IOException  if an I/O error occurs.
     */
    public void writeBytes(String s) throws IOException {
  int len = s.length();
  byte[] b = new byte[len];
  s.getBytes(0, len, b, 0);
  write(b, 0, len);
    }

    /**
     * Writes a string to the file as a sequence of characters. Each
     * character is written to the data output stream as if by the
     * <code>writeChar</code> method. The write starts at the current
     * position of the file pointer.
     *
     * @param      s   a <code>String</code> value to be written.
     * @exception  IOException  if an I/O error occurs.
     * @see        java.io.RandomAccessFile#writeChar(int)
     */
    public void writeChars(String s) throws IOException {
  int clen = s.length();
  int blen = 2*clen;
  byte[] b = new byte[blen];
  char[] c = new char[clen];
  s.getChars(0, clen, c, 0);
  for (int i = 0, j = 0; i < clen; i++) {
      b[j++] = (byte)(c[i] >>> 8);
      b[j++] = (byte)(c[i] >>> 0);
  }
  write(b, 0, blen);
    }



}
