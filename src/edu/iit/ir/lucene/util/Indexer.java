/*
 *    Jay Mundrawala
 *    Jordan Wilberding
 *    For now, no use of the code is permitted without written request.
 */

package edu.iit.ir.lucene.util;

import org.apache.lucene.analysis.*;
import org.apache.lucene.store.*;
import org.apache.lucene.analysis.snowball.*;
import org.apache.lucene.analysis.standard.*;
import org.apache.lucene.document.*;
import org.apache.lucene.index.*;

import java.io.*;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.xml.sax.*;

import javax.xml.parsers.*;

public class Indexer {
   public static File INDEX_DIR = new File("index");
   public static String USAGE = "edu.iit.ir.lucene.util.Indexer dir_to_index/";
   public static boolean DEBUG = true;
   private static int STATE_INDOC = 1;
   private static int STATE_OUTDOC = 1;


   public static void main(String[] args) throws Exception
   {
      System.out.println("STARTING");
      if(INDEX_DIR.exists())
      {
         System.out.println("Index already exists");
         System.exit(1);
      }
      
      if(args.length != 1)
      {
         System.out.println(USAGE);
         System.exit(1);
      }
      
      indexDir(new File(args[0]), INDEX_DIR);

      System.out.println("ENDING");

   }
   public static void indexDir(File dir_to_index, File index) throws Exception
   {
      Directory directory = EncryptedDirectory.getDirectory(INDEX_DIR);
		Analyzer analyzer = new SnowballAnalyzer("English");
      IndexWriter iwriter = new IndexWriter(directory, analyzer, true);
      iwriter.setUseCompoundFile(false);
      iwriter.setInfoStream(System.err);
     
      try{
         File[] files = dir_to_index.listFiles();
         for(int i = 0; i < files.length; i++)
         {
            File f = files[i];
            if(DEBUG)
               System.out.println(f.getName());
            indexFile(f, iwriter);
         }
         iwriter.optimize();
         iwriter.close();
      }catch(Exception e){
         directory.close();
         throw new RuntimeException(e);
      }
            directory.close();
   }
   public static void indexFile(File file_to_index, IndexWriter iwriter) throws Exception
   {
      DataInputStream in = null;
      int state = -1;

      try{
         in = new DataInputStream(new BufferedInputStream(new FileInputStream(file_to_index)));

         while(in.available() != 0) {
            //String doc = null;
            String s = in.readLine();
            
            if(s.trim().equals("<DOC>"))
            {
               boolean readingText = false;
               TrecDocument tdoc = new TrecDocument();

               while((s = in.readLine().trim()) != null && !s.equals("</DOC>")){
                  if(!readingText){
                     if(s.startsWith("<DOCNO>"))
                     {
                        int l_index = s.lastIndexOf("</DOCNO>");
                        if(l_index == -1)
                           throw new RuntimeException("END TAG NOT ON SAME LINE");
                        else
                           tdoc.doc_no = s.substring(7, l_index);
                     }

                     if(s.startsWith("<TTL>"))
                     {
                        int l_index = s.lastIndexOf("</TTL>");
                        if(l_index == -1)
                           throw new RuntimeException("END TAG NOT ON SAME LINE");
                        else
                           tdoc.title = s.substring(5, l_index);
                     }

                     if(s.startsWith("<TEXT>"))
                     {
                        readingText = true;
                        String sub = s.substring(6);
                        if(sub != null && sub.length() != 0)
                           tdoc.text = sub + "\n";
                        else
                           tdoc.text = new String();
                     }
                     
                  }else{
                     if(s.startsWith("</TEXT>"))
                           readingText = false;
                     else if(s.startsWith("<TTL>")){
                        int l_index = s.lastIndexOf("</TTL>");
                        if(l_index == -1)
                           throw new RuntimeException("END TAG NOT ON SAME LINE");
                        else
                           tdoc.title = s.substring(5, l_index);
                     }
                     else
                        tdoc.text += s + "\n";
                  }

               }
               try{               
                  indexTrecDoc(tdoc, iwriter);
               }catch(Exception e){
                  //e.printStackTrace();
                  //System.out.println("Caused by document " + tdoc.doc_no);
               }
            }
         }


      }catch(Exception e){
         e.printStackTrace();
         
         System.exit(1);
      }

//      iwriter.addDocument(indexTrecDoc(trecDoc));
   }
   public static void indexTrecDoc(TrecDocument trecDoc, IndexWriter iw) throws Exception
   {
      Document doc = new Document();
      doc.add(new Field("title", trecDoc.title, Field.Store.YES, Field.Index.TOKENIZED));
      doc.add(new Field("DOCNO", trecDoc.doc_no, Field.Store.YES, Field.Index.NO));
      doc.add(new Field("text", trecDoc.text, Field.Store.YES, Field.Index.TOKENIZED));
      iw.addDocument(doc);
   }

}
class TrecDocument
{
   String title;
   String doc_no;
   String text;
}
