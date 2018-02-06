/*
 * Copyright 2013 SPZ
 * http://www.opensource.org/licenses/mit-license.php
 */
package woodlouse.crypto.keystorage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * A simple name-value store (essentially a "String to String" HashMap)
 * persistable as an XML document.
 */
public class XmlStore {

   private static final String XML_ROOT = "values";
   private static final String XML_PAIR = "pair";
   private static final String XML_NAME = "name";
   private static final String XML_VALUE = "value";

   private static final String XPATH_PAIR = XML_ROOT + "/" + XML_PAIR;
   private static final String XPATH_PAIR_NAME = XML_NAME;
   private static final String XPATH_PAIR_VALUE = XML_VALUE;

   private final HashMap<String, String> nameValuePairs = new HashMap<String, String>(4);

   /**
    * Create a new initially empty Store.
    */
   public XmlStore() {
      // no-op
   }

   /**
    * Populate a new Store object from an existing on-disk XML representation.
    * 
    * @param f
    *           File from which the Store should be loaded.
    * @throws IOException
    */
   public XmlStore(final File f) throws IOException {
      FileInputStream fis = null;
      Document doc = null;
      try {
         fis = new FileInputStream(f);
         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         DocumentBuilder builder = factory.newDocumentBuilder();

         doc = builder.parse(fis);
      } catch (ParserConfigurationException e) {
         throw new KeyStorageException(e);
      } catch (SAXException e) {
         throw new KeyStorageException(e);
      } finally {
         if (fis != null) {
            try {
               fis.close();
            } catch (Exception ignore) {
            }
         }
      }

      populate(doc);
   }

   /**
    * The same as {@link Map#put(String, String)}.
    * 
    * @param name
    *           a unique key.
    * @param value
    *           a value associated with the name.
    * @return as in {@link Map#put(String, String)}.
    */
   public String put(final String name, final String value) {
      if (name == null) {
         throw new IllegalArgumentException("name == null");
      }
      if (value == null) {
         throw new IllegalArgumentException("value == null");
      }
      return nameValuePairs.put(name, value);
   }

   /**
    * The same as {@link Map#get(String)}.
    * 
    * @param name
    *           a unique key.
    * @return as in {@link Map#get(String)}.
    */
   public String get(final String name) {
      if (name == null) {
         throw new IllegalArgumentException("name == null");
      }
      return nameValuePairs.get(name);
   }

   /**
    * Returns all names (keys) in this Store.
    * 
    * @return
    */
   public Set<String> names() {
      HashSet<String> names = new HashSet<String>(nameValuePairs.keySet());
      return names;
   }

   /**
    * Does what its name suggests.
    * 
    * @param f
    *           File to persist to.
    */
   public void persistToDisk(final File f) {
      try {
         Transformer tf = TransformerFactory.newInstance().newTransformer();
         tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
         tf.setOutputProperty(OutputKeys.INDENT, "yes");
         tf.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
         Result result = new StreamResult(f);
         Source source = new DOMSource(toDocument());
         tf.transform(source, result);
      } catch (KeyStorageException e) {
         throw e;
      } catch (Exception e) {
         throw new KeyStorageException(e);
      }
   }

   private void populate(final Document doc) {
      try {
         XPath xp = XPathFactory.newInstance().newXPath();

         NodeList pairNodes = (NodeList) xp.evaluate(XPATH_PAIR, doc, XPathConstants.NODESET);

         for (int i = 0; i < pairNodes.getLength(); ++i) {
            Node pairNode = pairNodes.item(i);

            Node nameNode = (Node) xp.evaluate(XPATH_PAIR_NAME, pairNode, XPathConstants.NODE);
            Node valueNode = (Node) xp.evaluate(XPATH_PAIR_VALUE, pairNode, XPathConstants.NODE);

            String name = nameNode.getTextContent();
            String value = valueNode.getTextContent();

            nameValuePairs.put(name, value);
         }
      } catch (Exception e) {
         throw new KeyStorageException(e);
      }
   }

   private Document toDocument() {
      try {
         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
         DocumentBuilder builder = factory.newDocumentBuilder();
         Document doc = builder.newDocument();

         // document root element
         Element root = doc.createElement(XML_ROOT);
         doc.appendChild(root);

         for (final Map.Entry<String, String> entry : nameValuePairs.entrySet()) {
            // new pair element
            Element pair = doc.createElement(XML_PAIR);

            // new "name" child element
            Element name = doc.createElement(XML_NAME);
            name.appendChild(doc.createTextNode(entry.getKey()));

            // new "value" child element
            Element value = doc.createElement(XML_VALUE);
            value.appendChild(doc.createTextNode(entry.getValue()));

            // add name/value elements to parent pair
            pair.appendChild(name);
            pair.appendChild(value);

            // add pair element
            root.appendChild(pair);
         }

         return doc;
      } catch (Exception e) {
         throw new KeyStorageException(e);
      }
   }
}
