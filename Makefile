
default:
	javac -d classes/ -cp lib/xercesImpl.jar:lib/lucene-snowball-2.4-dev.jar:lib/lucene-queries-2.4-dev.jar:lib/lucene-highlighter-2.4-dev.jar:lib/lucene-core-2.4.0.jar:lib/lucene-analyzers-2.4-dev.jar:lib/bcprov-jdk15-141.jar:$(CLASSPATH) src/edu/iit/ir/lucene/util/*.java src/org/apache/lucene/store/*.java
