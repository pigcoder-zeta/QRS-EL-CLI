/**
 * @name Deserialization of Untrusted Data
 * @description User-controlled data flows into deserialization methods, leading to potential arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @id java/deserialization
 * @tags security
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(MethodCall mc |
      // java.io.ObjectInputStream#readObject and readUnshared
      (
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readObject") or
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readUnshared")
      ) and
      this.asExpr() = mc // The method call itself is the sink for these methods
    )
    or
    exists(MethodCall mc |
      // com.fasterxml.jackson.databind.ObjectMapper#readValue
      mc.getMethod().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper", "readValue") and
      this.asExpr() = mc.getArgument(0) // The first argument is the untrusted data
    )
    or
    exists(MethodCall mc |
      // org.yaml.snakeyaml.Yaml#load
      mc.getMethod().hasQualifiedName("org.yaml.snakeyaml", "Yaml", "load") and
      this.asExpr() = mc.getArgument(0) // The first argument is the untrusted data
    )
    or
    exists(MethodCall mc |
      // com.thoughtworks.xstream.XStream#fromXML
      mc.getMethod().hasQualifiedName("com.thoughtworks.xstream", "XStream", "fromXML") and
      this.asExpr() = mc.getArgument(0) // The first argument is the untrusted data
    )
  }
}

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CustomSink }
}

module Flow = TaintTracking::Global<FlowConfig>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Deserialization of untrusted data: user-controlled data from $@ flows into a deserialization method.", source, "user-controlled input"