/**
 * @name Deserialization
 * @description User-controlled data flows into deserialization methods, leading to potential arbitrary code execution or denial of service.
 * @kind problem
 * @problem.severity error
 * @id java/deserialization
 * @tags security external/cwe/cwe-502
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(MethodCall mc |
      // Sinks where the serialized data is the first argument of a method call
      (
        mc.getMethod().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper", "readValue") or
        mc.getMethod().hasQualifiedName("org.yaml.snakeyaml", "Yaml", "load") or
        mc.getMethod().hasQualifiedName("com.thoughtworks.xstream", "XStream", "fromXML")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    exists(ConstructorCall cc |
      // Sink for ObjectInputStream: the InputStream argument to the constructor
      // This covers the input for subsequent readObject/readUnshared calls.
      cc.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream") and
      this.asExpr() = cc.getArgument(0)
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
select sink, "Deserialization vulnerability: user-controlled data from $@ flows into a deserialization sink.", source, "user-controlled input"