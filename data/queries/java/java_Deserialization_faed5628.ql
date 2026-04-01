/**
 * @name Deserialization of Untrusted Data
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
      // Sinks where the argument is the vulnerable part
      (
        mc.getMethod().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper", "readValue") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("org.yaml.snakeyaml", "Yaml", "load") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("com.thoughtworks.xstream", "XStream", "fromXML") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      // Sinks where the method call itself is the vulnerable part (e.g., readObject takes no args, but processes data from its stream)
      (
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readObject") and
        this.asExpr() = mc
      )
      or
      (
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readUnshared") and
        this.asExpr() = mc
      )
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
select sink, "Deserialization of untrusted data from $@ flows into a deserialization method.", source, "用户可控输入"