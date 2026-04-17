/**
 * @name Unsafe Deserialization (Java)
 * @description User-controlled data flows into ObjectInputStream.readObject,
 *              enabling arbitrary code execution via gadget chains.
 * @kind problem
 * @problem.severity error
 * @id java/unsafe-deserialization
 * @tags security external/cwe/cwe-502
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class DeserSink extends DataFlow::Node {
  DeserSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readObject") or
        mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readUnshared")
      ) and
      this = DataFlow::exprNode(mc.getQualifier())
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructor().hasQualifiedName("java.io", "ObjectInputStream", "<init>") and
      this = DataFlow::exprNode(cie.getArgument(0))
    )
  }
}

module DeserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof DeserSink }
}

module DeserFlow = TaintTracking::Global<DeserConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DeserFlow::flow(source, sink)
select sink, "Unsafe deserialization: user-controlled data from $@ reaches ObjectInputStream.", source, "user input"