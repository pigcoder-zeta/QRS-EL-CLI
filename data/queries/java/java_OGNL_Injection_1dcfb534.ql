/**
 * @name OGNL Expression Injection
 * @description User-controlled data flows into Ognl.getValue or Ognl.parseExpression,
 *              enabling arbitrary code execution.
 * @kind problem
 * @problem.severity error
 * @id java/ognl-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class OgnlSink extends DataFlow::Node {
  OgnlSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("ognl", "Ognl", "getValue") or
        mc.getMethod().hasQualifiedName("ognl", "Ognl", "parseExpression")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module OgnlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof OgnlSink }
}

module OgnlInjectionFlow = TaintTracking::Global<OgnlInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where OgnlInjectionFlow::flow(source, sink)
select sink,
  "OGNL injection: user-controlled data from $@ flows into OGNL expression evaluator.",
  source, "user-controlled input"