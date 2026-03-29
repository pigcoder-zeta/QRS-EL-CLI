/**
 * @name Spring EL Injection
 * @description Detects potential Spring Expression Language (EL), OGNL, or MVEL injection vulnerabilities where untrusted input flows into expression evaluation methods.
 * @kind problem
 * @problem.severity error
 * @id java/spring-el-injection
 * @tags security
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class CustomSink extends DataFlow::Node {
  CustomSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("ognl", "Ognl", "getValue") and
        this.asExpr() = mc.getArgument(0)
      )
      or
      (
        mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "eval") and
        this.asExpr() = mc.getArgument(0)
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
select sink, "This Spring EL/OGNL/MVEL expression is constructed from untrusted data, leading to a potential expression injection vulnerability. Data originates from $@.", source, "user-controlled input"