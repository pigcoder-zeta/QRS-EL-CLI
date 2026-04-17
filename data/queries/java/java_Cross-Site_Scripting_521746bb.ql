/**
 * @name Cross-Site Scripting (Java)
 * @description User-controlled data flows into HTTP response without escaping.
 * @kind problem
 * @problem.severity error
 * @id java/xss
 * @tags security external/cwe/cwe-079
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class XssSink extends DataFlow::Node {
  XssSink() {
    exists(MethodCall mc |
      mc.getNumberOfArguments() > 0 and
      (
        mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "print") or
        mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "println") or
        mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "write") or
        mc.getMethod().hasQualifiedName("javax.servlet", "ServletOutputStream", "print") or
        mc.getMethod().hasQualifiedName("javax.servlet", "ServletOutputStream", "println")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
}

module XssFlow = TaintTracking::Global<XssConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XssFlow::flow(source, sink)
select sink, "XSS: user-controlled data from $@ flows into HTTP response without escaping.", source, "user input"