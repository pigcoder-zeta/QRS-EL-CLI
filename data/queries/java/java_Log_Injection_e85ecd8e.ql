/****
 * @name Log Injection (CWE-117)
 * @description User-controlled data flows into logging APIs without neutralization, potentially enabling log injection/forgery.
 * @kind problem
 * @problem.severity warning
 * @id java/log-injection
 * @tags security external/cwe/cwe-117
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class LogSink extends DataFlow::Node {
  LogSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("org.slf4j", "Logger", "info") or
        mc.getMethod().hasQualifiedName("org.slf4j", "Logger", "warn") or
        mc.getMethod().hasQualifiedName("org.slf4j", "Logger", "error") or
        mc.getMethod().hasQualifiedName("java.util.logging", "Logger", "info")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module LogInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof LogSink }
}

module LogInjectionFlow = TaintTracking::Global<LogInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where LogInjectionFlow::flow(source, sink)
select sink, "Log injection (CWE-117): user-controlled data from $@ flows into a log message.", source,
  "user-controlled input"