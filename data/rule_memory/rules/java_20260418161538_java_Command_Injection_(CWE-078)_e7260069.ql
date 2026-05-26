/**
 * @name Command Injection
 * @description User-controlled data flows into OS command execution.
 * @kind problem
 * @problem.severity error
 * @id java/command-injection
 * @tags security external/cwe/cwe-078
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.lang", "Runtime", "exec") or
        mc.getMethod().hasQualifiedName("java.lang", "ProcessBuilder", "command")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module CmdConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CommandSink }
}

module CmdFlow = TaintTracking::Global<CmdConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CmdFlow::flow(source, sink)
select sink, "Command injection: user-controlled data from $@ flows into OS command.", source, "user input"
