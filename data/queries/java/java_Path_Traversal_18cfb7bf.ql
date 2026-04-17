/****
 * @name Path Traversal
 * @description User-controlled path flows into file access without canonicalization.
 * @kind problem
 * @problem.severity error
 * @id java/path-traversal
 * @tags security external/cwe/cwe-022
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class PathSink extends DataFlow::Node {
  PathSink() {
    exists(ConstructorCall cc |
      (
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") or
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileOutputStream") or
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "File")
      ) and
      this.asExpr() = cc.getArgument(0)
    )
    or
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.nio.file", "Paths", "get") or
        mc.getMethod().hasQualifiedName("java.nio.file", "Files", "readAllBytes") or
        mc.getMethod().hasQualifiedName("java.nio.file", "Files", "newInputStream")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module PathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof PathSink }
}

module PathFlow = TaintTracking::Global<PathConfig>;

from DataFlow::Node source, DataFlow::Node sink
where
  source instanceof RemoteFlowSource and
  sink instanceof PathSink and
  PathFlow::flow(source, sink)
select sink, "Path traversal: user-controlled path from $@ flows into file access.", source, "user input"