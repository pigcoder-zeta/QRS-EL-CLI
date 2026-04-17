/**
 * @name SQL Injection
 * @description User-controlled data flows into a SQL query without parameterization.
 * @kind problem
 * @problem.severity error
 * @id java/sql-injection
 * @tags security external/cwe/cwe-089
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.sql", "Statement", "executeQuery") or
        mc.getMethod().hasQualifiedName("java.sql", "Statement", "execute") or
        mc.getMethod().hasQualifiedName("java.sql", "Statement", "executeUpdate") or
        mc.getMethod().hasQualifiedName("java.sql", "Connection", "prepareStatement") or
        mc.getMethod().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate", "queryForObject") or
        mc.getMethod().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate", "query")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecuteSink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SqlFlow::flow(source, sink)
select sink, "SQL injection: user-controlled data from $@ flows into SQL query.", source, "user input"
