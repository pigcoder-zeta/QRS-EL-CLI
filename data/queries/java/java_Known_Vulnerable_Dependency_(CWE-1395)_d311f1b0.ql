/**
 * @name Known vulnerable dependency (CWE-1395): calls to high-risk APIs often associated with vulnerable components
 * @description Flags calls to high-risk APIs frequently involved in exploits when present in known vulnerable dependencies or used with untrusted input (expression injection, OGNL/MVEL injection, command execution, SQL execution, unsafe deserialization).
 * @kind problem
 * @problem.severity warning
 * @id java/known-vulnerable-dependency
 * @tags security
 *       external/cwe/cwe-1395
 */
import java

predicate isHighRiskApiCall(MethodCall mc) {
  mc.getMethod().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") or
  mc.getMethod().hasQualifiedName("ognl", "Ognl", "getValue") or
  mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "eval") or
  mc.getMethod().hasQualifiedName("java.lang", "Runtime", "exec") or
  mc.getMethod().hasQualifiedName("java.sql", "Statement", "executeQuery") or
  mc.getMethod().hasQualifiedName("java.io", "ObjectInputStream", "readObject")
}

from MethodCall mc
where isHighRiskApiCall(mc)
select
  mc,
  "调用高风险 API: " +
    mc.getMethod().getDeclaringType().getQualifiedName() + "." + mc.getMethod().getName() +
    "。若该调用来自/依赖于已知漏洞组件或使用不当，可能导致严重安全问题（CWE-1395）。"