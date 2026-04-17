/**
 * @name Weak cryptography: broken or risky algorithm
 * @description Detects use of broken or risky cryptographic algorithms and modes (MD5, SHA-1, DES, and ECB mode) (CWE-327).
 * @kind problem
 * @problem.severity warning
 * @id java/weak-cryptography
 * @tags security external/cwe/cwe-327 cryptography
 */
import java

predicate isInsecureDigestAlgorithm(string alg) {
  exists(CompileTimeConstantExpr c |
    c.getStringValue() = alg and
    alg.regexpMatch("(?i)^(MD5|SHA-1)$")
  )
}

predicate isInsecureCipherTransform(string tr) {
  exists(CompileTimeConstantExpr c |
    c.getStringValue() = tr and
    (
      tr.regexpMatch("(?i).*\\bDES\\b.*") or
      tr.regexpMatch("(?i).*/ECB(/.*)?$") or
      tr.regexpMatch("(?i).*\\bECB\\b.*")
    )
  )
}

from MethodCall mc, string v
where
  (
    mc.getMethod().hasQualifiedName("java.security", "MessageDigest", "getInstance") and
    mc.getArgument(0) instanceof CompileTimeConstantExpr and
    isInsecureDigestAlgorithm(mc.getArgument(0).(CompileTimeConstantExpr).getStringValue()) and
    v = mc.getArgument(0).(CompileTimeConstantExpr).getStringValue()
  )
  or
  (
    mc.getMethod().hasQualifiedName("javax.crypto", "Cipher", "getInstance") and
    mc.getArgument(0) instanceof CompileTimeConstantExpr and
    isInsecureCipherTransform(mc.getArgument(0).(CompileTimeConstantExpr).getStringValue()) and
    v = mc.getArgument(0).(CompileTimeConstantExpr).getStringValue()
  )
select mc, "Use of broken or risky cryptographic algorithm/mode (CWE-327): " + v + "."