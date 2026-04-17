/**
 * @name Insecure randomness
 * @description Detects use of non-cryptographically-secure random number generation APIs (CWE-330), such as java.util.Random and java.lang.Math.random.
 * @kind problem
 * @problem.severity warning
 * @id java/insecure-randomness
 * @tags security external/cwe/cwe-330
 */
import java

from MethodCall mc
where
  mc.getMethod().hasQualifiedName("java.util", "Random", "nextInt") or
  mc.getMethod().hasQualifiedName("java.util", "Random", "nextLong") or
  mc.getMethod().hasQualifiedName("java.lang", "Math", "random")
select mc,
  "Insecure randomness (CWE-330): call to '" + mc.getMethod().getName() +
  "' is not cryptographically secure. Consider using java.security.SecureRandom for security-sensitive values."