package io.github.burakkaygusuz.service;

import io.github.burakkaygusuz.model.Vulnerability;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

  private final List<Vulnerability> vulnerabilities = new CopyOnWriteArrayList<>();

  public synchronized void reportVulnerability(Vulnerability vulnerability) {
    if (vulnerabilities.stream().noneMatch(v -> v.equals(vulnerability))) {
      vulnerabilities.add(vulnerability);
    }
  }

  public List<Vulnerability> getVulnerabilities() {
    return Collections.unmodifiableList(vulnerabilities);
  }

  public List<Vulnerability> getVulnerabilitiesBySeverity() {
    return vulnerabilities.stream()
        .sorted(Comparator.comparing(Vulnerability::getSeverityScore).reversed())
        .toList();
  }

  public Vulnerability getFirstVulnerability() {
    return vulnerabilities.isEmpty() ? null : vulnerabilities.getFirst();
  }

  public Vulnerability getLastVulnerability() {
    return vulnerabilities.isEmpty() ? null : vulnerabilities.getLast();
  }

  public int getVulnerabilityCount() {
    return vulnerabilities.size();
  }

  public void clear() {
    vulnerabilities.clear();
  }
}
