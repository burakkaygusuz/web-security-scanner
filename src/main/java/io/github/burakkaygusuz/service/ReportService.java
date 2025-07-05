package io.github.burakkaygusuz.service;

import io.github.burakkaygusuz.Vulnerability;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

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
    
    public int getVulnerabilityCount() {
        return vulnerabilities.size();
    }
    
    public void clear() {
        vulnerabilities.clear();
    }
}
