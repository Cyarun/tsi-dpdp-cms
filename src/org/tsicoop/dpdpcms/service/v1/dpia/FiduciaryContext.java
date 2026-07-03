package org.tsicoop.dpdpcms.service.v1.dpia;

/**
 * SERVER-derived fiduciary facts the DPIA report attests against — never PII.
 *
 * <p>Verbatim Java port of the {@code FiduciaryContext} dataclass in
 * {@code engine_source/dpia_report.py}. All fields are booleans / masked identifiers the app
 * resolves from config + catalog signals. {@code fiduciaryRef} is a masked suffix (e.g.
 * '...ab12cd'), never a raw fiduciary id or tenant secret.
 *
 * <p>{@code processesChildrenData} is a nullable Boolean: {@code null} = NOT ASSESSED (drives the
 * org-level "children_processing_unassessed" gap), matching the Python {@code Optional[bool]}
 * three-state semantics ({@code None}/{@code True}/{@code False}).
 *
 * <p>Pure value object — no OpenMetadata dependencies, so the engine stays unit-testable in
 * isolation and matches the Python exactly.
 */
public final class FiduciaryContext {

  public final String fiduciaryRef;
  public final boolean isSignificantDataFiduciary;
  public final boolean hasDpo;
  public final boolean hasGrievanceMechanism;
  public final boolean hasAuditor;
  public final boolean hasBreachProcess;
  /** null = not assessed; TRUE/FALSE = assessed outcome. */
  public final Boolean processesChildrenData;
  public final boolean hasConsentManager;

  private FiduciaryContext(Builder b) {
    this.fiduciaryRef = b.fiduciaryRef;
    this.isSignificantDataFiduciary = b.isSignificantDataFiduciary;
    this.hasDpo = b.hasDpo;
    this.hasGrievanceMechanism = b.hasGrievanceMechanism;
    this.hasAuditor = b.hasAuditor;
    this.hasBreachProcess = b.hasBreachProcess;
    this.processesChildrenData = b.processesChildrenData;
    this.hasConsentManager = b.hasConsentManager;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Fluent builder — all fields default to the Python dataclass defaults. */
  public static final class Builder {
    private String fiduciaryRef = "";
    private boolean isSignificantDataFiduciary = false;
    private boolean hasDpo = false;
    private boolean hasGrievanceMechanism = false;
    private boolean hasAuditor = false;
    private boolean hasBreachProcess = false;
    private Boolean processesChildrenData = null; // None = not assessed
    private boolean hasConsentManager = false;

    public Builder fiduciaryRef(String v) {
      this.fiduciaryRef = v == null ? "" : v;
      return this;
    }

    public Builder isSignificantDataFiduciary(boolean v) {
      this.isSignificantDataFiduciary = v;
      return this;
    }

    public Builder hasDpo(boolean v) {
      this.hasDpo = v;
      return this;
    }

    public Builder hasGrievanceMechanism(boolean v) {
      this.hasGrievanceMechanism = v;
      return this;
    }

    public Builder hasAuditor(boolean v) {
      this.hasAuditor = v;
      return this;
    }

    public Builder hasBreachProcess(boolean v) {
      this.hasBreachProcess = v;
      return this;
    }

    public Builder processesChildrenData(Boolean v) {
      this.processesChildrenData = v;
      return this;
    }

    public Builder hasConsentManager(boolean v) {
      this.hasConsentManager = v;
      return this;
    }

    public FiduciaryContext build() {
      return new FiduciaryContext(this);
    }
  }
}
