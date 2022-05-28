const BASE_SCORE = {
  av: {
    _name: "Attack Vector (AV)",
    _column: 0,

    n: "Network (N)",
    a: "Adjacent (A)",
    l: "Local (L)",
    p: "Physical (P)",
  },
  ac: {
    _name: "Attack Complexity (AC)",
    _column: 0,

    l: "Low (L)",
    h: "High (H)",
  },
  pr: {
    _name: "Privileges Required (PR)",
    _column: 0,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  ui: {
    _name: "User Interaction (UI)",
    _column: 0,

    n: "None (N)",
    r: "Required (R)",
  },
  s: {
    _name: "Scope (S)",
    _column: 1,

    u: "Unchanged (U)",
    c: "Changed (C)",
  },
  c: {
    _name: "Confidentiality (C)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  i: {
    _name: "Integrity (I)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  a: {
    _name: "Availability (A)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
}

const TEMPORAL_SCORE = {
  e: {
    _name: "Exploit Code Maturity (E)",
    _column: 0,

    x: "Not Defined (X)",
    u: "Unproven (U)",
    p: "Proof-of-Concept (P)",
    f: "Functional (F)",
    h: "High (H)",
  },
  rl: {
    _name: "Remediation Level (RL)",
    _column: 0,

    x: "Not Defined (X)",
    o: "Offical Fix (O)",
    t: "Temporary Fix (T)",
    w: "Workaround (W)",
    u: "Unavailable (U)",
  },
  rc: {
    _name: "Report Confidence (RC)",
    _column: 0,

    x: "Not Defined (X)",
    u: "Unknown (U)",
    r: "Reasonable (R)",
    c: "Confirmed (C)",
  },
}

const ENVIRONMENTAL_SCORE = {
  cr: {
    _name: "Confidentiality Requirement (CR)",
    _column: 0,

    x: "Not Defined (X)",
    l: "Low (L)",
    m: "Medium (M)",
    h: "High (H)",
  },
  ir: {
    _name: "Integrity Requirement (IR)",
    _column: 0,

    x: "Not Defined (X)",
    l: "Low (L)",
    m: "Medium (M)",
    h: "High (H)",
  },
  ar: {
    _name: "Availability Requirement (AR)",
    _column: 0,

    x: "Not Defined (X)",
    l: "Low (L)",
    m: "Medium (M)",
    h: "High (H)",
  },
  mav: {
    _name: "Modified Attack Vector (MAV)",
    _column: 1,

    x: "Not Defined (X)",
    n: "Network (N)",
    a: "Adjacent Network (A)",
    l: "Local (L)",
    p: "Physical (P)",
  },
  mac: {
    _name: "Modified Attack Complexity (MAC)",
    _column: 1,

    l: "Low (L)",
    h: "High (H)",
  },
  mpr: {
    _name: "Modified Privileges Required (MPR)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  mui: {
    _name: "Modified User Interaction (MUI)",
    _column: 1,

    n: "None (N)",
    r: "Required (R)",
  },
  ms: {
    _name: "Modified Scope (MS)",
    _column: 1,

    u: "Unchanged",
    c: "Changed",
  },
  mc: {
    _name: "Modified Confidentiality (MC)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  mi: {
    _name: "Modified Integrity (MI)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  ma: {
    _name: "Modified Availablity (MA)",
    _column: 1,

    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
}

export { BASE_SCORE, TEMPORAL_SCORE, ENVIRONMENTAL_SCORE }
