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

const generate_explation = (cvss_vector, criteria, el) => {
  // Remove spaces
  let vector = cvss_vector.replace(" ", "")

  // Get categories
  let cvss_categories = vector.split("/").slice(1)

  // Clear the explanation and error regions
  $(el).html("")
  // $(".error").html("")

  // Display an explanation for each category
  let columns = Array(2).fill("")
  for (category of cvss_categories) {
    let [category_label, category_value] = category.toLowerCase().split(":")
    if (criteria[category_label]) {
      columns[
        criteria[category_label]["_column"]
      ] += `<div class="active">${criteria[category_label]["_name"]} = ${criteria[category_label][category_value]}</div>`
    }
  }

  for (column of columns) {
    $(el).append(`<div>${column}</div>`)
  }

  // let score = CVSS31.calculateCVSSFromVector(vector)

  // if (score.success === false) {
  //   $(".error").html(`An error occurred.
  //     The error type is ${score.errorType}
  //     and the metrics with errors are ${score.errorMetrics}
  //   `)
  // }
}

const decode = (cvss_vector) => {
  generate_explation(cvss_vector, BASE_SCORE, $(".base_score"))
  generate_explation(cvss_vector, TEMPORAL_SCORE, $(".temporal_score"))
  generate_explation(
    cvss_vector,
    ENVIRONMENTAL_SCORE,
    $(".environmental_score")
  )
}

$(document).ready(function () {
  // Pull last string from browser cache
  // let cached_cvss = localStorage.getItem("cvss_vector_cache")
  // if (cached_cvss) {
  //   $("#cvss_input").val(cached_cvss)
  //   decode(cached_cvss)
  // }

  // Update the explanation when the input field changes
  $("#cvss_input").on("change keyup input", (e) => {
    localStorage.setItem("cvss_vector_cache", e.target.value)
    decode(e.target.value)

    // window.history.pushState(null,null,'https://stackoverflow.com/bkah');
  })

  // String to decode from the page URL
  if (window.location.hash) {
    $("#cvss_input").val(window.location.hash.substring(1))
    decode(window.location.hash.substring(1))
  }

  // Allow the user to paste their CVSS string right on the page load
  $("#cvss_input").focus()
  $("#cvss_input").select()
})
