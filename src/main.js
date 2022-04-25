const BASE_SCORE = {
  av: {
    _name: "Attack Vector (AV)",
    n: "Network (N)",
    a: "Adjacent (A)",
    l: "Local (L)",
    p: "Physical (P)",
  },
  ac: { _name: "Attack Complexity (AC)", l: "Low (L)", h: "High (H)" },
  pr: {
    _name: "Privileges Required (PR)",
    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  ui: { _name: "User Interaction (UI)", n: "None (N)", r: "Required (R)" },
  s: { _name: "Scope (S)", u: "Unchanged (U)", c: "Changed (C)" },
  c: {
    _name: "Confidentiality (C)",
    n: "None (N)",
    l: "Low (L)",
    h: "High (H)",
  },
  i: { _name: "Integrity (I)", n: "None (N)", l: "Low (L)", h: "High (H)" },
  a: { _name: "Availability (A)", n: "None (N)", l: "Low (L)", h: "High (H)" },
}

const generate_explation = (cvss_vector) => {
  // Remove spaces
  let vector = cvss_vector.replace(" ", "")

  // Get categories
  let cvss_categories = vector.split("/").slice(1)

  // Clear the explanation region
  $(".cvss_explaination").html("")

  // Display an explanation for each category
  for (category of cvss_categories) {
    let [category_label, category_value] = category.toLowerCase().split(":")
    if (BASE_SCORE[category_label]) {
      $(".cvss_explaination").append(
        `<div>${BASE_SCORE[category_label]["_name"]} = ${BASE_SCORE[category_label][category_value]}</div>`
      )
    }
  }

  let score = CVSS31.calculateCVSSFromVector(vector)

  console.log(score)

  var result
  if (score.success === true) {
    result =
      "Base score is " +
      score.baseMetricScore +
      ". " +
      "Base severity is " +
      score.baseSeverity +
      ". " +
      "Temporal score is " +
      score.temporalMetricScore +
      ". " +
      "Temporal severity is " +
      score.temporalSeverity +
      ". " +
      "Environmental score is " +
      score.environmentalMetricScore +
      ". " +
      "Environmental severity is " +
      score.environmentalSeverity +
      ". " +
      "Vector string is " +
      score.vectorString +
      ". "
  } else {
    result =
      "An error occurred. The error type is '" +
      score.errorType +
      "' and the metrics with errors are " +
      score.errorMetrics +
      "."
  }

  $(".error").html(result)
}

$(document).ready(function () {
  // Pull last string from browser cache
  let cached_cvss = localStorage.getItem("cvss_vector_cache")
  if (cached_cvss) {
    $("#cvss_input").val(cached_cvss)
    generate_explation(cached_cvss)
  }

  // Allow the user to paste their CVSS string on page load
  $("#cvss_input").focus()
  $("#cvss_input").select()

  $("#cvss_input").on("change keyup input", (e) => {
    localStorage.setItem("cvss_vector_cache", e.target.value)
    generate_explation(e.target.value)
  })
})
