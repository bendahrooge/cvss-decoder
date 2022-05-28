import { BASE_SCORE, TEMPORAL_SCORE, ENVIRONMENTAL_SCORE } from "./criteria.js"

const generate_explation = (cvss_vector, criteria, el) => {
  // Remove spaces
  let vector = cvss_vector.replace(" ", "")

  // Get categories
  let cvss_categories = vector.split("/").slice(1)

  // Clear the explanation region
  $(el).html("")

  // Display an explanation for each category
  let columns = Array(2).fill("")
  for (let category of cvss_categories) {
    let [category_label, category_value] = category.toLowerCase().split(":")
    if (criteria[category_label]) {
      columns[
        criteria[category_label]["_column"]
      ] += `<div class="active">${criteria[category_label]["_name"]} = ${criteria[category_label][category_value]}</div>`
    }
  }

  for (let column of columns) {
    $(el).append(`<div>${column}</div>`)
  }
}

const category_score = (score, severity) => {
  return `<div class="category_score">${score} <br /> ${severity}</div>`
}

const decode = (cvss_vector) => {
  let score = CVSS31.calculateCVSSFromVector(cvss_vector)

  if (score.success === false) {
    $(".error").html(`An error occurred.
      The error type is ${score.errorType}
      and the metrics with errors are ${score.errorMetrics}
    `)
    $(".base_score, .temporal_score, .environmental_score").html("")
    return
  }

  $(".error").html("")
  $(".category_score").remove()
  console.log(score)

  generate_explation(cvss_vector, BASE_SCORE, $(".base_score"))
  generate_explation(cvss_vector, TEMPORAL_SCORE, $(".temporal_score"))
  generate_explation(
    cvss_vector,
    ENVIRONMENTAL_SCORE,
    $(".environmental_score")
  )

  $(".base_title").append(
    category_score(score.baseMetricScore, score.baseSeverity)
  )
  $(".temporal_title").append(
    category_score(score.temporalMetricScore, score.temporalSeverity)
  )
  $(".environmental_title").append(
    category_score(score.environmentalMetricScore, score.environmentalSeverity)
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
    window.location.hash = e.target.value
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
