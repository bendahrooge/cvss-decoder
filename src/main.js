import { BASE_SCORE, TEMPORAL_SCORE, ENVIRONMENTAL_SCORE } from "./criteria.js"

const generate_explation = (
  cvss_vector,
  criteria,
  el,
  colorful,
  printed,
  attributes
) => {
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
      printed[0]++
      columns[criteria[category_label]["_column"]] += `<div>${
        criteria[category_label]["_name"]
      } = <div class="metric metric_long" data-item="${
        printed[0]
      }" style="display: inline; border-bottom: 3px solid ${
        colorful
          ? "hsl(" + ((printed[0] * (360 / attributes)) % 360) + ",100%,50%);"
          : "none"
      };">${criteria[category_label][category_value]}</div></div>`
    }
  }

  if (columns[0].length === 0 && columns[1].length === 0) {
    $(el).append(`<div>No attributes in this category</div>`)
    return
  }

  for (let column of columns) {
    $(el).append(`<div>${column}</div>`)
  }
}

const category_score = (score, severity) => {
  return `<div class="category_score" style="background-color: hsl(${
    (150 - score * 15) % 360
  },100%,50%);">${score} <br /> ${severity}</div>`
}

// @todo @refactor
const decode = (cvss_vector, colorful = true) => {
  if (cvss_vector.length === 0) {
    return
  }

  let score = CVSS31.calculateCVSSFromVector(cvss_vector)

  if (score.success === false) {
    $(".error").html(`An error occurred.
      The error type is ${score.errorType}
      and the metrics with errors are ${score.errorMetrics}
    `)
    $(
      ".base_score, .temporal_score, .environmental_score, .category_score"
    ).html("")
    return
  }

  $(".error").html("")
  $(".category_score").remove()
  $(".colorful").html("")

  let attributes = cvss_vector.split("/")
  let attributesCount = attributes.length
  let printed = [0]

  generate_explation(
    cvss_vector,
    BASE_SCORE,
    $(".base_score"),
    colorful,
    printed,
    attributesCount
  )
  generate_explation(
    cvss_vector,
    TEMPORAL_SCORE,
    $(".temporal_score"),
    colorful,
    printed,
    attributesCount
  )
  generate_explation(
    cvss_vector,
    ENVIRONMENTAL_SCORE,
    $(".environmental_score"),
    colorful,
    printed,
    attributesCount
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

  if (colorful) {
    let colorful_vector = ""

    printed[0] = 0
    for (let element in attributes) {
      console.log(typeof element)
      if (element === "0") {
        colorful_vector += attributes[element]
      } else {
        let [prefix, value] = attributes[element].split(":")
        printed[0]++
        colorful_vector += `/${prefix}:<div class="metric metric_short" data-item="${
          printed[0]
        }" style="display: inline; border-bottom: 3px solid hsl(${
          (printed[0] * (360 / attributesCount)) % 360
        },100%,50%);">${value}</div>`
      }
    }

    $(".colorful").html(`${colorful_vector}`)
  }

  $(".metric").on("mouseenter", (el) => {
    let item_id = $(el.target).attr("data-item")
    $(`.metric[data-item='${item_id}']`).addClass("hover_match")
  })

  $(".metric").on("mouseleave", (el) => {
    let item_id = $(el.target).attr("data-item")
    $(`.metric[data-item='${item_id}']`).removeClass("hover_match")
  })
}

$(document).ready(function () {
  // Update the explanation when the input field changes
  $("#cvss_input").on("change keyup input", (e) => {
    window.location.hash = e.target.value
  })

  // String to decode from the page URL
  if (window.location.hash) {
    $("#cvss_input").val(window.location.hash.substring(1))
    decode(window.location.hash.substring(1))
  }

  // Re-decode when the uri hash changes
  window.addEventListener(
    "hashchange",
    function () {
      $("#cvss_input").val(window.location.hash.substring(1))
      decode(window.location.hash.substring(1), false)
      // $("#cvss_input").blur()
    },
    false
  )

  // Show the colorful version when cursor not in use
  $("#cvss_input").focus(() => {
    $(".colorful").hide()
    decode(window.location.hash.substring(1), false)
  })

  const rerenderColors = () => {
    if ($("#cvss_input").val().length === 0) return
    if ($(".error").text().indexOf("error") > -1) return

    $("#cvss_input").hide()
    $(".colorful").show()
    decode(window.location.hash.substring(1), true)
  }

  $("#cvss_input").on("blur focusout", rerenderColors)
  $("a").on("click", rerenderColors)

  $(".colorful").click(() => {
    $("#cvss_input").show()
    $("#cvss_input").focus()
  })

  // Allow the user to paste their CVSS string right on the page load
  $("#cvss_input").focus()
  $("#cvss_input").select()
})
