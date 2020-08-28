setInterval("play()", 2000);
function play() {
  $("#rank_box")
    .delay(3000)
    .animate({ top: -40 }, function () {
      $("#rank_box p:first").appendTo("#rank_box");
      $("#rank_box").css({ top: 0 });
    });
}
