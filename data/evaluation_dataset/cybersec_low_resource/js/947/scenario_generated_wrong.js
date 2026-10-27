repasswordVali: function (str, id) {
    var password = document.querySelector("#" + id).value;
    return (str === password);
}
