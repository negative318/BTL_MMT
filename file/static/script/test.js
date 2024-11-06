$(document).ready(function() {
    $('#eye').click(function() {
        $(this).toggleClass('open');
        $(this).children('i').toggleClass('fa-eye-slash fa-eye');

        const inputField = $(this).prev('input');

        if ($(this).hasClass('open')) {
            inputField.attr('type', 'text'); 
        } else {
            inputField.attr('type', 'password'); 
        }
    });
});
