jQuery(document).ready(function($) {
    $('.nav-tab').click(function(e) {
        e.preventDefault();
        $('.nav-tab').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');
        $('.tab-content').hide();
        $($(this).attr('href')).show();
    });
    $('#test-smtp').click(function() {
        var email = $('#test-email').val();
        $('#smtp-test-result').text(maxsysAjax.strings.testing);
        $.ajax({
            url: maxsysAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'maxsys_test_smtp',
                nonce: maxsysAjax.nonce,
                test_email: email
            },
            success: function(response) {
                $('#smtp-test-result').text(response.data);
            },
            error: function(response) {
                $('#smtp-test-result').text(maxsysAjax.strings.error + ' ' + (response.responseJSON?.data || 'Unknown error'));
            }
        });
    });
    $('#clear-rate-limits').click(function() {
        if (confirm(maxsysAjax.strings.confirm_clear)) {
            $.ajax({
                url: maxsysAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'maxsys_clear_rate_limits',
                    nonce: maxsysAjax.nonce
                },
                success: function(response) {
                    alert(response.data);
                },
                error: function(response) {
                    alert(maxsysAjax.strings.error + ' ' + (response.responseJSON?.data || 'Unknown error'));
                }
            });
        }
    });
});
