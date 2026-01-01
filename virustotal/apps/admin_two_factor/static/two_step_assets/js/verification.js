// HEMEN ÇALIŞACAK KOD - Eski kodları override et
(function() {
    // Eski AjaxCheckTwoStepVerification fonksiyonunu hemen override et
    window.AjaxCheckTwoStepVerification = function(param) {
        console.warn('AjaxCheckTwoStepVerification çağrıldı - jquery-confirm kontrol ediliyor...');
        
        // jQuery yüklü mü kontrol et
        if (typeof jQuery === 'undefined' || typeof $ === 'undefined') {
            console.error('jQuery yüklenmemiş!');
            return;
        }
        
        var $ = jQuery;
        var url = param['url'] || param.url;
        var $form = param['form'] || param.form || $('#login-form');
        
        $.ajax({
            url: url,
            type: 'POST',
            async: true,
            data: $form.serialize(),
            success: function (data) {
                if (!data.is_valid) {
                    $form.submit();
                } else {
                    // $.confirm'in yüklendiğinden emin ol
                    if (typeof $.confirm !== 'function') {
                        console.error('$.confirm is not a function! jquery-confirm yüklenmemiş olabilir.');
                        // Fallback: prompt kullan
                        var code = prompt('Two Step Verification\n\nVerification Code:');
                        if (code) {
                            $.ajax({
                                url: url,
                                type: 'POST',
                                data: $form.serialize() + '&code=' + code,
                                headers: {
                                    'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || ($.cookie ? $.cookie('csrftoken') : '')
                                },
                                success: function (r) {
                                    if (!r.is_valid) {
                                        alert(r.message || 'Geçersiz kod');
                                        return;
                                    }
                                    $form.submit();
                                }
                            });
                        }
                        return;
                    }
                    
                    // $.confirm kullan
                    $.confirm({
                        title: 'Two Step Verification',
                        content: '' +
                            '<div class="form-group">' +
                            '<label>Verification Code: </label>' +
                            '<input name="code" type="text" placeholder="Code" class="code form-control" required />' +
                            '</div>',
                        type: 'orange',
                        buttons: {
                            verify: function () {
                                var code = this.$content.find('.code').val();
                                if (!code) {
                                    if (typeof $.alert === 'function') {
                                        $.alert('provide a valid code');
                                    } else {
                                        alert('provide a valid code');
                                    }
                                    return false;
                                }

                                $.ajax({
                                    url: url,
                                    type: 'POST',  // PUT yerine POST
                                    async: true,
                                    data: $form.serialize() + "&code=" + code,
                                    headers: {
                                        'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || ($.cookie ? $.cookie('csrftoken') : '')
                                    },
                                    success: function (data) {
                                        if (!data.is_valid) {
                                            if (typeof $.alert === 'function') {
                                                $.alert(data.message);
                                            } else {
                                                alert(data.message);
                                            }
                                            return false;
                                        }
                                        $form.submit();
                                    },
                                    error: function () {
                                        if (typeof $.alert === 'function') {
                                            $.alert('Error occurred');
                                        } else {
                                            alert('Error occurred');
                                        }
                                        return false;
                                    }
                                });
                            },
                            cancel: function () {}
                        },
                    });
                }
            },
            error: function () {
                alert('Error occurred');
            }
        });
    };
    
    // Eski $(document).ready kodunu override et
    if (typeof jQuery !== 'undefined') {
        jQuery(function($) {
            // Eski click handler'ı kaldır
            $('#CheckTwoStep').off('click');
        });
    }
})();

// ANA KOD - IIFE içinde
(function() {
    
    var checkCount = 0;
    var maxChecks = 100;
    
    function init() {
        checkCount++;
        
        // jQuery yüklü mü kontrol et
        if (typeof jQuery === 'undefined' || typeof $ === 'undefined') {
            if (checkCount < maxChecks) {
                setTimeout(init, 50);
            } else {
                console.error('jQuery yüklenemedi!');
            }
            return;
        }
        
        // jquery-confirm yüklü mü kontrol et
        if (typeof jQuery.fn.confirm === 'undefined' && typeof $.confirm === 'undefined') {
            if (checkCount < maxChecks) {
                setTimeout(init, 50);
            } else {
                console.error('jquery-confirm yüklenemedi! jQuery:', typeof jQuery, '$.confirm:', typeof $.confirm);
            }
            return;
        }
        
        console.log('✓ jquery-confirm hazır!');
        // Her şey hazır, event listener'ı ekle
        setupVerification();
    }
    
    function setupVerification() {
        jQuery(function($) {
            
            // Önce tüm eski event listener'ları temizle
            $('#CheckTwoStep').off('click');
            
            // Eski AjaxCheckTwoStepVerification fonksiyonunu override et (eğer varsa)
            if (typeof window.AjaxCheckTwoStepVerification !== 'undefined') {
                window.AjaxCheckTwoStepVerification = function(param) {
                    console.warn('Eski AjaxCheckTwoStepVerification çağrıldı, yeni versiyon kullanılıyor');
                    var url = param['url'] || param.url;
                    var $form = param['form'] || param.form || $('#login-form');
                    
                    $.ajax({
                        url: url,
                        type: 'POST',
                        async: true,
                        data: $form.serialize(),
                        success: function (data) {
                            if (!data.is_valid) {
                                $form.submit();
                            } else {
                                // $.confirm'in yüklendiğinden emin ol
                                if (typeof $.confirm !== 'function') {
                                    console.error('$.confirm is not a function!');
                                    var code = prompt('Two Step Verification\n\nVerification Code:');
                                    if (code) {
                                        $.ajax({
                                            url: url,
                                            type: 'POST',
                                            data: $form.serialize() + '&code=' + code,
                                            headers: {
                                                'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || ($.cookie ? $.cookie('csrftoken') : '')
                                            },
                                            success: function (r) {
                                                if (!r.is_valid) {
                                                    alert(r.message || 'Geçersiz kod');
                                                    return;
                                                }
                                                $form.submit();
                                            }
                                        });
                                    }
                                    return;
                                }
                                
                                $.confirm({
                                    title: 'Two Step Verification',
                                    content: '' +
                                        '<div class="form-group">' +
                                        '<label>Verification Code: </label>' +
                                        '<input name="code" type="text" placeholder="Code" class="code form-control" required />' +
                                        '</div>',
                                    type: 'orange',
                                    buttons: {
                                        verify: function () {
                                            var code = this.$content.find('.code').val();
                                            if (!code) {
                                                if (typeof $.alert === 'function') {
                                                    $.alert('provide a valid code');
                                                } else {
                                                    alert('provide a valid code');
                                                }
                                                return false;
                                            }

                                            $.ajax({
                                                url: url,
                                                type: 'POST',  // PUT yerine POST kullan
                                                async: true,
                                                data: $form.serialize() + "&code=" + code,
                                                headers: {
                                                    'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || ($.cookie ? $.cookie('csrftoken') : '')
                                                },
                                                success: function (data) {
                                                    if (!data.is_valid) {
                                                        if (typeof $.alert === 'function') {
                                                            $.alert(data.message);
                                                        } else {
                                                            alert(data.message);
                                                        }
                                                        return false;
                                                    }
                                                    $form.submit();
                                                },
                                                error: function () {
                                                    if (typeof $.alert === 'function') {
                                                        $.alert('Error occurred');
                                                    } else {
                                                        alert('Error occurred');
                                                    }
                                                    return false;
                                                }
                                            });
                                        },
                                        cancel: function () {}
                                    },
                                });
                            }
                        },
                        error: function () {
                            alert('Error occurred');
                        }
                    });
                };
            }
            
            // Yeni event listener ekle
            $('#CheckTwoStep').on('click', function(e) {
                e.preventDefault();

                const $form = $('#login-form');
                const url = $(this).data('url');

                $.post(url, $form.serialize(), function(res) {

                    if (!res.is_valid) {
                        $form.submit();
                        return;
                    }

                    // $.confirm'in yüklendiğinden emin ol - callback içinde tekrar kontrol et
                    if (typeof $.confirm !== 'function') {
                        console.error('$.confirm is not a function! jquery-confirm plugin yüklenmemiş olabilir.');
                        // Fallback: Eğer $.confirm yoksa normal prompt kullan
                        const code = prompt('Two Step Verification\n\nVerification Code:');
                        if (code) {
                            $.ajax({
                                url: url,
                                type: 'POST',
                                data: $form.serialize() + '&code=' + code,
                                headers: {
                                    'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || ($.cookie ? $.cookie('csrftoken') : '')
                                },
                                success: function (r) {
                                    if (!r.is_valid) {
                                        alert(r.message || 'Geçersiz kod');
                                        return;
                                    }
                                    $form.submit();
                                },
                                error: function() {
                                    alert('Bir hata oluştu. Lütfen tekrar deneyin.');
                                }
                            });
                        }
                        return;
                    }

                    // $.confirm kullan (jquery-confirm plugin)
                    $.confirm({
                        title: 'Two Step Verification',
                        content:
                            '<div class="form-group">' +
                            '<label>Verification Code</label>' +
                            '<input type="text" class="code form-control" required>' +
                            '</div>',
                        buttons: {
                            verify: function () {
                                const code = this.$content.find('.code').val();

                                if (!code) {
                                    if (typeof $.alert === 'function') {
                                        $.alert('Kod giriniz');
                                    } else {
                                        alert('Kod giriniz');
                                    }
                                    return false;
                                }

                                $.ajax({
                                    url: url,
                                    type: 'POST',
                                    data: $form.serialize() + '&code=' + code,
                                    headers: {
                                        'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || ($.cookie ? $.cookie('csrftoken') : '')
                                    },
                                    success: function (r) {
                                        if (!r.is_valid) {
                                            if (typeof $.alert === 'function') {
                                                $.alert(r.message || 'Geçersiz kod');
                                            } else {
                                                alert(r.message || 'Geçersiz kod');
                                            }
                                            return;
                                        }
                                        $form.submit();
                                    },
                                    error: function(xhr, status, error) {
                                        console.error('AJAX Error:', error);
                                        if (typeof $.alert === 'function') {
                                            $.alert('Bir hata oluştu. Lütfen tekrar deneyin.');
                                        } else {
                                            alert('Bir hata oluştu. Lütfen tekrar deneyin.');
                                        }
                                    }
                                });
                            },
                            cancel: function () {}
                        }
                    });
                }).fail(function(xhr, status, error) {
                    console.error('POST Error:', error);
                    // Hata durumunda normal form submit yap
                    $form.submit();
                });
            });
        });
    }
    
    // Başlat
    init();
    
})();
