ls.init.settings = function() {
    //$('.mpc_panel').toggle();
    // ^ what it is?.. 

    // Drag-and-drop initialization
    var $dragSections = $('.drag-sections');
    $dragSections.length && dragula($dragSections.get(), {
        removeOnSpill : true,
        moves         : function (el, container, handle) {
            return handle.className === 'd-handle';
        }
    });

    $(':file').filestyle({
        icon         : false,
        buttonText   : 'Browse',
        buttonBefore : true,
        size         : 'sm'
    });
    $('.inp-colorpicker').colorpicker({
        sliders : {
            saturation : {
                maxLeft : 150,
                maxTop  : 135
            },
            hue        : {
                maxTop : 135
            },
            alpha      : {
                maxTop : 135
            }
        }
    });

    $('.nav-themes a').on('click', function (event) {
        event.preventDefault();
        var selected = $(this).attr('href'),
            $linkStyle = $('#theme');

        var filter = /[^-a-zA-Z]/;
        var themeName = selected.replace(filter, '');

        $linkStyle.attr('href', 'styles/css/theme-' + themeName + '.css');

        $(this).addClass('active').siblings('a').removeClass('active');
        
        isFrontend && localStorage.setItem('ls.colorScheme', $(this).attr('href'))
        return false;
    });

    $('.reset-btn').click(function() { localStorage.clear(); });

    $('.sett-width input[type="radio"]').on('change', function(){
        var value = this.value;
        if (value == 'default'){
            $('.wd-cut').removeClass('s-cut');
            $('.drag-sections').removeClass('d-cut');
        } else {
            $('.wd-cut').addClass('s-cut');
            $('.drag-sections').addClass('d-cut');
        }
        isFrontend && localStorage.setItem('ls.blocksWidth', value);
    });
    
    $('.fx-sl').on('change', function(){
        changesSettAnimation('#main-banner', 'mainSlFx', this.value);
        isFrontend && localStorage.setItem('ls.sliderAnimation',this.value);
    });
    $('.fx-modal').on('change', function(){
        changesSettAnimation('.overlay', 'modalEff', this.value);
        isFrontend && localStorage.setItem('ls.modalAnimation', this.value);
    });
    $('.fx-cl').on('change', function(){
        changesSettAnimation('.clients-slider .tooltip-content', 'tooltipClFx', this.value);
        isFrontend && localStorage.setItem('ls.reviewsAnimation',this.value);
    });
    
    $('.fx-disc').on('change', function(){
        changesSettAnimation('.s-discounts .title, .s-discounts .discount-slider', 'discountFx', this.value);
        isFrontend && localStorage.setItem('ls.promoAnimation',this.value);
    });

    $('.fx-item').on('change', function(){
        $('.item').removeClass('fadeInDown').addClass(this.value);
        isFrontend && localStorage.setItem('ls.item-fx', this.value);
    });

    $('.gpt-sett input[name="rad3"]').on('change', function() {
        isFrontend && localStorage.setItem('gpt-sett',this.value);
    });
    
    $('input[name="cart-view"]').on('change', function() {
        var oldVal = bdSettings.cartView,
            newVal = $(this).val(),
            $oldWrap = $('#cartView-' + oldVal),
            $newWrap = $('#cartView-' + newVal),
            content = $oldWrap.html();

        $oldWrap.empty();
        $newWrap.html(content);

        // $('.b-title.text-center.c-white').removeClass('c-white');
        // ^ when popup? why?..

        bdSettings.cartView = newVal;
        updateCartLinks();
        ls.init.cart();
        isFrontend && localStorage.setItem('ls.cartView', bdSettings.cartView);
    });

    if (isFrontend){
        var newVal;
        if (newVal = localStorage.getItem('ls.modalAnimation')) {
            $('.fx-modal').val(newVal).change();
        }
        if (newVal = localStorage.getItem('ls.sliderAnimation')) {
            $('.fx-sl').val(newVal).change();
        }
        if (newVal = localStorage.getItem('ls.promoAnimation')) {
            $('.fx-disc').val(newVal).change();
        }
        if (newVal = localStorage.getItem('ls.reviewsAnimation')) {
            $('.fx-cl').val(newVal).change();
        }
        if (newVal = localStorage.getItem('ls.blocksWidth')) {
            $('input[value="' + newVal + '"]').attr('checked', true).change();
        }
        if (newVal = localStorage.getItem('ls.item-fx')) {
            $('.fx-item').val(newVal).change();
        }
        if (newVal = localStorage.getItem('ls.cartView')) {
            $('input[value="' + newVal + '"]').attr('checked', true).change();
        }
        if (newVal = localStorage.getItem('ls.colorScheme')) {
            $('a[href="' + newVal + '"]').trigger('click');
        }
    }
}