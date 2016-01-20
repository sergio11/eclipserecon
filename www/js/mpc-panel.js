var $devices = $('#mpc_device'),
    $preview = $('#mpc_preview');

$devices.on('click', 'a', function (e) {
    e.preventDefault();

    var $this = $(this);

    if ($this.is('.active'))
        return false;

    $devices.children().removeClass('active');
    $this.addClass('active');

    if ($this.is('#mpc_desktop'))
        $preview.attr('class', '').addClass('desktop-view');
    else if ($this.is('#mpc_tablet'))
        $preview.attr('class', '').addClass('tablet-view');
    else if ($this.is('#mpc_phone'))
        $preview.attr('class', '').addClass('phone-view');
});

var $current = $('#mpc_product_select span'),
    $select = $('#mpc_product_list'),
    $preview = $('#mpc_preview'),
    $removeFrame = $('#mpc_remove_frame a'),
    $purchase = $('#mpc_purchase a');

$select.on('mouseenter', 'a', function(e) {
    var $this = $(this);

    if(!$this.is('.loaded')) {
        var $img = $this.find('img'),
            $temp = $('<img>');

        $temp.on('load', function() {
            $img.attr('src', $img.attr('data-src'));
            $this.addClass('loaded');
        }).attr('src', $img.attr('data-src'));
    }
});

$select.on('click', 'a', function(e) {
    e.preventDefault();

    var $this = $(this);

    if($this.is('.active')) {
        return;
    }

    $select.find('a').removeClass('active');
    $this.addClass('active');

    $current.text($this.children('.name').text());
    document.title = $current.text() + ' | mpcreation';

    $removeFrame.attr('href', $this.attr('data-product-url'));
    $purchase.attr('href', $this.attr('data-purchase-url'));
    $preview.attr('src', $this.attr('data-product-url'));
});

var $list = $('#mpc_product_select'),
    $products = $('#mpc_product_list > ul');

$list.on('click', function(e) {
    e.stopPropagation();

    if($products.is('.visible'))
        $products.removeClass('visible');
    else
        $products.addClass('visible');

    $products.one('mouseleave', function() {
        $products.removeClass('visible');
    });
    $products.one('click', function() {
        $products.removeClass('visible');
    });
    $products.one('click', function() {
        $products.removeClass('visible');
    });
});

//function that hides mpc_panel and increases body
function deleteMPC() { 
    $('body').css('height',$(window).height()+$('.mpc_panel').height()+'px');
    $('.mpc_panel').css('display','none');
}


//function to automate deleteMPC()
function autoMPC() {
    if($(document).width()<768) {
        $('.mpc_panel').addClass('hidden');
        $('body').css('height',$('body').height()+$('.mpc_panel').height()+'px');
    }
    else if($(document).width()>767){
        $('.mpc_panel').removeClass('hidden');
    }
}
$(document).ready(function() {
    autoMPC();
});
$(window).resize(function() {
    if($('.mpc_panel').css('display')=='none') deleteMPC();
    autoMPC();
});