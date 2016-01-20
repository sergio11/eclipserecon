ls = {}; // ls for LandingShop
ls.init = {};

var $body, $w = $(window), $html = $('html'), $doc = $(document),
    windowLoaded = false, docReady = false,
    $mainHeader, $mainNav, $panel, hasPanel;

ls.resizeHandlers = [];
var resizeTimeout;
function resizeDelay(){
    if (ls.resizeHandlers.length === 0) return;
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(function(){
        for (var i = 0; i < ls.resizeHandlers.length; i++){
            if (typeof ls.resizeHandlers[i] === 'function'){
                ls.resizeHandlers[i].call();
            }
        }
    }, 300);
}
$w.on('resize', resizeDelay);

$(function(){
    $body = $('body');
    docReady = true;
    $mainHeader = $('#main-header');
    $mainNav = $('#main-nav');
    $panel = $('#bx-panel');
    hasPanel = $panel.length;
})
$w.on('load', function(){
    windowLoaded = true;
})

var isFrontend = true;
// Global Settings
var bdSettings = {
    cartView: 'popup',
    // 'popup' is actually modal. Backend renamed it in such way, frontend must follow :(
    // also can be 'page' for on-page slide-up cart

    mainSlFx: 'fxSoftScale', // Main slider effects
    // mainSlFx: 'fxPressAway',
    // mainSlFx: 'fxSideSwing',
    // mainSlFx: 'fxFortuneWheel',
    // mainSlFx: 'fxPushReveal',
    // mainSlFx: 'fxSnapIn',
    // mainSlFx: 'fxLetMeIn',
    // mainSlFx: 'fxStickIt',
    // mainSlFx: 'fxArchiveMe',
    // mainSlFx: 'fxVGrowth',
    // mainSlFx: 'fxSlideBehind',
    // mainSlFx: 'fxSoftPulse',
    // mainSlFx: 'fxEarthquake',
    // mainSlFx: 'fxCliffDiving',

    // modalEff: 'overlay-corner', // Modals effects
    // modalEff: 'overlay-door',
    // modalEff: 'overlay-hugeinc',
    // modalEff: 'overlay-slidedown',
    // modalEff: 'overlay-scale',
    // modalEff: 'overlay-open',
    // modalEff: 'overlay-contentpush',
    // modalEff: 'overlay-contentscale',
    modalEff: 'overlay-simplegenie',

    discountFx: 'fadeInDown', // Promotion blocks effects
    // discountFx: 'flipInX',
    // discountFx: 'bounceInDown',

    tooltipClFx: 'default', // Reviews effects
    // tooltipClFx: 'tooltip-sharp',
    // tooltipClFx: 'tooltip-round-1',
    // tooltipClFx: 'tooltip-round-2',


    settingsClSl: {
        nextButton: '.cli-next-arrow',
        prevButton: '.cli-prev-arrow',
        slidesPerView: 10,
        spaceBetween: 23,
        loop: true
    },
    settingsClSlSm: {
        nextButton: '.cli-next-arrow',
        prevButton: '.cli-prev-arrow',
        slidesPerView: 7,
        spaceBetween: 11,
    },
    settingsClSlXs: {
        nextButton: '.cli-next-arrow',
        prevButton: '.cli-prev-arrow',
        slidesPerView: 3,
        spaceBetween: 11,
        centeredSlides: true,
        slideToClickedSlide: true,
        loop: true,
        onSlideChangeStart: function(){
            cliSlPadding();
        },
        onInit: function(){
            cliSlPadding();
        }
    },
};