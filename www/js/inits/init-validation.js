function changeClassEmail(_this,changeSubmit){
	var showNotice = function(hide){
		var $helpBlock = $(_this).parents('.form-group:first').find('.help-block');
		if ($helpBlock.size()<1)
			$(_this).parents('.form-group:first').append('<div class="help-block"></div>');

		if (!hide)
			$helpBlock.html($(_this).data('notice') ? $(_this).data('notice') : 'The field is required!');
		else
			$helpBlock.html('');
	};
	if (changeSubmit === undefined){
		_this = this;
		changeSubmit = true;
	}
	if (_this.value){
		if (!vea.validateEmail(_this.value)){
			$(_this).parent().addClass('has-error');
			$(_this).parent().removeClass('has-success');
			showNotice();
		} else {
			$(_this).parent().removeClass('has-error');
			$(_this).parent().addClass('has-success');
			showNotice(true);
		}
	} else $(_this).parent().removeClass('has-error');

	if (changeSubmit){
		if ($(_this).parent().hasClass('has-error')){
			disableSubmit($(_this).parents('form:first'));
			showNotice();
		} else {
			// $(_this).parents('form:first').find('[type=submit]').attr('disable',false)
			enableSubmit($(_this).parents('form:first'));
			showNotice(true);
		}
	}
};

function disableSubmit(form){ // failed validation handler
	$(form).find('button[type=submit]:first').attr('disabled', true);
	if (oldIE && !fixSubmitFormOldIE){
		$(form).submit(function(){ return false; });
		$(form).find('button[type=submit]:first').click(function(){return false;});
		fixSubmitFormOldIE=true;
	}
};

function enableSubmit(form){
	$(form).find('button[type=submit]:first').attr('disabled', false);
	if (oldIE && fixSubmitFormOldIE){
		$(form).unbind('submit');
		$(form).find('button[type=submit]:first').unbind('click').attr('disabled',false);
		fixSubmitFormOldIE = false;
	}
};

function initValidation($form,formValidateName) {
	//if not required whatever should check format and show notice
	if (!$form.find('input[type=email]').attr('required')){
		$form.find('input[type=email]').keyup(function () {
			changeClassEmail(this, false);
		}).blur(function () {
			changeClassEmail(this, false);
		});
	}
		
	////////////plugin-validation-form
	vea.validateForm({
		form            : formValidateName,
		required        : '[required]',
		submit          : '[type=submit]',
		passNeed        : false,
		errorForm       : disableSubmit,             //(runs once per cycle)
		successValidate : enableSubmit,
		errorInput      : function (input, fail) {   //required field every bypass handler
			var testNumberPhone = false;
			var $parent = $(input).parents('.form-group'),
				$notice = $parent.find('.help-block');    // notice about "wtf is wrong"

			//separately process phone. It's necessary to calculate amount of digits
			if ($(input).hasClass('form-tel')) {
				var numbers = input.value.replace(/\D/g, '');
				var codeLength = 11;
				if (device.mobile() || device.tablet()) {
					if ($parent.find('select option:selected').data('dial-code') > 99) codeLength = 12;
				} else {
					if ($parent.find('.country.active').data('dial-code') > 99) codeLength = 12;
				}
				if (numbers.length < codeLength) testNumberPhone = true;
			}


			if (fail || testNumberPhone) {
				$parent.addClass('has-error');
				$parent.removeClass('has-success');

				if ($notice.size() < 1) {
					var div = document.createElement('DIV');
					div.innerHTML = $(input).data('notice') ? $(input).data('notice') : 'Поле обязательно для заполнения!';
					div.className = 'help-block';
					$parent.append(div);
				} else $notice.removeClass('hidden');
			} else {
				$parent.addClass('has-success');
				$parent.removeClass('has-error');
				if ($notice.size() > 0) $notice.addClass('hidden');
			}

			if (testNumberPhone) return false;
		}
	});
};

ls.init.validation = function(){
	var formValidateName = 'form.form-req',
		$form = $(formValidateName),
		fixSubmitFormOldIE = false;
	if (!$form.length) return;

	$('#main-slider input[type=email]').keyup(changeClassEmail).blur(changeClassEmail);
	initValidation($form,formValidateName);
}