<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
if(!class_exists('OtpLoginFront'))
{
    class OtpLoginFront {
        /**
         * Construct the plugin object
         */
        public function __construct()  {
			// Is enable settings from admin
			$isEnable = get_option('otpl_enable') ? get_option('otpl_enable') : 0;
			if(!$isEnable){
			return;
			}
           	//front-end hooks action
			add_action('wp_footer', array(&$this,'otpl_popup_html') );
			add_action( 'wp_ajax_nopriv_otplaction', array(&$this, 'otpl_login_action') );
			add_action( 'wp_enqueue_scripts', array( &$this, 'otpl_enqueue_scripts_hooks') );
			//add_action( 'wp_ajax_otplaction', array(&$this, 'otpl_login_action') );
			
			add_shortcode( 'otp_login', array( &$this,'otp_login_func') );


        } // END public function __construct
        
            public function otp_login_func( $atts ) {
                
                $title = isset( $atts['title'] ) ? $atts['title'] : 'Login with OTP' ;
                
                $button  = '<span class="otplogin-shortcode otpl-popup"><a href="javascript:">'.$title.'</a></span>';
                
        	        return $button;
             }
            public function otpl_enqueue_scripts_hooks() {
            
            //check user logged or not
			if(is_user_logged_in())
			return;
			
			$otplscript = ' jQuery(document).ready(function() {
			
				jQuery(document).on("click", "#otpl_lightbox .close span", function() { jQuery("#otpllightbox").html("");jQuery("#otpl_lightbox").hide().fadeOut(1000);});
			
			
			jQuery(document).on("submit", "#optl-form", function(event) {
				var formid = "#optl-form";
				event.preventDefault(); //prevent default action 
				var email = jQuery("#optl-form #email").val();
				var email_otp = jQuery("#optl-form #email_otp").val();
				var regex = /^([a-zA-Z0-9_\.\-\+])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
				if(!regex.test(email))
				{
				jQuery(".emailerror").text(" Invalid Email");
				return false;
				}else{
				//jQuery("#cl-login #email").removeAttr("disabled");
				jQuery(".emailerror").text("");
				}
					var post_url = "'.admin_url( 'admin-ajax.php' ).'"; //get form action url
					var request_method = jQuery(formid).attr("method"); //get form GET/POST method
					var form_data = jQuery(formid).serialize()+ "&action=otplaction&validateotp=0"; //Encode form elements for submission
					jQuery.ajax({
						url : post_url,
						type: request_method,
						data : form_data,
						cache: false,             
						processData: false, 
					}).done(function(response){ 
						var data = JSON.parse(response);
									   var divclass = "error text-danger";
									   if(data.sendotp){
									   divclass = "success text-success";
									   jQuery("#sendotp").hide();jQuery("#submitotpsec").show();
									   jQuery(formid+" #submitotpsec #email_otp").val("");
									   jQuery("#submitotpsec #sbmitedemail").text(email);
									   jQuery(formid+" .otpestatus").addClass(divclass).show("slow").html("").html(data.message);
									   }else{
									   jQuery(formid+" .emailerror").addClass(divclass).show().html("").html(data.message);
									   console.log(data.response);
									   }
									   
					});
				});
				//validate otp
				jQuery(document).on("click", "#submitOtp", function(event){
				var formid = "#optl-form";
				event.preventDefault(); //prevent default action 
				var email = jQuery("#optl-form #email").val();
				var email_otp = jQuery("#optl-form #email_otp").val();
				var compare=/^[0-9]{1,6}$/g;
				if(email_otp=="" || !compare.test(email_otp))
				{
				jQuery(".otperror").html(" Invalid OTP");
				return false;
				}else{
				//jQuery("#optl-form #email_otp").removeAttr("disabled");
				jQuery(".otperror").html("");
				}
					var form_data = jQuery(formid).serialize()+ "&action=otplaction&validateotp=1";
					jQuery(formid+" #submitotp #email_otp").val("");
					jQuery.ajax({
						url : "'.admin_url( 'admin-ajax.php' ).'",
						type: "POST",
						data : form_data,
						cache: false,             
						processData: false, 
					}).done(function(response){ //
						var data = JSON.parse(response);
						jQuery("#submitotpsec #email_otp").val("");
									   if(data.status)
									   {
									   divclass = "success text-success";
									   jQuery(".otpestatus").html(data.message);
									   var redirecturl = data.redirect;
									   if(typeof redirecturl !== "undefined")
									   {
										 document.location.href = redirecturl;
									   }
									   }else{
									   jQuery(".otpestatus").html(" Invalid OTP");
									   }
									   
					});
				});
				jQuery(document).on("click", ".loginback",function(){
				jQuery("#optl-form #email").val("");jQuery("#submitotpsec #email_otp").val("");
				jQuery(".emailerror").html("");
				jQuery(".otperror").html("");
				jQuery(".otpestatus").html("");
				jQuery("#sendotp").show();
				jQuery("#submitotpsec").hide();
				});
				
				jQuery(".otpl-popup a").click(function(e) {
					e.preventDefault();
					var content =jQuery("#otpl_contact").html();
							var otpl_lightbox_content = 
							"<div id=\"otpl_lightbox\">" +
								"<div id=\"otpl_content\">" +
								"<div class=\"close\"><span></span></div>"  + content  +
								"</div>" +	
							"</div>";
							//insert lightbox HTML into page
							jQuery("#otpllightbox").append(otpl_lightbox_content).hide().fadeIn(1000);
				});
			    
			});';
			
            
            wp_add_inline_script( 'jquery-core', $otplscript );
            
            // CSS 
            $otplcss = 'body.logged-in .otpl-popup { display: none; } form#optl-form {position: relative;}#otpl-body {background: #f9f9f9;padding: 3rem;}#submitotpsec{display:none;}#otpl_lightbox #otpl_content form label{color:#000;display:block;font-size:18px;}span.loginback {cursor: pointer;z-index: 99;top: 6px;position: absolute;left: 0px;padding: 2px 15px;color: #e96125;}#otpl_lightbox #otpl_content form .req{color:red;font-size:14px; display:inline-block;}#otpl_lightbox #otpl_content form input,#otpl_lightbox #otpl_content form textarea{border:1px solid #ccc;color:#666!important;display:inline-block!important;width:100%!important; min-height:40px;padding:0px 10px;}#otpl_lightbox #otpl_content form input[type=submit]{background: #E73E34;color: #FFF !important;font-size: 100% !important;font-weight: 700 !important;width: 100% !important;padding: 10px 0px;margin-top: 10px;}#otpl_lightbox #otpl_content form #submitotpsec input[type=submit].generateOtp {cursor: pointer;  text-decoration: underline;background: none !important; border: 0px; color: #E73E34 !important; padding: 0px; outline: none; }#otpl_lightbox #otpl_content form input[type="submit"]:disabled {background: #ccc;cursor: initial;}#otpl_lightbox #otpl_content form input.cswbfs_submit_btn:hover{background:#000;cursor:pointer}#otpl_lightbox .close {cursor: pointer; position: absolute; top: 10px; right: 10px; left: 0px; z-index: 9;}@media (max-width:767px){#otpl-body {padding: 1rem;}#otpl_lightbox #otpl_content{width:90%}#otpl_lightbox #otpl_content p{font-size:12px!important}}@media (max-width:800px) and (min-width:501px){#otpl_lightbox #otpl_content{width:70%}#otpl_lightbox #otpl_content p{font-size:12px!important}}@media (max-width:2200px) and (min-width:801px){#otpl_lightbox #otpl_content{width:60%}#otpl_lightbox #otpl_content p{font-size:15px!important}}#otpl_lightbox{position:fixed;top:0;left:0;width:100%;height:100%;background:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAA9JREFUeNpiYGBg2AwQYAAAuAC01qHx9QAAAABJRU5ErkJggg==);text-align:center;z-index:999999!important;clear:both}#otpl_lightbox #otpl_content{background: #FFF;color: #666;margin: 10% auto 0;position: relative;z-index: 999999;padding: 0px;font-size: 15px !important;height: 250px;overflow: initial;max-width: 450px;}#otpl_lightbox #otpl_content p{padding:1%;text-align:left;margin:0!important;line-height: 20px;}#otpl_lightbox #otpl_content .close span{background:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABmJLR0QA/wD/AP+gvaeTAAAAjklEQVRIie2Vyw2AIBQER3uQaIlarhwsRy+Y4AfCPuTmnEx0dwg+FH4MzIAz5FzIZlmAHfCixIXMHjqSDMAaHtyAqaD8nhnVQE4ilysSc3mJpLo8J/ms/CSeEH+7tozzK/GqpZX3FdKuInuh6Ra9vVDLYSwuT92TJSWjaJYocy5LLIdIkjT/XEPjH87PgwNng1K28QMLlAAAAABJRU5ErkJggg==) right 0 no-repeat;display:block;float:right;height:36px;height:36px;width:100%}#otpl_lightbox #otpl_content .close span:hover,#otpl_lightbox .otplmsg:hover{cursor:pointer}#otpl_lightbox .heading {padding: 10px 5px;margin: 0 !important;}#otpl_lightbox .heading h3{font-size:1.5rem;} span.otplogin-shortcode.otpl-popup {border: 1px solid #ccc;padding: 8px 10px;border-radius: 10px;}';
            
            			 // register css  
			 wp_register_style( 'otpl-inlinecss', false );
			 wp_enqueue_style( 'otpl-inlinecss' );
			 wp_add_inline_style( 'otpl-inlinecss', $otplcss );
			 
        }
        /**
		 * @hooks wp_footer
		 * hook to add html into site footer
		 */		
		 public function otpl_popup_html(){
			//check user logged or not
			if(is_user_logged_in()) {
				return;
				}
				
			$enableLogin = get_option('otpl_enable') ? get_option('otpl_enable') : 0;
			
			$registerURL = get_option('otpl_register_url') ? get_option('otpl_register_url') : '';
			
			$otplFormHtml = '';
			//if($enableLogin):
			$otplFormHtml .='<div id="otpllightbox"></div>';
			$otplFormHtml .='<div id="otplBox" style="display:none">';
			$otplFormHtml .='<div id="otpl_contact">
				  <div class="otplmsg"></div>';
				  
			//check external url or not
			 $otplFormHtml .= '<form name="clfrom" id="optl-form" class="otpl-section" action="" method="post" novalidate autocomplete="off" role="form" >';
			 // secutiry + honeypot captcha
			 $otplFormHtml .= '<div style="display:none;">'; 
			 $otplFormHtml .= '<input type="hidden"  name="otplsecurity" value="'.wp_create_nonce('otpl_filed_once_val').'">';
			 $otplFormHtml .= '<input type="hidden"  name="otplzplussecurity" value="">';
			 $otplFormHtml .='</div>';
			 $otplFormHtml  .='<div class="heading"><h3>OTP Verification</h3></div><div id="otpl-body"><div id="sendotp"><label for="email">Enter your email to get login OTP<span class="req">*</span><span class="emailerror req"></span></label><input type="email" name="email" id="email" value="" class="otpl-req-fields" size="40"> <input type="submit" class="otpl_submit_btn generateOtp" id="generateOtp" value="Next"> </div>
					
					<div id="submitotpsec"><span class="loginback" type="button">< Back</span>
					<span class="email-otp">
										<label for="email_otp">Enter 6 digit code sent to your email<br><span id="sbmitedemail"></span><span class="req"><span class="otperror"></span></span></label>
										<input type="number" name="email_otp" id="email_otp" value="" maxlength="6">
									</span>
									<div class="otpl-submit-sec"><input type="submit" class="submitOtp"  id="submitOtp" value="Submit OTP" /> <span class="otpestatus req d-inline-block"></span></div>
					</div></div>
				</form></div>';
				
				
				if( $registerURL != '' ) {
				
				$otplFormHtml .= '<a href="{$registerURL}" class="otpl-register">Register</a>';
				
				}
				
				$otplFormHtml .='</div>'; 
					//End social-inner
			//endif;
			
			echo $otplFormHtml;  
			}
       	/*
		 * Send OTP Email on User Email
		 * 
		 * */	 
		public function otpl_send_otp($email,$otp) {
		// send OTP over email
		$otp_message = '<table width="50%" cellpadding="0" cellspacing="0" align="center" bgcolor="f5f5f5">
								 <tr>
									<td>
										<table width="650" align="center">
											<tr>
												<td>
													<p class="font_18 pd_lft_25">We have received a one time password request.</p>
													<p class="font_17">Your new OTP is <strong>'.$otp.'</strong></p>
													
														<p class="font_17">Website '.home_url().'</p>
												</td>
											</tr>
										</table>

									<table  width="100%" height="40" bgcolor="c5c5c5"  align="center" cellpadding="0" cellspacing="0">
											<tr>
												<td valign="top" align="center">
												<p>This email powered by : <a href="https://www.wp-experts.in">WP-EXPERTS.IN</a></p>
												</td>
											</tr>
										</table>
										</td>
									</tr>
							</table>';
			
			$from = get_bloginfo( 'admin_email' );
			
			$headers[] = 'Content-Type: text/html; charset=UTF-8';
			
			//From
			if($from!='')
			$headers[] = 'From:'.$from;
			
			$mail = wp_mail( $email, "You have received new OTP to login at ".get_bloginfo( 'name' ), $otp_message, $headers);
			return $mail;
			die();
		}
		/*
		 * Handle all login form request
		 * 
		 * */	 
		public function otpl_login_action() {
				global $wpdb;
				// check security 
				if(wp_doing_ajax())
				file_put_contents("/tmp/debug.log", "incep verificarea\n", FILE_APPEND);
				check_ajax_referer( 'otpl_filed_once_val', 'otplsecurity');// First check the nonce, if it fails the function will break
				file_put_contents("/tmp/debug.log", "Crapa la ajax_referer cand verifica nonce-ul\n", FILE_APPEND);

				$otplzplussecurity = sanitize_text_field($_POST['otplzplussecurity']);
				$email_otp		   = sanitize_text_field($_POST['email_otp']);
				$email			   = sanitize_email($_POST['email']);
				$validateotp	   = sanitize_text_field($_POST['validateotp']);
			   // check zplus security
			   if(!isset($otplzplussecurity) || (isset($otplzplussecurity) && $otplzplussecurity!=''))
				{
					file_put_contents("/tmp/debug.log", "crapa la verificarea de request security\n", FILE_APPEND);
					echo json_encode(array('status'=>0,'message'=>'Request has been cancelled.','response'=>'Request has been rejected due to security! Please contact to administrator.'));
					wp_die();
				 }
			   // check is request for generate otp or submit otp
			   if( empty( $email_otp) ) {  
			   // required fields
			   if(empty( $email)) {
					file_put_contents("/tmp/debug.log", "Crapa la email\n", FILE_APPEND);
					echo json_encode(array('status'=>0,'message'=>'Validation error','response'=>'Enter email'));
					wp_die();
				 }
				 //check user already registered or not
				$user_id = email_exists($email);
				   
				if ( ! $user_id && false == email_exists($email) ) {
					file_put_contents("/tmp/debug.log", "Crapa la USER_ID\n", FILE_APPEND);
					echo json_encode(array('status'=>0,'message'=>'User does not exist.','response'=>'User does not exist'));
					  wp_die();
					
				} else {
					//check type of login request
					   // send otp on email address
						$newotp   =  rand(100000,999999);
						file_put_contents('/tmp/debug.log', "OTP for {$email}: {$newotp}\n", FILE_APPEND);
						$otpmail = $this->otpl_send_otp($email,$newotp); 
						update_user_meta( $user_id, "emilotp",  $newotp ) ; //update first name
					   if(!$otpmail) {
							$json_arg['response'] = 'OTP has generated for user but email failed!, please try again';
							$json_arg['message']  = '<input type="submit" class="generateOtp" value="Resend OTP" name="resendotp" />';
							$json_arg['status'] = 0;
							$json_arg['sendotp'] = 1;
						} else {
							$json_arg['response'] ='Success';
							$json_arg['message'] = 'OTP has sent on your email '.$user;
							$json_arg['status'] = 1;
							$json_arg['sendotp'] = 1;
							
							}
					echo json_encode($json_arg);
						wp_die();
				 }
					
				} else {
					// check otp valid or not
					$user_id = email_exists($email);
					global $wp;
					$db_otp = get_user_meta( $user_id, "emilotp",  true);
					 if($db_otp==$email_otp && $validateotp!=0){
						 $user = get_user_by( 'email', $email);
						 wp_set_current_user( $user_id, $user->user_login );
						 wp_set_auth_cookie( $user_id );
						 do_action( 'wp_login', $user->user_login, $user );
						 if(is_user_logged_in()) {
						  $url = get_option('otpl_redirect_url') ? get_option('otpl_redirect_url') : home_url( $wp->request );
						  echo json_encode(array('status'=>1,'message'=>'You have successfully logged in','response'=>'OTP Matched','sendotp'=>0,'redirect'=> $url));
						 update_user_meta( $user_id, "emilotp",  '' ) ;// reset otp
						 wp_die();
						 }
						 echo json_encode(array('status'=>1,'message'=>'not logged in','response'=>'OTP Matched but not logged in','sendotp'=>0,'redirect'=> $url));
						 wp_die();
					 
					 }else
					 {
						 echo json_encode(array('status'=>1,'message'=>'OTP does not matched. <input type="submit" class="generateOtp" value="Resend OTP" name="resendotp" />','response'=>'OTP does not exist','sendotp'=>1));
						 wp_die();
						 
						 }
					}
			}
	
     }
}
//init class
if(class_exists('OtpLoginFront'))
{
    // instantiate the plugin class
    $OtpLoginFront = new OtpLoginFront();
}
