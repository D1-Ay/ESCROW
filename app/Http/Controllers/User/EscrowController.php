<?php

namespace App\Http\Controllers\User;

use Exception;
use App\Models\User;
use App\Models\Escrow;
use App\Models\UserWallet;
use Illuminate\Http\Request;
use App\Models\EscrowDetails;
use App\Models\TemporaryData;
use App\Models\Admin\Currency;
use App\Models\EscrowCategory;
use Illuminate\Support\Carbon;
use App\Models\UserNotification;
use App\Constants\EscrowConstants;
use Illuminate\Support\Facades\DB;
use App\Models\Admin\BasicSettings;
use App\Constants\NotificationConst;
use App\Http\Controllers\Controller;
use App\Models\Admin\PaymentGateway;
use Illuminate\Support\Facades\Auth; 
use App\Constants\PaymentGatewayConst;
use App\Models\Admin\CryptoTransaction;
use Illuminate\Support\Facades\Session;
use App\Models\Admin\TransactionSetting;
use App\Traits\ControlDynamicInputFields;
use Illuminate\Support\Facades\Validator;
use App\Http\Helpers\EscrowPaymentGateway;
use App\Notifications\Escrow\EscrowRequest;
use App\Models\Admin\PaymentGatewayCurrency;
use App\Events\User\NotificationEvent as UserNotificationEvent;
use Illuminate\Support\Facades\Log;

class EscrowController extends Controller
{
    use ControlDynamicInputFields;
        /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index() {
        $page_title = "My Escrow";
        $escrowData = Escrow::with('escrowCategory','escrowDetails')->where('user_id', auth()->user()->id)->orWhere('buyer_or_seller_id',auth()->user()->id)->latest()->paginate(20);
        return view('user.my-escrow.index', compact('page_title','escrowData'));
    } 
        /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create(Request $request) {
        // Log the start of the method
        Log::info('Starting the create method.');
    
        // Log page title setting
        $page_title = "Create New Escrow";
        Log::info('Page title set: ' . $page_title);
    
        // Log fetching currencies
        Log::info('Fetching currencies where status is true.');
        $currencies = Currency::where('status', true)->get();
        Log::info('Currencies fetched: ', ['currencies' => $currencies]);
    
        // Log fetching escrow categories
        Log::info('Fetching escrow categories where status is true and sorting by latest.');
        $escrowCategories = EscrowCategory::where('status', true)->latest()->get();
        Log::info('Escrow categories fetched: ', ['escrowCategories' => $escrowCategories]);
    
        // Log fetching payment gateway currencies
        Log::info('Fetching payment gateways with active status for add money slug.');
        $payment_gateways_currencies = PaymentGatewayCurrency::whereHas('gateway', function ($gateway) {
            $gateway->where('slug', PaymentGatewayConst::add_money_slug());
            $gateway->where('status', 1);
        })->get();
        Log::info('Payment gateways currencies fetched: ', ['payment_gateways_currencies' => $payment_gateways_currencies]);
    
        // Log the request data
        $user_pass_data = $request->all();
        Log::info('Request data received: ', ['user_pass_data' => $user_pass_data]);
    
        // Log returning the view
        Log::info('Rendering view for create escrow.');
        return view('user.my-escrow.create', compact('page_title', 'escrowCategories', 'currencies', 'payment_gateways_currencies', 'user_pass_data'));
    }
    
    //===================== escrow submission ======================================================
    public function submit(Request $request) { 
        \Log::info('Submit method started');
        
        // Fetch basic settings
        $basic_setting = BasicSettings::first();
        \Log::info('BasicSettings fetched');
    
        // Get authenticated user
        $user = auth()->user();
        \Log::info('User fetched: '.$user->id);
    
        // KYC Verification Checks
        // if ($basic_setting->kyc_verification) {
        //     if ($user->kyc_verified == 0) {
        //         \Log::info('User KYC not submitted');
        //         return redirect()->route('user.authorize.kyc')->with(['error' => [__('Please submit kyc information')]]);
        //     } elseif ($user->kyc_verified == 2) {
        //         \Log::info('User KYC pending approval');
        //         return redirect()->route('user.authorize.kyc')->with(['error' => [__('Please wait before admin approves your kyc information')]]);
        //     } elseif ($user->kyc_verified == 3) {
        //         \Log::info('User KYC rejected');
        //         return redirect()->route('user.authorize.kyc')->with(['error' => [__('Admin rejected your kyc information, Please re-submit again')]]);
        //     }
        // }
    
        // Page Title
        $page_title = "Escrow Details";
    
        // Validation of input
        $validator = Validator::make($request->all(), [
            'title'                 => 'required|string',
            'escrow_category'       => 'required|integer',
            'role'                  => 'required|string',
            'who_will_pay_options'  => 'required|string',
            'buyer_seller_identify' => 'required',
            'amount'                => 'required|numeric',
            'escrow_currency'       => 'required|string',
            'payment_gateway'       => 'nullable',
            'remarks'               => 'nullable|string',
            'file.*'                => 'nullable|file|max:100000|mimes:jpg,jpeg,png,pdf,zip',
        ]);
    
        // Check if validation fails
        if ($validator->fails()) {
            \Log::info('Validation failed');
            return back()->withErrors($validator)->withInput();
        }
        
        \Log::info('Validation passed');
        
        // Validate and sanitize input
        $validated = $validator->validate();
        \Log::info('Input validated', $validated);
    
        // Fetch escrow category
        $escrowCategory = EscrowCategory::find($validated['escrow_category']);
        \Log::info('Escrow category fetched: '.$escrowCategory->id);
    
        // Fetch transaction settings for escrow charges
        $getEscrowChargeLimit = TransactionSetting::find(1);
        \Log::info('Transaction settings fetched');
    
        // Fetch the currency
        $sender_currency = Currency::where('code', $validated['escrow_currency'])->first();
        \Log::info('Sender currency fetched: '.$sender_currency->code);
    
        // Opposite user fetch
        $opposite_user = User::where('username', $validated['buyer_seller_identify'])
                            ->orWhere('email', $validated['buyer_seller_identify'])->first();
        
        if (empty($opposite_user) || $opposite_user->email == $user->email) {
            \Log::info('Opposite user not found or same as authenticated user');
            return redirect()->back()->withInput()->with(['error' => [__('User not found')]]);
        }
        
        \Log::info('Opposite user found: '.$opposite_user->id);
    
        // Payment method and currency calculations
        \Log::info('Processing payment method');
        
        $payment_type = EscrowConstants::DID_NOT_PAID;
        $payment_gateways_currencies = null;
    
        if ($validated['role'] == "buyer") {
            if ($validated['payment_gateway'] == "myWallet") {
                $user_wallets = UserWallet::where(['user_id' => $user->id, 'currency_id' => $sender_currency->id])->first();
                if (empty($user_wallets)) {
                    \Log::info('User wallet not found');
                    return redirect()->back()->withInput()->with(['error' => ['Wallet not found.']]); 
                }
                if ($user_wallets->balance < $validated['amount']) {
                    \Log::info('Insufficient balance in wallet');
                    return redirect()->back()->withInput()->with(['error' => [__('Insufficient Balance')]]);
                }
    
                \Log::info('Payment method: My Wallet');
                $payment_method        = "My Wallet";
                $gateway_currency      = $validated['escrow_currency'];
                $gateway_exchange_rate = 1;
                $payment_type          = EscrowConstants::MY_WALLET;
            } else {
                $payment_gateways_currencies = PaymentGatewayCurrency::with('gateway')->find($validated['payment_gateway']);
                if (!$payment_gateways_currencies || !$payment_gateways_currencies->gateway) {
                    \Log::info('Payment gateway not found');
                    return redirect()->back()->withInput()->with(['error' => ['Payment gateway not found.']]); 
                }
    
                \Log::info('Payment method: Gateway - '.$payment_gateways_currencies->name);
                $payment_method   = $payment_gateways_currencies->name;
                $gateway_currency = $payment_gateways_currencies->currency_code;
    
                // Calculate gateway exchange rate
                $gateway_exchange_rate = (1 / $sender_currency->rate) * $payment_gateways_currencies->rate;
                $payment_type = EscrowConstants::GATEWAY;
            }
        }
    
        \Log::info('Escrow amount and charges processing');
    
        // Convert escrow currency amount into default currency
        $usd_exchange_amount = (1 / $sender_currency->rate) * $validated['amount'];
    
        // Calculate escrow charges
        $usd_fixed_charge   = $getEscrowChargeLimit->fixed_charge;
        $usd_percent_charge = ($getEscrowChargeLimit->percent_charge / 100) * $usd_exchange_amount;
        $usd_total_charge   = $usd_fixed_charge + $usd_percent_charge;
    
        // Final charge in escrow currency
        $escrow_total_charge = $usd_total_charge * $sender_currency->rate;
    
        // Check if escrow amount is within limits
        if ($getEscrowChargeLimit->min_limit > $usd_exchange_amount || $getEscrowChargeLimit->max_limit < $usd_exchange_amount) {
            \Log::info('Escrow amount out of limits');
            return redirect()->back()->withInput()->with(['error' => [__('Please follow the escrow limit')]]);
        }
    
        \Log::info('Escrow amounts calculated successfully');
    
        // Generate a unique identifier for the escrow transaction
        $identifier = generate_unique_string("escrows", "escrow_id", 16);
        \Log::info('Generated identifier: '.$identifier);
    
        // Initialize the attachment variable to avoid undefined issues
        $attachment = [];
    
        // File upload processing
        if ($request->hasFile('file')) {
            $validated_files = $request->file("file");
            $files_link = [];
            foreach ($validated_files as $item) {
                $upload_file = upload_file($item, 'escrow-temp-file');
                if ($upload_file != false) {
                    $attachment[] = [
                        'attachment'      => $upload_file['name'],
                        'attachment_info' => json_encode($upload_file),
                        'created_at'      => now(),
                    ];
                    $files_link[] = get_files_path('escrow-temp-file') . "/". $upload_file['name'];
                    \Log::info('File uploaded: '.$upload_file['name']);
                } else {
                    \Log::error('File upload failed');
                    return back()->with(['error' => [__('Oops! Failed to upload attachment. Please try again')]]);
                }
            }
        }
    
        // Preparing final data
        $oldData = (object) [ 
            'buyer_or_seller_id'          => $opposite_user->id,
            'escrow_category_id'          => $validated['escrow_category'],
            'payment_type'                => $payment_type,
            'payment_gateway_currency_id' => $payment_type == EscrowConstants::GATEWAY ? $payment_gateways_currencies->id : null,
            'user_id'                     => auth()->user()->id,
            'title'                       => $validated['title'],
            'role'                        => $validated['role'],
            'product_type'                => $escrowCategory->name,
            'amount'                      => $validated['amount'],
            'escrow_currency'             => $validated['escrow_currency'],
            'charge_payer'                => $validated['who_will_pay_options'],
            'escrow_total_charge'         => $escrow_total_charge,
            'seller_amount'               => $seller_amount ?? 0,
            'gateway_currency'            => $gateway_currency ?? "null",
            'payment_method'              => $payment_method ?? "null",
            'gateway_exchange_rate'       => $gateway_exchange_rate ?? 0,
            'buyer_amount'                => $buyer_amount ?? 0,
            'remarks'                     => $validated['remarks'] ?? null,
            'file'                        => null,
        ];
    
        // Storing temporary data for the escrow
        $tempData = [
            'trx'              => $identifier,
            'escrow'           => $oldData,
            'gateway_currency' => $payment_gateways_currencies ?? null,
            'attachment'       => json_encode($attachment) ?? null,
            'creator_table'    => auth()->guard(get_auth_guard())->user()->getTable(),
            'creator_id'       => auth()->guard(get_auth_guard())->user()->id,   
            'creator_guard'    => get_auth_guard(),                              
        ];
    
        $this->addEscrowTempData($identifier, $tempData);
    
        // Store the identifier in the session
        Session::put('identifier', $identifier);
        \Log::info('Session identifier stored');
        \Log::info('Preparing to render escrow-preview view');
        
        
        // Prepare final response
        return view('user.my-escrow.escrow-preview', compact('page_title', 'oldData', 'identifier'));
    }
    
    
    //escrow temp data insert
    public function addEscrowTempData($identifier,$data) {  
        return TemporaryData::create([
            'type'       => "add-escrow",
            'identifier' => $identifier,
            'data'       => $data,
        ]);
    }
    //===================== end escrow submission ==================================================
    //====================== escrow payment ========================================================
    public function successConfirm(Request $request) {
        \Log::info('successConfirm method started');
    
        // Validation
        $validator  = Validator::make($request->all(),[
            'identifier' => 'required',
        ]);
        if($validator->fails()) {
            \Log::info('Validation failed');
            return back()->withErrors($validator)->withInput();
        }
        
        // Get the identifier from the request or session
        $identifier = $request->identifier ?? session()->get('identifier');
        \Log::info('Identifier fetched: '.$identifier);
    
        // Fetch Temporary Data
        $tempData = TemporaryData::where("identifier", $identifier)->first();
        \Log::info('Temporary data fetched for identifier: '.$identifier);
    
        if (!$tempData) {
            \Log::error('No TemporaryData found for identifier: '.$identifier);
            return redirect()->back()->with(['error' => __("Temporary data not found")]);
        }
    
        // Check escrow role
        if ($tempData->data->escrow->role == EscrowConstants::SELLER_TYPE) {
            \Log::info('Escrow role is seller, creating escrow');
            $this->createEscrow($tempData);
            \Log::info('Escrow created successfully');
            return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]);
        }
    
        // Escrow wallet payment
        if ($tempData->data->escrow->payment_type == EscrowConstants::MY_WALLET) {
            \Log::info('Payment type: MY_WALLET, processing wallet payment');
            $this->escrowWalletPayment($tempData);
            \Log::info('Wallet payment processed, creating escrow');
            $this->createEscrow($tempData);
            \Log::info('Escrow created successfully');
            return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
        }
    
        // Escrow payment via payment gateway
        if ($tempData->data->escrow->payment_type == EscrowConstants::GATEWAY) {
            try {
                \Log::info('Payment type: GATEWAY, initializing payment gateway');
                $instance = EscrowPaymentGateway::init($tempData)->gateway();
                \Log::info('Payment gateway initialized successfully');
                return $instance;
            } catch (Exception $e) {
                \Log::error('Payment gateway error: '.$e->getMessage());
                return back()->with(['error' => [$e->getMessage()]]);
            }
        }
    
        \Log::info('End of successConfirm method, something went wrong');
        return redirect()->back()->with(['error' => __("Something went wrong")]);
    }
    
    public function escrowPaymentSuccess(Request $request, $gateway = null, $trx = null) { 
        try{
            $identifier = $trx ?? session()->get('identifier');
            $tempData   = TemporaryData::where("identifier",$identifier)->first();
            $this->createEscrow($tempData);
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    public function cancel(Request $request, $gateway = null) {
        $token = session()->get('identifier');
        if($token){
            TemporaryData::where("identifier",$token)->delete();
        }

        return redirect()->route('user.my-escrow.index')->with(['error' => [__('You have canceled the payment')]]);
    }
    //stripe payment success 
    public function stripePaymentSuccess(Request $request, $gateway = null, $trx = null){
        try{
            $identifier = $trx ?? session()->get('identifier');
            $tempData   = TemporaryData::where("identifier",$identifier)->first();
            $this->createEscrow($tempData);
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    //qrpay payment success 
    public function qrpayPaymentSuccess(Request $request, $gateway = null, $trx = null){
        try{
            $identifier = $trx ?? session()->get('identifier');
            $tempData   = TemporaryData::where("identifier",$identifier)->first();
            $this->createEscrow($tempData);
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    public function qrpayCancel(Request $request, $trx = null) {
        $token = session()->get('identifier');
        if($token){
            TemporaryData::where("identifier",$token)->delete();
        }

        return redirect()->route('user.my-escrow.index')->with(['error' => [__('You have canceled the payment')]]);
    } 
    //qrpay payment success 
    public function coingateSuccess(Request $request){ 
        try{  
            $identifier = $request->get('trx');
            $escrowData = Escrow::where('callback_ref',$identifier)->first();
            if($escrowData == null) {
                $tempData   = TemporaryData::where("identifier",$identifier)->first();
                $this->createEscrow($tempData,null,EscrowConstants::PAYMENT_PENDING);
            } 
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    public function coingateCallbackResponse(Request $request) { 
        $callback_data = $request->all(); 
        $callback_status = $callback_data['status'] ?? ""; 
        $tempData   = TemporaryData::where("identifier",$request->get('trx'))->first(); 
        $escrowData = Escrow::where('callback_ref',$request->get('trx'))->first();
        if($escrowData != null) { // if transaction already created & status is not success
            // Just update transaction status and update user wallet if needed
            if($callback_status == "paid") {  
                // update transaction status
                DB::beginTransaction(); 
                try{ 
                    DB::table('escrows')->where('id',$escrowData->id)->update([
                        'status'            => EscrowConstants::ONGOING, 
                        'callback_ref'      => $callback_data['trx'],
                    ]); 
                    DB::commit(); 
                }catch(Exception $e) {
                    DB::rollBack();
                    logger($e->getMessage());
                    throw new Exception($e);
                }
            }
        }else { // need to create transaction and update status if needed 
            $status = EscrowConstants::PAYMENT_PENDING; 
            if($callback_status == "paid") {
                $status = EscrowConstants::ONGOING;
            } 
            $this->createEscrow($tempData,null,$status);
        } 
        logger("Escrow Created Successfully ::" . $callback_data['status']);
    }
    public function coingateCancel(Request $request, $trx = null) {
        $token = session()->get('identifier');
        if($token){
            TemporaryData::where("identifier",$token)->delete();
        }

        return redirect()->route('user.my-escrow.index')->with(['error' => [__('You have canceled the payment')]]);
    } 
    //flutterwave payment success 
    public function flutterwaveCallback(Request $request, $gateway = null, $trx = null) { 
        $status = request()->status; 
        //if payment is successful
        if ($status ==  'successful' || $status ==  'completed') {  
            try{
                $identifier = $trx ?? session()->get('identifier');
                $tempData   = TemporaryData::where("identifier",$identifier)->first();
                $this->createEscrow($tempData); 
            }catch(Exception $e) {
                return back()->with(['error' => [$e->getMessage()]]);
            }
            return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]);
        }
        elseif ($status ==  'cancelled'){
            return redirect()->route('user.my-escrow.index','flutterWave')->with(['error' => [__('You have cancelled the payment')]]);
        }
        else{
            return redirect()->route('user.my-escrow.payment.success')->with(['error' => [__('Transaction failed')]]);
        }
    }
    public function razorCallback(){ 
        $request_data = request()->all(); 
        $identifier = $request_data['trx'] ?? session()->get('identifier');
        $tempData   = TemporaryData::where("identifier",$identifier)->first();
        $this->createEscrow($tempData);
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    public function escrowPaymentSuccessperfectMoney(Request $request, $gateway = null, $trx = null) { 
        try{
            $identifier = $trx ?? session()->get('identifier');
            $tempData   = TemporaryData::where("identifier",$identifier)->first();
            $this->createEscrow($tempData);
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    //========= escrow manual payment ===============
    public function manualPaymentPrivew(Request $request, $gateway = null, $trx = null) {
        $identifier = $trx ?? session()->get('identifier');
        $oldData   = TemporaryData::where("identifier",$identifier)->first();
        $gateway    = PaymentGateway::manual()->where('slug',PaymentGatewayConst::add_money_slug())->where('id',$oldData->data->gateway_currency->gateway->id)->first();
        $page_title = "Manual Payment".' ( '.$gateway->name.' )';
        if(!$oldData){
            return redirect()->route('user.my-escrow.index');
        }
        return view('user.my-escrow.manual-payment',compact("page_title","oldData",'gateway'));
    }
    public function manualPaymentConfirm(Request $request) { 
        $tempData       = Session::get('identifier');
        $oldData        = TemporaryData::where('identifier', $tempData)->first();
        $gateway        = PaymentGateway::manual()->where('slug',PaymentGatewayConst::add_money_slug())->where('id',$oldData->data->gateway_currency->gateway->id)->first();
        $payment_fields = $gateway->input_fields ?? [];
        $validation_rules       = $this->generateValidationRules($payment_fields);
        $payment_field_validate = Validator::make($request->all(),$validation_rules)->validate();
        $get_values             = $this->placeValueWithFields($payment_fields,$payment_field_validate);
        $this->successEscrow($get_values);
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    //========= end escrow manual payment ===============
    //escrow wallet payment
    public function escrowWalletPayment($escrowTempData) {
        \Log::info('escrowWalletPayment method started');
    
        // Fetching currency
        $sender_currency = Currency::where('code', $escrowTempData->data->escrow->escrow_currency)->first();
        \Log::info('Sender currency fetched: ' . $sender_currency->code);
    
        // Fetching user wallet
        $user_wallet = UserWallet::where(['user_id' => auth()->user()->id, 'currency_id' => $sender_currency->id])->first();
        \Log::info('User wallet fetched, balance: ' . $user_wallet->balance);
    
        // Deducting amount from wallet
        \Log::info('Deducting ' . $escrowTempData->data->escrow->buyer_amount . ' from wallet');
        $user_wallet->balance -= $escrowTempData->data->escrow->buyer_amount;
        $user_wallet->save();
        \Log::info('New wallet balance: ' . $user_wallet->balance);
    
        \Log::info('escrowWalletPayment method completed');
    }
    
    //====================== end escrow payment ========================================================
    //======================= escrow data insertion after payment ==================================
    //escrow data insert
    public function successEscrow($additionalData = null) {
        $identifier = session()->get('identifier');
        $tempData   = TemporaryData::where("identifier",$identifier)->first();
        if(!$tempData) return redirect()->route('user.my-escrow.index')->with(['error' => [__('Transaction Failed. Record didn\'t saved properly. Please try again')]]);
        $this->createEscrow($tempData,$additionalData);
        
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    } 
    //escrow sslcommerz data insert
    public function successEscrowSslcommerz(Request $request) {  
        $tempData = TemporaryData::where("identifier",$request->tran_id)->first();
        if(!$tempData) return redirect()->route('user.my-escrow.index')->with(['error' => [__('Transaction Failed. Record didn\'t saved properly. Please try again')]]); 
        $creator_id    = $tempData->data->creator_id ?? null;
        $creator_guard = $tempData->data->creator_guard ?? null;
        $user          = Auth::guard($creator_guard)->loginUsingId($creator_id); 
        if( $request->status != "VALID"){
            return redirect()->route("user.my-escrow.index")->with(['error' => [__('Escrow Create Failed')]]);
        }
        $this->createEscrow($tempData); 
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    } 
    //insert escrow data
    public function createEscrow($tempData, $additionalData = null, $setStatus = null) {
        \Log::info('createEscrow method started');
    
        $escrowData = $tempData->data->escrow;
        if ($setStatus == null) {
            $status = 0;
            if ($escrowData->role == "seller") {
                $status = EscrowConstants::APPROVAL_PENDING;
            } else if ($escrowData->role == "buyer" && $escrowData->payment_gateway_currency_id != null) { 
                if ($tempData->data->gateway_currency->gateway->type == PaymentGatewayConst::AUTOMATIC) {
                    $status = EscrowConstants::ONGOING;
                } else if ($tempData->data->gateway_currency->gateway->type == PaymentGatewayConst::MANUAL) {
                    $status = EscrowConstants::PAYMENT_PENDING;
                    $additionalData = json_encode($additionalData);
                }
            } else if ($escrowData->role == "buyer" && $escrowData->payment_type == EscrowConstants::MY_WALLET) {
                $status = EscrowConstants::ONGOING;
            }
        } else {
            $status = $setStatus;
        }
    
        DB::beginTransaction();
        try {
            \Log::info('Creating escrow entry in database for user_id: ' . $escrowData->user_id);
            
            // Create the escrow
            $escrowCreate = Escrow::create([
                'user_id'                     => $escrowData->user_id,
                'escrow_category_id'          => $escrowData->escrow_category_id,
                'payment_gateway_currency_id' => $escrowData->payment_gateway_currency_id ?? null,
                'escrow_id'                   => 'EC' . getTrxNum(),
                'payment_type'                => $escrowData->payment_type,
                'role'                        => $escrowData->role,
                'who_will_pay'                => $escrowData->charge_payer,
                'buyer_or_seller_id'          => $escrowData->buyer_or_seller_id,
                'amount'                      => $escrowData->amount,
                'escrow_currency'             => $escrowData->escrow_currency,
                'title'                       => $escrowData->title,
                'remark'                      => $escrowData->remarks,
                'file'                        => json_decode($tempData->data->attachment),
                'status'                      => $status,
                'details'                     => $additionalData,
                'created_at'                  => now(),
                'callback_ref'                => $tempData->identifier,
            ]);
    
            \Log::info('Escrow created with ID: ' . $escrowCreate->id);
    
            // Create escrow details
            EscrowDetails::create([
                'escrow_id'             => $escrowCreate->id ?? 0,
                'fee'                   => $escrowData->escrow_total_charge,
                'seller_get'            => $escrowData->seller_amount,
                'buyer_pay'             => $escrowData->buyer_amount,
                'gateway_exchange_rate' => $escrowData->gateway_exchange_rate,
                'created_at'            => now(),
            ]);
            \Log::info('Escrow details created for escrow ID: ' . $escrowCreate->id);
    
            DB::commit();
    
            // Send user notifications
            $byerOrSeller = User::findOrFail($escrowData->buyer_or_seller_id);
            \Log::info('Sending notification to user ID: ' . $byerOrSeller->id);
    
            $notification_content = [
                'title'   => "Escrow Request",
                'message' => "A user created an escrow with you",
                'time'    => Carbon::now()->diffForHumans(),
                'image'   => files_asset_path('profile-default'),
            ];
            UserNotification::create([
                'type'    => NotificationConst::ESCROW_CREATE,
                'user_id' => $escrowData->buyer_or_seller_id,
                'message' => $notification_content,
            ]);
    
           // Push Notifications
            $basic_setting = BasicSettings::first();
            try { 
                $byerOrSeller->notify(new EscrowRequest($byerOrSeller, $escrowCreate));
    
                if ($basic_setting->push_notification == true) {
                    \Log::info('Sending push notification to user ID: ' . $byerOrSeller->id);
                    event(new UserNotificationEvent($notification_content, $byerOrSeller));
                    send_push_notification(["user-" . $byerOrSeller->id], [
                        'title' => $notification_content['title'],
                        'body'  => $notification_content['message'],
                        'icon'  => $notification_content['image'],
                    ]);
                }
            } catch (Exception $e) {
                \Log::error('Push notification error: ' . $e->getMessage());
            }
    
            // Clean up temporary data
            TemporaryData::where("identifier", $tempData->identifier)->delete();
            \Log::info('Temporary data deleted for identifier: ' . $tempData->identifier);
    
        } catch (Exception $e) {
            DB::rollBack();
            \Log::error('Escrow creation failed: ' . $e->getMessage());
            throw new Exception($e->getMessage());
        }
    
        \Log::info('createEscrow method completed');
    }
    
    //escrow sslcommerz fail
     public function escrowSllCommerzFails(Request $request){ 
        $tempData = TemporaryData::where("identifier",$request->tran_id)->first();
        if(!$tempData) return redirect()->route('user.my-escrow.index')->with(['error' => [__('Transaction Failed. Record didn\'t saved properly. Please try again')]]);
        $creator_id    = $tempData->data->creator_id ?? null;
        $creator_guard = $tempData->data->creator_guard ?? null;
        $user          = Auth::guard($creator_guard)->loginUsingId($creator_id);
        if($request->status == "FAILED"){
            TemporaryData::destroy($tempData->id);
            return redirect()->route("user.my-escrow.index")->with(['error' => [__('Escrow Create Failed')]]);
        }
    } 
    //escrow sslcommerz cancel
    public function escrowSllCommerzCancel(Request $request){ 
        $tempData = TemporaryData::where("identifier",$request->tran_id)->first();
        if(!$tempData) return redirect()->route('user.my-escrow.index')->with(['error' => [__('Transaction Failed. Record didn\'t saved properly. Please try again')]]);
        $creator_id    = $tempData->data->creator_id ?? null;
        $creator_guard = $tempData->data->creator_guard ?? null;
        $user          = Auth::guard($creator_guard)->loginUsingId($creator_id);
        if($request->status == "FAILED"){
            TemporaryData::destroy($tempData->id);
            return redirect()->route("user.my-escrow.index")->with(['error' => [__('Escrow Create Cancel')]]);
        }
    } 
    //======================= end escrow data insertion after payment ==================================
    //======================= additional actions ==============================================
    // ajax call for get user available balance by currency 
    public function availableBalanceByCurrency(Request $request) {
        $user_wallets = UserWallet::where(['user_id' => auth()->user()->id, 'currency_id' => $request->id])->first();
        $digitShow    = $user_wallets->currency->type == "CRYPTO" ? 6 : 2 ;
        return number_format($user_wallets->balance,$digitShow);
    } 
    public function userCheck(Request $request){ 
        $getUser = User::where('status', true)->where('username', $request->userCheck)->orWhere('email',$request->userCheck)->first();
        if($getUser != null){
            if($getUser->id == auth()->user()->id){
                return false;
            }
            return true;
        }
        return false;
    }

    public function cryptoPaymentAddress(Request $request, $escrow_id) {
        $page_title = "Crypto Payment Address";
        $escrowData = Escrow::where('escrow_id',$escrow_id)->first();
         
        return view('user.my-escrow.payment.crypto.address', compact( 
            'page_title',
            'escrowData',
        )); 
    }
    public function cryptoPaymentConfirm(Request $request, $escrow_id)
    {
        $escrowData = Escrow::where('escrow_id',$escrow_id)->first();
        
        $dy_input_fields = $escrowData->details->payment_info->requirements ?? [];
        $validation_rules = $this->generateValidationRules($dy_input_fields);

        $validated = [];
        if(count($validation_rules) > 0) {
            $validated = Validator::make($request->all(), $validation_rules)->validate();
        }

        if(!isset($validated['txn_hash'])) return back()->with(['error' => ['Transaction hash is required for verify']]);

        $receiver_address = $escrowData->details->payment_info->receiver_address ?? "";

        
        // check hash is valid or not
        $crypto_transaction = CryptoTransaction::where('txn_hash', $validated['txn_hash'])
                                                ->where('receiver_address', $receiver_address)
                                                ->where('asset',$escrowData->paymentGatewayCurrency->currency_code)
                                                ->where(function($query) {
                                                    return $query->where('transaction_type',"Native")
                                                                ->orWhere('transaction_type', "native");
                                                })
                                                ->where('status',PaymentGatewayConst::NOT_USED)
                                                ->first();
       
        if(!$crypto_transaction) return back()->with(['error' => ['Transaction hash is not valid! Please input a valid hash']]);

        if($crypto_transaction->amount >= $escrowData->escrowDetails->buyer_pay == false) {
            if(!$crypto_transaction) return back()->with(['error' => ['Insufficient amount added. Please contact with system administrator']]);
        }

        DB::beginTransaction();
        try{

            // update crypto transaction as used
            DB::table($crypto_transaction->getTable())->where('id', $crypto_transaction->id)->update([
                'status'        => PaymentGatewayConst::USED,
            ]);

            // update transaction status
            $transaction_details = json_decode(json_encode($escrowData->details), true);
            $transaction_details['payment_info']['txn_hash'] = $validated['txn_hash'];

            DB::table($escrowData->getTable())->where('id', $escrowData->id)->update([
                'details'       => $transaction_details,
                'status'        => EscrowConstants::ONGOING,
                'payment_type'        => EscrowConstants::GATEWAY,
            ]);

            DB::commit();

        }catch(Exception $e) { 
            DB::rollback();
            return back()->with(['error' => ['Something went wrong! Please try again']]);
        }

        return back()->with(['success' => ['Payment Confirmation Success!']]);
    }
    /**
     * Redirect Users for collecting payment via Button Pay (JS Checkout)
     */
    public function redirectBtnPay(Request $request, $gateway)
    {  
        try{ 
            return EscrowPaymentGateway::init([])->handleBtnPay($gateway, $request->all());
        }catch(Exception $e) {
            return redirect()->route('user.my-escrow.index')->with(['error' => [$e->getMessage()]]);
        }
    }
    public function escrowPaymentSuccessRazorpay(Request $request, $gateway) {
        try{
            $identifier = $request->token ;
            $tempData   = TemporaryData::where("identifier",$identifier)->first();
            $this->createEscrow($tempData);
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
    public function escrowPaymentSuccessRazorpayPost(Request $request, $gateway) {
        try{
            $identifier = $request->token ;
            $tempData   = TemporaryData::where("identifier",$identifier)->first();
            $this->createEscrow($tempData);
        }catch(Exception $e) {
            return back()->with(['error' => [$e->getMessage()]]);
        }
        return redirect()->route('user.my-escrow.index')->with(['success' => [__('Escrow created successfully')]]); 
    }
}
