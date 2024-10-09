<?php

namespace Database\Seeders\Update;

use App\Models\Admin\PaymentGateway;
use App\Models\Admin\PaymentGatewayCurrency;
use Illuminate\Database\Seeder;

class PaymentGatewaySeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        //============================Qrpay gateway automatic start=================================================
        $data =  array('slug' => 'add-money','code' => '230','type' => 'AUTOMATIC','name' => 'Qrpay','title' => 'Qrpay Gateway','alias' => 'qrpay','image' => 'cf4e938a-f837-4ed4-aada-ce0593225427.webp','credentials' => '[{"label":"Live Base Url","placeholder":"Enter Live Base Url","name":"live-base-url","value":"https:\\/\\/envato.appdevs.net\\/qrpay\\/pay\\/api\\/v1"},{"label":"Sendbox Base Url","placeholder":"Enter Sendbox Base Url","name":"sendbox-base-url","value":"https:\\/\\/envato.appdevs.net\\/qrpay\\/pay\\/sandbox\\/api\\/v1"},{"label":"Client Secret","placeholder":"Enter Client Secret","name":"client-secret","value":"oZouVmqHCbyg6ad7iMnrwq3d8wy9Kr4bo6VpQnsX6zAOoEs4oxHPjttpun36JhGxDl7AUMz3ShUqVyPmxh4oPk3TQmDF7YvHN5M3"},{"label":"Client Id","placeholder":"Enter Client Id","name":"client-id","value":"tRCDXCuztQzRYThPwlh1KXAYm4bG3rwWjbxM2R63kTefrGD2B9jNn6JnarDf7ycxdzfnaroxcyr5cnduY6AqpulRSebwHwRmGerA"}]','supported_currencies' => '["USD"]','crypto' => '0','desc' => NULL,'input_fields' => NULL,'env' => 'SANDBOX','status' => '1','last_edit_by' => '1','created_at' => '2023-11-23 08:30:18','updated_at' => '2023-11-23 10:37:13');
        $gateway_id = PaymentGateway::insertGetId($data);

        $gateway_currency = array(
            array('payment_gateway_id' => $gateway_id,'name' => 'Qrpay USD','alias' => 'add-money-qrpay-usd-automatic','currency_code' => 'USD','currency_symbol' => '$','image' => NULL,'min_limit' => '1.0000000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '1.0000000000000000','created_at' => '2023-11-23 10:37:13','updated_at' => '2023-11-23 10:37:13')
        );
        PaymentGatewayCurrency::insert($gateway_currency);
        //============================Qrpay gateway automatic end=================================================
        //============================Tatum gateway automatic start=================================================
        $data =  array('slug' => 'add-money','code' => '235','type' => 'AUTOMATIC','name' => 'Tatum','title' => 'Tatum Gateway','alias' => 'tatum','image' => '7019735c-9ae1-43ca-84ba-eebdf28a9508.webp','credentials' => '[{"label":"Mainnet","placeholder":"Enter Mainnet","name":"mainnet","value":""},{"label":"Testnet","placeholder":"Enter Testnet","name":"testnet","value":""}]','supported_currencies' => '["BTC","ETH","SOL"]','crypto' => '1','desc' => NULL,'input_fields' => NULL,'env' => 'SANDBOX','status' => '1','last_edit_by' => '1','created_at' => '2023-12-27 04:30:12','updated_at' => '2023-12-27 04:33:47');
        $gateway_id = PaymentGateway::insertGetId($data);

        $gateway_currency = array(
            array('payment_gateway_id' => $gateway_id,'name' => 'Tatum SOL','alias' => 'add-money-tatum-sol-automatic','currency_code' => 'SOL','currency_symbol' => 'S/','image' => NULL,'min_limit' => '0.0100000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '3.7000000000000000','created_at' => '2023-12-27 04:33:47','updated_at' => '2023-12-27 07:16:14'),
            array('payment_gateway_id' => $gateway_id,'name' => 'Tatum ETH','alias' => 'add-money-tatum-eth-automatic','currency_code' => 'ETH','currency_symbol' => 'Ξ','image' => NULL,'min_limit' => '0.0001000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '0.0006100000000000','created_at' => '2023-12-27 04:33:47','updated_at' => '2023-12-27 07:16:14'),
            array('payment_gateway_id' => $gateway_id,'name' => 'Tatum BTC','alias' => 'add-money-tatum-btc-automatic','currency_code' => 'BTC','currency_symbol' => '฿','image' => NULL,'min_limit' => '0.0001000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '0.0000360000000000','created_at' => '2023-12-27 04:33:47','updated_at' => '2023-12-27 07:16:14')
        );
        PaymentGatewayCurrency::insert($gateway_currency);
        //============================Tatum gateway automatic end=================================================
        //============================Coingate gateway automatic start=================================================
        $data =  array('slug' => 'add-money','code' => '240','type' => 'AUTOMATIC','name' => 'Coingate','title' => 'Coingate Gateway','alias' => 'coingate','image' => 'dd7f5f3f-f605-4562-948c-a523602411f6.webp','credentials' => '[{"label":"Production App Token","placeholder":"Enter Production App Token","name":"production-app-token","value":null},{"label":"Production URL","placeholder":"Enter Production URL","name":"production-url","value":"https:\\/\\/api.coingate.com\\/v2"},{"label":"Sandbox App Token","placeholder":"Enter Sandbox App Token","name":"sandbox-app-token","value":"XJW4RyhT8F-xssX2PvaHMWJjYe5nsbsrbb2Uqy4m"},{"label":"Sandbox URL","placeholder":"Enter Sandbox URL","name":"sandbox-url","value":"https:\\/\\/api-sandbox.coingate.com\\/v2"}]','supported_currencies' => '["USD","BTC","LTC","ETH","BCH","TRX","ETC","DOGE","BTG","BNB","TUSD","USDT","BSV","MATIC","BUSD","SOL","WBTC","RVN","BCD","ATOM","BTTC","EURT"]','crypto' => '1','desc' => NULL,'input_fields' => NULL,'env' => 'SANDBOX','status' => '1','last_edit_by' => '1','created_at' => '2023-12-27 11:18:11','updated_at' => '2023-12-27 11:32:26');
        $gateway_id = PaymentGateway::insertGetId($data);

        $gateway_currency = array(
            array('payment_gateway_id' => $gateway_id,'name' => 'Coingate USDT','alias' => 'add-money-coingate-usdt-automatic','currency_code' => 'USDT','currency_symbol' => '₮','image' => NULL,'min_limit' => '1.0000000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '1.00000000000000000','created_at' => '2023-12-27 11:32:26','updated_at' => '2023-12-27 11:32:26'),
            array('payment_gateway_id' => $gateway_id,'name' => 'Coingate ETH','alias' => 'add-money-coingate-eth-automatic','currency_code' => 'ETH','currency_symbol' => 'Ξ','image' => NULL,'min_limit' => '0.0001000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '0.0006100000000000','created_at' => '2023-12-27 11:32:26','updated_at' => '2023-12-27 11:32:26'),
            array('payment_gateway_id' => $gateway_id,'name' => 'Coingate BTC','alias' => 'add-money-coingate-btc-automatic','currency_code' => 'BTC','currency_symbol' => '฿','image' => NULL,'min_limit' => '0.0001000000000000','max_limit' => '100.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '0.0000360000000000','created_at' => '2023-12-27 11:32:26','updated_at' => '2023-12-27 11:32:26'),
            array('payment_gateway_id' => $gateway_id,'name' => 'Coingate USD','alias' => 'add-money-coingate-usd-automatic','currency_code' => 'USD','currency_symbol' => '$','image' => NULL,'min_limit' => '1.0000000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '1.00000000000000000','created_at' => '2023-12-27 11:32:26','updated_at' => '2023-12-27 11:32:26'),
        );
        PaymentGatewayCurrency::insert($gateway_currency);
        //============================Coingate gateway automatic end=================================================
        //============================Pagadito gateway automatic start=================================================
        $data =  array('slug' => 'add-money','code' => '245','type' => 'AUTOMATIC','name' => 'Pagadito','title' => 'Pagadito Paymnet Gateway','alias' => 'pagadito','image' => '562667d0-9251-441c-a7d4-20b9e21d885e.webp','credentials' => '[{"label":"UID","placeholder":"Enter UID","name":"uid","value":"b73eb3fa1dc8bea4b4363322c906a8fd"},{"label":"WSK","placeholder":"Enter WSK","name":"wsk","value":"dc843ff5865bac2858ad8f23af081256"},{"label":"Sandbox Base URL","placeholder":"Enter Sandbox Base URL","name":"sandbox-base-url","value":"https:\\/\\/sandbox.pagadito.com"},{"label":"Live Base URL","placeholder":"Enter Live Base URL","name":"live-base-url","value":"https:\\/\\/pagadito.com"}]','supported_currencies' => '["USD","HNL","CRC","DOP","GTQ","NIU","PAB"]','crypto' => '0','desc' => NULL,'input_fields' => NULL,'env' => 'SANDBOX','status' => '1','last_edit_by' => '1','created_at' => '2023-12-28 05:48:55','updated_at' => '2023-12-28 05:50:56');
        $gateway_id = PaymentGateway::insertGetId($data);

        $gateway_currency = array(
            array('payment_gateway_id' => $gateway_id,'name' => 'Pagadito USD','alias' => 'add-money-pagadito-usd-automatic','currency_code' => 'USD','currency_symbol' => '$','image' => NULL,'min_limit' => '1.0000000000000000','max_limit' => '1000.0000000000000000','percent_charge' => '2.0000000000000000','fixed_charge' => '0.0000000000000000','rate' => '1.0000000000000000','created_at' => '2023-12-28 05:50:56','updated_at' => '2023-12-28 07:24:30')
        );
        PaymentGatewayCurrency::insert($gateway_currency);
        //============================Pagadito gateway automatic end=================================================
        //============================Perfect Money automatic start=================================================
        $data =  array('slug' => 'add-money','code' => '20000','type' => 'AUTOMATIC','name' => 'Perfect Money','title' => 'Perfect Money Gateway','alias' => 'perfect-money','image' => '38e0dfa8-cc70-410a-a4ae-2e303b66b93d.webp','credentials' => '[{"label":"USD Account","placeholder":"Enter USD Account","name":"usd-account","value":""},{"label":"EUR Account","placeholder":"Enter EUR Account","name":"eur-account","value":""},{"label":"Alternate Passphrase","placeholder":"Enter Alternate Passphrase","name":"alternate_passphrase","value":""}]','supported_currencies' => '["USD","EUR"]','crypto' => '0','desc' => NULL,'input_fields' => NULL,'env' => 'SANDBOX','status' => '1','last_edit_by' => '1','created_at' => '2023-12-30 16:05:59','updated_at' => '2024-01-03 06:22:22');
        $gateway_id = PaymentGateway::insertGetId($data);

        $gateway_currency = array(
            array('payment_gateway_id' => $gateway_id,'name' => 'Perfect Money EUR','alias' => 'add-money-perfect-money-eur-automatic','currency_code' => 'EUR','currency_symbol' => '€','image' => NULL,'min_limit' => '1.00000000','max_limit' => '5000.00000000','percent_charge' => '2.00000000','fixed_charge' => '1.00000000','rate' => '0.90000000','created_at' => '2023-12-30 16:44:49','updated_at' => '2024-01-01 06:27:26'),
            array('payment_gateway_id' => $gateway_id,'name' => 'Perfect Money USD','alias' => 'add-money-perfect-money-usd-automatic','currency_code' => 'USD','currency_symbol' => '$','image' => NULL,'min_limit' => '1.00000000','max_limit' => '5000.00000000','percent_charge' => '2.00000000','fixed_charge' => '1.00000000','rate' => '1.00000000','created_at' => '2023-12-30 16:44:49','updated_at' => '2024-01-01 06:27:26')
        );
        PaymentGatewayCurrency::insert($gateway_currency);
        //============================Perfect Money automatic end=================================================




    }
}
