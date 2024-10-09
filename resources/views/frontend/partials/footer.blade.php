@php 
    $pages = App\Models\Admin\SetupPage::where(['type' => 'useful-links', 'status' => true])->get();
@endphp
<!--~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Start Footer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-->
<footer class="footer-section section--bg">
    <div class="circle-blur"></div>
    <div class="container">
        <div class="footer-wrapper">
            <div class="footer-logo">
                <a class="site-logo" href="{{ setRoute('index') }}"><img src="{{ get_logo($basic_settings) }}" alt="logo"></a>
            </div>
            <ul class="footer-list">
                <li>
                    <a href="{{ setRoute('faq') }}" target="_blanck">{{ __('FAQ') }}</a>
                </li>
                @foreach ($pages as $item)
                <li>
                    <a href="{{ route('page.view',$item->slug) }}" target="_blanck">{{ __($item->title) }}</a>
                </li>
                @endforeach
            </ul>
            <div class="copyright-area">
                <p>{{ __('Made by') }} <span class="gradient-text">{{ $basic_settings->site_name }}</span></p>
            </div>
        </div>
    </div>
</footer>
<!--~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    End Footer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~-->