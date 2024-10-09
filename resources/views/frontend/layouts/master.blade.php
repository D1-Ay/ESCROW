<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ (isset($page_title) ? __($page_title) : __("Public")) }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@100;200;300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    @include('partials.header-asset')
    @stack('css')
</head>
<body class="{{ selectedLangDir() ?? "ltr"}}">
    <main> 
        @include('frontend.partials.preloader')
        @include('frontend.partials.body-overlay') 
        @include('frontend.partials.scroll-to-top')
        @include('frontend.partials.header')
        @yield("content")
        @include('frontend.partials.footer')
        @include('partials.footer-asset') 
    </main>
    @stack('script') 
    <script>
        $(document).ready(function () {
            $(".language-select").change(function(){ 
                var submitForm = `<form action="{{ setRoute('languages.switch') }}" id="local_submit" method="POST"> @csrf <input type="hidden" name="target" value="${$(this).val()}" ></form>`;
                $("body").append(submitForm);
                $("#local_submit").submit();
            });
        });
    </script>
</body>
</html>