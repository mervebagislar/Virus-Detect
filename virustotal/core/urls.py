# -*- encoding: utf-8 -*-
from django.views.generic import RedirectView

from django.contrib import admin
from django.urls import path, include  # add this

urlpatterns = [
    path('admin/', admin.site.urls),          # Django admin route
    path('', RedirectView.as_view(url='/notification/')),
    path("", include("apps.authentication.urls")), # Auth routes - login / register
    path('two_factor/', include(('admin_two_factor.urls', 'admin_two_factor'), namespace='two_factor')),
    path('api/', include('apps.predictor.urls')),
    # ADD NEW Routes HERE

    # Leave `Home.Urls` as last the last line
    path("", include("apps.home.urls"))
]
