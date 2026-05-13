from django import forms
from django.contrib.auth.forms import AuthenticationForm
from .models import Threat

class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))

class ThreatForm(forms.ModelForm):
    class Meta:
        model = Threat
        fields = ['source_ip','destination_ip','protocol','packet_size','attack_type']
        widgets = {
            'source_ip': forms.TextInput(attrs={'class':'form-control'}),
            'destination_ip': forms.TextInput(attrs={'class':'form-control'}),
            'protocol': forms.NumberInput(attrs={'class':'form-control'}),
            'packet_size': forms.NumberInput(attrs={'class':'form-control'}),
            'attack_type': forms.TextInput(attrs={'class':'form-control'}),
        }
