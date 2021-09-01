from django import forms

class ScanForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Name'}))
    scan_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Scan Name'}))
    address = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'IP Address'}))

class RenameScanForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'New Name'}))