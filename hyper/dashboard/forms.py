from django import forms
from .models import port_info
class ScanForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Name'}))
    scan_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Scan Name'}))
    address = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'IP Address'}))

class RenameScanForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'New Name'}))

class CreateAssetGroup(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'New Name'}))



class AddAssetForm(forms.Form):
    def __init__(self, user, *args, **kwargs):
        super(AddAssetForm, self).__init__(*args,**kwargs)
        self.fields['addresses'] = forms.ChoiceField(
            choices=[(ip['ip'], ip['ip']) for ip in port_info.objects.filter(user=user).values('ip').distinct()]
        )