from django import forms
from django.db.models import fields
from django.forms.widgets import HiddenInput
from .models import asset, port_info, asset_group
class ScanForm(forms.Form):
    #name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Name'}))
    scan_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Scan Name'}))
    address = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'EX: 192.168.1.1, 192.168.1.10-192.168.1.15, 192.168.2.0/24'}),
                            required=False)
    CHOICES =[
        ('all_ports', 'All Ports'),
        ('top', 'Top 1000'),
        ('custom', 'Custom Range')
    ]
    ports = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect)
    custom_range = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'port range'}), required=False)
    def __init__(self, user, *args, **kwargs):
        super(ScanForm, self).__init__(*args,**kwargs)
        self.fields['asset_groups'] = forms.MultipleChoiceField(
            choices = [(group['name'], group['name']) for group in asset_group.objects.filter(user=user).values('name').distinct()],
            required=False
            )
        self.fields['asset_groups'].widget.attrs.update({'class':'form-control', 'multiple': ''})

class RenameScanForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'New Name'}))

class CreateAssetGroup(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'New Name'}))
    def __init__(self, user, *args, **kwargs):
        super(CreateAssetGroup, self).__init__(*args,**kwargs)
        self.fields['Add_Addresses'] = forms.MultipleChoiceField(
            choices=[(ip['ip'], ip['ip']) for ip in port_info.objects.filter(user=user).values('ip').distinct()],
            required=False
        )
        self.fields['Add_Addresses'].widget.attrs.update({'class':'form-control','multiple': ''})


class AddAssetForm(forms.Form):
    def __init__(self, user, *args, **kwargs):
        super(AddAssetForm, self).__init__(*args,**kwargs)
        self.fields['Add_Addresses'] = forms.MultipleChoiceField(
            choices=[(ip['ip'], ip['ip']) for ip in port_info.objects.filter(user=user).values('ip').distinct()],
        )
        #self.fields['Add Addresses'].widget.attrs.update({'class':'form-control select2-selection--multiple','multiple': ''})

class DeleteAssetForm(forms.Form):
    def __init__(self, user,groupid, *args, **kwargs):
        super(DeleteAssetForm, self).__init__(*args,**kwargs)
        self.fields['Remove_Addresses'] = forms.MultipleChoiceField(
            choices=[(ip['address'], ip['address']) for ip in asset.objects.filter(user=user, group=groupid).values('address').distinct()],
        )
        self.fields['Remove_Addresses'].widget.attrs.update({'class':'form-control','multiple': ''})

class AssetScanForm(forms.Form):
    #name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Name'}))
    scan_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Scan Name'}))
    CHOICES =[
        ('all_ports', 'All Ports'),
        ('top', 'Top 1000'),
        ('custom', 'Custom Range')
    ]
    ports = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect)
    custom_range = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'port range'}), required=False)