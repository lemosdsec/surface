# Generated by Django 3.2.8 on 2021-11-02 10:46

import core_utils.fields
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import dns_ips.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DNSDomain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('last_seen', models.DateTimeField(blank=True, db_index=True, default=django.utils.timezone.now, editable=False, null=True)),
                ('name', models.CharField(db_index=True, max_length=255, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('registration_date', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('expire_date', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('raw_whois', models.TextField(blank=True, null=True)),
                ('register_management_status', models.BooleanField(db_index=True, default=False)),
                ('register_dns_managed', models.BooleanField(db_index=True, default=False)),
                ('register_csc_lock', models.BooleanField(db_index=True, default=False)),
                ('register_masking', models.BooleanField(db_index=True, default=False)),
                ('register_registrant_name', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('register_registrant_organisation', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('register_registrant_address', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_postcode', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_city', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_state', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_country', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_phone', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_fax', models.CharField(blank=True, max_length=255, null=True)),
                ('register_registrant_email', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('register_admin_name', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_organisation', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_address', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_postcode', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_city', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_state', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_country', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_phone', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_fax', models.CharField(blank=True, max_length=255, null=True)),
                ('register_admin_email', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_name', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_organisation', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_address', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_postcode', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_city', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_state', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_country', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_phone', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_fax', models.CharField(blank=True, max_length=255, null=True)),
                ('register_technical_email', models.CharField(blank=True, max_length=255, null=True)),
                ('register_portfolio_sections', models.CharField(blank=True, max_length=255, null=True)),
                ('register_account_name', models.CharField(blank=True, max_length=255, null=True)),
                ('register_tld_region', models.CharField(blank=True, max_length=255, null=True)),
                ('register_tld_country', models.CharField(blank=True, max_length=255, null=True)),
                ('register_email', models.CharField(blank=True, max_length=255, null=True)),
                ('register_puny_code', models.CharField(blank=True, max_length=255, null=True)),
                ('register_comment', models.TextField(blank=True, null=True)),
                ('register_registrar', models.CharField(blank=True, max_length=255, null=True)),
                ('register_cost_center', models.CharField(blank=True, max_length=255, null=True)),
                ('register_website', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'verbose_name': 'DNS Domain',
                'verbose_name_plural': 'DNS Domains',
            },
        ),
        migrations.CreateModel(
            name='DNSNameserver',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('active', models.BooleanField(default=True)),
                ('last_seen', models.DateTimeField(blank=True, default=django.utils.timezone.now, editable=False, null=True)),
                ('name', models.CharField(max_length=255, null=True)),
            ],
            options={
                'verbose_name': 'DNS Nameserver',
                'verbose_name_plural': 'DNS Nameservers',
            },
        ),
        migrations.CreateModel(
            name='DNSRecord',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('last_seen', models.DateTimeField(blank=True, db_index=True, default=django.utils.timezone.now, editable=False, null=True)),
                ('name', models.CharField(db_index=True, max_length=255, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dns_ips.dnsdomain')),
            ],
            options={
                'verbose_name': 'DNS Record',
            },
        ),
        migrations.CreateModel(
            name='IPRange',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('range', models.CharField(max_length=100)),
                ('range_min', core_utils.fields.UnsignedIntegerField(blank=True, null=True)),
                ('range_max', core_utils.fields.UnsignedIntegerField(blank=True, null=True)),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('last_seen', models.DateTimeField(blank=True, db_index=True, default=django.utils.timezone.now, editable=False, null=True)),
                ('vlan', models.CharField(blank=True, max_length=255, null=True)),
                ('zone', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('datacenter', models.CharField(blank=True, max_length=255, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'IP Range',
                'verbose_name_plural': 'IP Ranges',
            },
        ),
        migrations.CreateModel(
            name='Source',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('function', models.CharField(db_index=True, max_length=255)),
                ('owner', models.CharField(db_index=True, max_length=255)),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('last_sync', models.DateTimeField(db_index=True, default=django.utils.timezone.now, editable=False)),
                ('notes', models.TextField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'Source',
                'verbose_name_plural': 'Sources',
            },
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('notes', models.TextField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'DNS & IPs Tag',
                'verbose_name_plural': 'DNS & IPs Tags',
            },
        ),
        migrations.CreateModel(
            name='Organisation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_key', models.CharField(blank=True, max_length=255, null=True)),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('name', models.CharField(max_length=255)),
                ('owned_by_us', models.BooleanField(db_index=True, default=False)),
                ('whitelisted_to_be_scanned', models.BooleanField(db_index=True, default=False)),
                ('point_of_contact', models.CharField(blank=True, max_length=1024, null=True)),
                ('country', models.CharField(blank=True, max_length=255, null=True)),
                ('email', models.CharField(blank=True, max_length=255, null=True)),
                ('website', models.CharField(blank=True, max_length=512, null=True)),
                ('owner', models.CharField(blank=True, max_length=255, null=True)),
                ('key_supplier', models.CharField(blank=True, max_length=255, null=True)),
                ('manufacturer', models.CharField(blank=True, max_length=255, null=True)),
                ('customer', models.CharField(blank=True, max_length=255, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('source', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dns_ips.source')),
            ],
            options={
                'verbose_name': 'Organisation',
                'verbose_name_plural': 'Organisations',
            },
        ),
        migrations.CreateModel(
            name='IPRangeThirdParty',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sn_ref', models.CharField(blank=True, max_length=64, null=True)),
                ('expected_traffic', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('expected_ports', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('expected_protocol', models.CharField(blank=True, db_index=True, max_length=255, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('organisation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dns_ips.organisation')),
                ('range', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dns_ips.iprange')),
            ],
            options={
                'verbose_name': 'IP Range - Third Party (SN)',
                'verbose_name_plural': 'IP Ranges - Third Parties (SN)',
            },
        ),
        migrations.AddField(
            model_name='iprange',
            name='source',
            field=models.ForeignKey(default=dns_ips.models.default_source_unknown, on_delete=django.db.models.deletion.CASCADE, to='dns_ips.source'),
        ),
        migrations.CreateModel(
            name='IPAddress',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('active', models.BooleanField(db_index=True, default=True)),
                ('last_seen', models.DateTimeField(blank=True, db_index=True, default=django.utils.timezone.now, editable=False, null=True)),
                ('name', models.GenericIPAddressField(db_index=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('organisation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dns_ips.organisation')),
                ('organisation_ip_owner', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='organisation_ip_owner', to='dns_ips.organisation')),
                ('source', models.ForeignKey(default=dns_ips.models.default_source_unknown, on_delete=django.db.models.deletion.CASCADE, related_name='dns_ips_source', to='dns_ips.source')),
                ('tags', models.ManyToManyField(blank=True, to='dns_ips.Tag')),
            ],
            options={
                'verbose_name': 'IP Address',
                'verbose_name_plural': 'IP Addresses',
            },
        ),
        migrations.CreateModel(
            name='DNSRecordValue',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rtype', models.CharField(choices=[('A', 'A'), ('CNAME', 'Cname'), ('TXT', 'Txt'), ('SPF', 'Spf'), ('MX', 'Mx'), ('DKIM', 'Dkim'), ('DMARC', 'Dmarc'), ('SRV', 'Srv'), ('SOA', 'Soa'), ('PTR', 'Ptr'), ('NS', 'Ns'), ('AAAA', 'Aaaa'), ('APEXALIAS', 'Apexalias'), ('LB', 'Lb'), ('CAA', 'Caa')], db_index=True, max_length=10, verbose_name='Record Type')),
                ('ttl', models.IntegerField(default=None, null=True, verbose_name='TTL')),
                ('value', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('ips', models.ManyToManyField(blank=True, related_name='dnsrecordvalue_ips', to='dns_ips.IPAddress', verbose_name='IPs')),
                ('record', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dns_ips.dnsrecord')),
            ],
            options={
                'verbose_name': 'DNS Record Value',
            },
        ),
        migrations.AddField(
            model_name='dnsrecord',
            name='source',
            field=models.ForeignKey(default=dns_ips.models.default_source_unknown, on_delete=django.db.models.deletion.CASCADE, related_name='dnsrecord_source', to='dns_ips.source'),
        ),
        migrations.AddField(
            model_name='dnsrecord',
            name='tags',
            field=models.ManyToManyField(blank=True, to='dns_ips.Tag'),
        ),
    ]
