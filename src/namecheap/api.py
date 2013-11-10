# -*- coding: utf-8 -*-
#
# Copyright (c) 2011, Martín Raúl Villalba
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import datetime
from decimal import Decimal

from namecheap.exceptions import *

NC_LIST_ALL = 'ALL'
NC_LIST_EXPIRING = 'EXPIRING'
NC_LIST_EXPIRED = 'EXPIRED'
NC_LIST_PROCESSING = 'Processing'
NC_LIST_EMAILSENT = 'EmailSent'
NC_LIST_TECHNICALPROBLEM = 'TechnicalProblem'
NC_LIST_INPROGRESS = 'InProgress'
NC_LIST_COMPLETED = 'Completed'
NC_LIST_DEACTIVATED = 'Deactivated'
NC_LIST_ACTIVE = 'Active'
NC_LIST_CANCELLED = 'Cancelled'
NC_LIST_NEWPURCHASE = 'NewPurchase'
NC_LIST_NEWRENEWAL = 'NewRenewal'
NC_SORT_NAME = 'NAME'
NC_SORT_NAME_DESC = 'NAME_DESC'
NC_SORT_EXPIREDATE = 'EXPIREDATE'
NC_SORT_EXPIREDATE_DESC = 'EXPIREDATE_DESC'
NC_SORT_CREATEDATE = 'CREATEDATE'
NC_SORT_CREATEDATE_DESC = 'CREATEDATE_DESC'
NC_SORT_DOMAINNAME = 'DOMAINNAME'
NC_SORT_DOMAINNAME_DESC = 'DOMAINNAME_DESC'
NC_SORT_TRANSFERDATE = 'TRANSFERDATE'
NC_SORT_TRANSFERDATE_DESC = 'TRANSFERDATE_DESC'
NC_SORT_STATUSDATE = 'STATUSDATE'
NC_SORT_STATUSDATE_DESC = 'STATUSDATE_DESC'
NC_SORT_PURCHASEDATE = 'PURCHASEDATE'
NC_SORT_PURCHASEDATE_DESC = 'PURCHASEDATE_DESC'
NC_SORT_SSLTYPE = 'SSLTYPE'
NC_SORT_SSLTYPE_DESC = 'SSLTYPE'
NC_SORT_EXPIREDATETIME = 'EXPIREDATETIME'
NC_SORT_EXPIREDATETIME_DESC = 'EXPIREDATETIME_DESC'
NC_SORT_HOSTNAME = 'Host_Name'
NC_SORT_HOSTNAME_DESC = 'Host_Name_DESC'
NC_RECORD_A = 'A'
NC_RECORD_AAAA = 'AAAA'
NC_RECORD_CNAME = 'CNAME'
NC_RECORD_MX = 'MX'
NC_RECORD_MXE = 'MXE'
NC_RECORD_TXT = 'TXT'
NC_RECORD_URL = 'URL'
NC_RECORD_URL301= 'URL301'
NC_RECORD_FRAME = 'FRAME'
NC_EMAIL_MXE = 'MXE'
NC_EMAIL_MX = 'MX'
NC_EMAIL_FWD = 'FWD'
NC_TRANSFER_ALL = 'ALL'
NC_TRANSFER_INPROGRESS = 'INPROGRESS'
NC_TRANSFER_CANCELLED = 'CANCELLED'
NC_TRANSFER_COMPLETED = 'COMPLETED'
NC_PRODUCT_DOMAIN = 'DOMAIN'
NC_PRODUCT_DOMAIN_REGISTER = 'REGISTER'
NC_PRODUCT_DOMAIN_RENEW = 'RENEW'
NC_PRODUCT_DOMAIN_REACTIVATE = 'REACTIVATE'
NC_PRODUCT_DOMAIN_TRANSFER = 'TRANSFER'
NC_PRODUCT_DOMAIN_WBL = 'WBL'
NC_SSL = 'SSL'
NC_SSL_COMODO = 'COMODO'
NC_SSL_GEOTRUST = 'GEOTRUST'
NC_SSL_QUICKSSL = 'QuickSSL'
NC_SSL_QUICKSSL_PREMIUM = 'QuickSSL Premium'
NC_SSL_RAPIDSSL = 'RapidSSL'
NC_SSL_RAPIDSSL_WILDCARD = 'RapidSSL Wildcard'
NC_SSL_PREMIUMSSL = 'PremiumSSL'
NC_SSL_INSTANTSSL = 'InstantSSL'
NC_SSL_POSITIVESSL = 'PositiveSSL'
NC_SSL_POSITIVESSL_WILDCARD = 'PositiveSSL Wildcard'
NC_SSL_TRUEBUSINESSID_EV = 'True BusinessID with EV'
NC_SSL_TRUEBUSINESSID = 'True BusinessID'
NC_SSL_TRUEBUSINESSID_WILDCARD = 'True BusinessID Wildcard'
NC_SSL_SECURESITE = 'Secure Site'
NC_SSL_SECURESITE_PRO = 'Secure Site Pro'
NC_SSL_SECURESITE_EV = 'Secure Site with EV'
NC_SSL_SECURESITE_PRO_EV = 'Secure Site Pro with EV'
NC_PAYMENT_CREDITCARD = 'CREDITCARD'
NC_FIND_DOMAINNAME = 'DOMAINNAME'
NC_FIND_EMAILADDRESS = 'EMAILADDRESS'
NC_FIND_USERNAME = 'USERNAME'

class NCAPI(object):
    def __init__(self, client):
        self.client = client

    def _bool(self, value):
        return True if value == 'true' else False

    def _call(self, command, args={}, method="GET"):
        doc = self.client._call('namecheap.{0}'.format(command), args, method)

        if doc['Errors']:
            system = doc['Errors']['Number'][0:2]

            if system == '10':
                raise NCAuthenticationError(doc)
            elif system == '20':
                raise NCValidationError(doc)
            elif system == '25':
                raise NCPaymentError(doc)
            elif system == '30':
                raise NCProviderError(doc)
            elif system == '35':
                raise NCPolicyError(doc)
            elif system == '40':
                raise NCSystemError(doc)
            elif system == '50':
                raise NCUnknownError(doc)
            else:
                raise NCError(doc)

        return doc

class NCDomain(NCAPI):
    def create(self, contact_data, nameservers=None, add_free_whoisguard=None,
               enable_whoisguard=None, extended_attributes=None):
        pass

    def get_contacts(self, domain):
        pass

    def set_contacts(self, domain, contact_data, extended_attributes=None):
        pass

    def renew(self, domain, years=1, coupon=None):
        args = {
            'DomainName': domain,
            'Years': years,
        }

        if coupon:
            args['PromotionCode'] = coupon

        doc = self._call('domains.renew', args)

        result = doc['CommandResponse'] \
            .findall(self.client._name('DomainRenewResult'))[0]

        assert result.attrib['DomainName'] == domain, \
               'Got an unexpected domain name.'

        ret = {
            'DomainID': int(result.attrib['DomainID']),
            'Renew': self._bool(result.attrib['Renew']),
            'OrderID': int(result.attrib['OrderID']),
            'TransactionID': int(result.attrib['TransactionID']),
            'ChargedAmount': Decimal(result.attrib['ChargedAmount']),
        }

        return ret

    def reactivate(self, domain):
        pass

    def set_registrar_lock(self, domain, lock=True):
        args = {
            'DomainName': domain,
            'LockAction': 'LOCK' if lock else 'UNLOCK',
        }
        doc = self._call('domains.setRegistrarLock', args)

        result = doc['CommandResponse'] \
            .findall(self.client._name('DomainSetRegistrarLockResult'))[0]

        assert result.attrib['Domain'] == domain, \
               'Got an unexpected domain name.'

        return self._bool(result.attrib['IsSuccess'])

    def get_registrar_lock(self, domain):
        args = {'DomainName': domain}
        doc = self._call('domains.getRegistrarLock', args)

        result = doc['CommandResponse'] \
            .findall(self.client._name('DomainGetRegistrarLockResult'))[0]

        assert result.attrib['Domain'] == domain, \
               'Got an unexpected domain name.'

        return self._bool(result.attrib['RegistrarLockStatus'])

    def get_list(self, list_type=None, search_term=None, page=None,
                 page_size=None, sort_by=None):
        args = dict()
        if list_type:
            args['ListType'] = list_type
        if search_term:
            args['SearchTerm'] = search_term
        if page:
            args['Page'] = page
        if page_size:
            args['PageSize'] = page_size
        if sort_by:
            args['SortBy'] = sort_by

        doc = self._call('domains.getList', args)

        ret = dict()
        domains = doc['CommandResponse'] \
            .findall(self.client._name('DomainGetListResult'))[0] \
            .findall(self.client._name('Domain'))

        ret['Domains'] = []
        for domain in domains:
            created = domain.attrib['Created'].split('/')
            expires = domain.attrib['Expires'].split('/')
            created = datetime.date(int(created[2]), int(created[0]),
                                    int(created[1]))
            expires = datetime.date(int(expires[2]), int(expires[0]),
                                    int(expires[1]))
            ret['Domains'].append({
                'ID': int(domain.attrib['ID']),
                'Name': domain.attrib['Name'],
                'User': domain.attrib['User'],
                'Created': created,
                'Expires': expires,
                'IsExpired': self._bool(domain.attrib['IsExpired']),
                'IsLocked': self._bool(domain.attrib['IsLocked']),
                'AutoRenew': self._bool(domain.attrib['AutoRenew']),
                'WhoisGuard': domain.attrib['WhoisGuard'],
            })

        paging = doc['CommandResponse'] \
            .findall(self.client._name('Paging'))[0]
        ret['Paging'] = {
            'TotalItems': int(paging.findall \
                          (self.client._name('TotalItems'))[0].text),
            'CurrentPage': int(paging.findall \
                           (self.client._name('CurrentPage'))[0].text),
            'PageSize': int(paging.findall \
                        (self.client._name('PageSize'))[0].text),
        }

        return ret

    def get_tld_list(self):
        doc = self._call('domains.getTldList')

        results = doc['CommandResponse'] \
            .findall(self.client._name('Tlds'))[0] \
            .findall(self.client._name('Tld'))


        ret = dict()
        for tld in results:
            ret[tld.attrib['Name']] = {
                'NonRealTime': self._bool(tld.attrib['NonRealTime']),
                'MinRegisterYears': int(tld.attrib['MinRegisterYears']),
                'MaxRegisterYears': int(tld.attrib['MaxRegisterYears']),
                'MinRenewYears': int(tld.attrib['MinRenewYears']),
                'MaxRenewYears': int(tld.attrib['MaxRenewYears']),
                'MinTransferYears': int(tld.attrib['MinTransferYears']),
                'MaxTransferYears': int(tld.attrib['MaxTransferYears']),
                'IsApiRegisterable': self._bool(
                    tld.attrib['IsApiRegisterable']),
                'IsApiRenewable': self._bool(tld.attrib['IsApiRenewable']),
                'IsApiTransferable': self._bool(
                    tld.attrib['IsApiTransferable']),
                'IsEppRequired': self._bool(tld.attrib['IsEppRequired']),
                'IsDisableModContact': self._bool(
                    tld.attrib['IsDisableModContact']),
                'IsDisableWGAllot': self._bool(tld.attrib['IsDisableWGAllot']),
                'IsIncludeInExtendedSearchOnly': \
                    self._bool(tld.attrib['IsIncludeInExtendedSearchOnly']),
            }

        return ret

    def check(self, domains):
        arg1 = ','.join(domains)
        args = {'DomainList': arg1}
        doc = self._call('domains.check', args)

        results = doc['CommandResponse'] \
            .findall(self.client._name('DomainCheckResult'))

        ret = dict()
        for domain in results:
            avail = self._bool(domain.attrib['Available'])
            ret[domain.attrib['Domain']] = avail

        return ret

class NCDomainDNS(NCAPI):
    def set_default(self, sld, tld):
        pass

    def set_custom(self, sld, tld, servers):
        pass

    def get_list(self, sld, tld):
        pass

    def get_hosts(self, sld, tld):
        pass

    def set_hosts(self, sld, tld, hostnames, record_types, addresses,
                  mxprefs=None, email_type=None, ttl=None):
        pass

    def get_email_forwarding(self, domain):
        pass

    def set_email_forwarding(self, domain, mailboxes, forwardto):
        pass

class NCDomainNS(NCAPI):
    def create(self, sld, tld, nameserver, ip):
        pass

    def delete(self, sld, tld, nameserver):
        pass

    def get_info(self, sld, tld, nameserver):
        pass

    def update(self, sld, tld, nameserver, oldip, ip):
        pass

class NCDomainTransfer(NCAPI):
    def create(self, domain, years, eppcode=None, coupon=None):
        pass

    def get_status(self, transferid):
        pass
    def update_status(self, transferid, resubmit):
        pass

    def get_list(self, list_type=None, search_term=None, page=None,
                 page_size=None, sort_by=None):
        pass

class NCSSL(NCAPI):
    def create(self, years, ssl_type, coupon=None):
        args = dict()
        if years:
            args['Years'] = years
        if ssl_type:
            args['Type'] = ssl_type
        if coupon:
            args['PromotionCode'] = coupon
        
        doc = self._call('ssl.create', args)
        
        """
        <SSLCreateResult IsSuccess="true" OrderId="3186" TransactionId="4211" ChargedAmount="30.2000">
          <SSLCertificate CertificateID="500393" Created="06/26/2010" Expires="" 
                          SSLType="SSLCertificate1" Years="2" Status="NewPurchase"/>
          </SSLCreateResult>
        """
        ret = dict()
        ssl_certs = doc['CommandResponse'] \
            .findall(self.client._name('SSLCreateResult'))[0] \
            .findall(self.client._name('SSLCertificate'))

        ret['SSLCertificates'] = []
        for ssl in ssl_certs:
            ret['SSLCertificates'].append({
                'CertificateID': int(ssl.attrib['CertificateID']),
                'Created': ssl.attrib['Created'],
                #'Expires': ssl.attrib['Expires'],
                'SSLType': ssl.attrib['SSLType'],
                'Years': ssl.attrib['Years'],
                'Status': ssl.attrib['Status'],                
            })

        return ret

    def activate(self, certificate_id, approver_email, csr, web_server_type,
                 contact_data):
        args = dict()
        args['CertificateID'] = certificate_id
        args['ApproverEmail'] = approver_email
        args['csr'] = csr
        args['WebServerType'] = web_server_type
        args['AdminJobTitle'] = contact_data['AdminJobTitle']
        args['AdminFirstName'] = contact_data['AdminFirstName']
        args['AdminLastName'] = contact_data['AdminLastName']
        args['AdminAddress1'] = contact_data['AdminAddress1']
        args['AdminCity'] = contact_data['AdminCity']
        args['AdminStateProvince'] = contact_data['AdminStateProvince']
        args['AdminPostalCode'] = contact_data['AdminPostalCode']
        args['AdminCountry'] = contact_data['AdminCountry']
        args['AdminPhone'] = contact_data['AdminPhone']
        args['AdminEmailAddress'] = contact_data['AdminEmailAddress']
        args['AdminOrganizationName'] = contact_data['AdminOrganizationName'] 
        doc = self._call('ssl.activate', args=args, method='POST')
        return doc

    def reissue(self, certificate_id, approver_email, csr, web_server_type,
                 contact_data):
        args = dict()
        args['CertificateID'] = certificate_id
        args['ApproverEmail'] = approver_email
        args['csr'] = csr
        args['WebServerType'] = web_server_type
        args['AdminJobTitle'] = contact_data['AdminJobTitle']
        args['AdminFirstName'] = contact_data['AdminFirstName']
        args['AdminLastName'] = contact_data['AdminLastName']
        args['AdminAddress1'] = contact_data['AdminAddress1']
        args['AdminCity'] = contact_data['AdminCity']
        args['AdminStateProvince'] = contact_data['AdminStateProvince']
        args['AdminPostalCode'] = contact_data['AdminPostalCode']
        args['AdminCountry'] = contact_data['AdminCountry']
        args['AdminPhone'] = contact_data['AdminPhone']
        args['AdminEmailAddress'] = contact_data['AdminEmailAddress']
        args['AdminOrganizationName'] = contact_data['AdminOrganizationName'] 
        doc = self._call('ssl.reissue', args=args, method='POST')
        return doc
        
    def get_info(self, certificate_id):
        pass

    def parse_csr(self, csr, certificate_type=None):
        args = dict()
        if csr:
            args['csr'] = csr
        if certificate_type:
            args['CertificateType'] = CertificateType
        
        doc = self._call('ssl.parseCSR', args=args, method='POST')
        
        return doc

    def get_approver_email_list(self, domain, certificate_type):
        args = dict()
        args['DomainName'] = domain
        args['CertificateType'] = certificate_type
        
        doc = self._call('ssl.getApproverEmailList', args)
        
        return doc
        
    def get_list(self, list_type=None, search_term=None, sort_by=None,
                 page=None, page_size=None):
        args = dict()
        if list_type:
            args['ListType'] = list_type
        if search_term:
            args['SearchTerm'] = search_term
        if page:
            args['Page'] = page
        if page_size:
            args['PageSize'] = page_size
        if sort_by:
            args['SortBy'] = sort_by

        doc = self._call('ssl.getList', args)

        ret = dict()
        ssl_certs = doc['CommandResponse'] \
            .findall(self.client._name('SSLListResult'))[0] \
            .findall(self.client._name('SSL'))

        ret['SSLs'] = []
        for ssl in ssl_certs:
            ret['SSLs'].append({
                'CertificateID': int(ssl.attrib['CertificateID']),
                'HostName': ssl.attrib['HostName'],
                'SSLType': ssl.attrib['SSLType'],
                'PurchaseDate': ssl.attrib['PurchaseDate'],
                'ExpireDate': ssl.attrib['ExpireDate'],
                'ActivationExpireDate': ssl.attrib['ActivationExpireDate'],
                'IsExpiredYN': self._bool(ssl.attrib['IsExpiredYN']),
                'Status': ssl.attrib['Status'],                
            })
        paging = doc['CommandResponse'] \
            .findall(self.client._name('Paging'))[0]
        ret['Paging'] = {
            'TotalItems': int(paging.findall \
                          (self.client._name('TotalItems'))[0].text),
            'CurrentPage': int(paging.findall \
                           (self.client._name('CurrentPage'))[0].text),
            'PageSize': int(paging.findall \
                        (self.client._name('PageSize'))[0].text),
        }

        return ret
                
    def resend_approver_email(self, certificate_id):
        args = dict()
        args['CertificateID'] = certificate_id
        
        doc = self._call('ssl.resendApproverEmail', args)
        
        return doc    

    def resend_fullfillment_email(self, certificate_id):
        args = dict()
        args['CertificateID'] = certificate_id
        
        doc = self._call('ssl.resendfulfillmentemail', args)
        
        return doc    

class NCUser(NCAPI):
    def create(self, username, password, email, acept_terms, accept_news,
               contact_data, ignore_duplicates=None):
        pass

    def get_pricing(self, product_type, product_category=None, coupon=None):
        pass

    def get_balances(self):
        pass

    def change_password(self, old_password, new_password):
        pass
    def update(self, contact_data):
        pass

    def create_add_funds_request(self, username, amount, return_url,
                                 payment_type=NC_PAYMENT_CREDITCARD):
        pass

    def get_add_funds_status(self, tokenid):
        pass

    def login(self, password):
        pass

    def reset_password(self, find_by, find_by_value, email_from_name=None,
                       email_from_address=None, url_pattern=None):
        pass

class NCUserAddress(NCAPI):
    def create(self, address_name, contact_data, default=None):
        pass

    def update(self, address_id, address_name, contact_data, default=None):
        pass
    def delete(self, address_id):
        pass

    def get_list(self):
        pass

    def get_info(self, address_id):
        pass

    def set_default(self, address_id):
        pass

