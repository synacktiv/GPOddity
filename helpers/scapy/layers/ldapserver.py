import re
import json
import copy
import socket
import base64
import traceback

from scapy.supersocket import StreamSocket
from scapy.automaton import ATMT, Automaton
from scapy.packet import NoPayload

from scapy.error import log_runtime, log_interactive
from scapy.config import conf

from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.ntlm import NTLMSSP, NTLM_CHALLENGE
from scapy.layers.kerberos import KerberosSSP, KRB_InnerToken, KRB_GSS_Wrap

from scapy.layers.ldap import (
    LDAP,
    LDAP_BindRequest,
    LDAP_BindResponse,
    LDAP_Control,
    LDAP_SASL_Buffer,
    LDAP_Authentication_simple,
    LDAP_Authentication_sicilyPackageDiscovery,
    LDAP_Authentication_SaslCredentials,
    LDAP_SearchRequest,
    LDAP_ModifyRequest,
    LDAP_ModifyResponse,
    LDAP_AddRequest,
    LDAP_AddResponse,
    LDAP_DelRequest,
    LDAP_DelResponse,
    LDAP_SearchResponseEntry,
    LDAP_SearchResponseResultDone,
    LDAP_PartialAttribute,
    LDAP_AttributeValue,
    LDAP_FilterAnd,
    LDAP_FilterOr,
    LDAP_FilterNot,
    LDAP_FilterEqual,
    LDAP_FilterApproxMatch,
    LDAP_SubstringFilter,
    LDAP_FilterGreaterOrEqual,
    LDAP_FilterLessOrEqual,
    LDAP_FilterPresent,
    LDAP_FilterExtensibleMatch,
    LDAP_SASL_GSSAPI_SsfCap,
    LSAP_SASL_GSSAPI_SsfCap_Wrapped,
    LDAP_Authentication_SaslCredentials,
    LDAP_Exception
)

from scapy.layers.gssapi import GSSAPI_BLOB, GSS_S_COMPLETE, GSSAPI_BLOB_SIGNATURE, GSS_C_FLAGS

from scapy.asn1.asn1 import (
    ASN1_STRING
)
from scapy.asn1fields import (
    ASN1F_STRING
)

from typing import List

LDAP_SEARCH_SCOPES = {
    "BASE": 0,
    "LEVEL": 1,
    "SUBTREE": 2
}

LDAP_STATUS_CODES = {
    'success': 0,
    'operationsError': 1,
    'protocolError': 2,
    'timeLimitExceeded': 3,
    'sizeLimitExceeded': 4,
    'compareFalse': 5,
    'compareTrue': 6,
    'authMethodNotSupported': 7,
    'strongerAuthRequired': 8,
    'referral': 10,
    'adminLimitExceeded': 11,
    'saslBindInProgress': 14,
    'noSuchAttribute': 16,
    'undefinedAttributeType': 17,
    'inappropriateMatching': 18,
    'constraintViolation': 19,
    'attributeOrValueExists': 20,
    'invalidAttributeSyntax': 21,
    'noSuchObject': 32,
    'aliasProblem': 33,
    'invalidDNSyntax': 34,
    'isLeaf': 35,
    'aliasDereferencingProblem': 36,
    'inappropriateAuthentication': 48,
    'invalidCredentials': 49,
    'insufficientAccessRights': 50,
    'busy': 51,
    'unavailable': 52,
    'unwillingToPerform': 53,
    'loopDetect': 54,
    'namingViolation': 64,
    'objectClassViolation': 65,
    'notAllowedOnNonLeaf': 66,
    'notAllowedOnRDN': 67,
    'entryAlreadyExists': 68,
    'objectClassModsProhibited': 69,
    'resultsTooLarge': 70,
    'other': 80
}

LDAP_ERROR_MESSAGES = {
    "UNSUPPORTED_AUTH": "Unsupported authentication method. Supported authentications are: SIMPLE, GSSAPI and GSS-SPNEGO",
    "SEARCH_BEFORE_BIND": "This operation can only be performed after a successful bind was completed on the connection",
    "INVALID_ROOT_DSE_SEARCH": "Invalid ROOT dse search",
    "GENERIC_SEARCH_FAILED": "Search operation failed",
}

LDAP_SCOPES = {
    "BASE": 0,
    "LEVEL": 1,
    "SUBTREE": 2
}

LDAP_SEARCH_ATTRIBUTES = {
    "ALL_ATTRIBUTES": "*",
    "ALL_OPERATIONAL_ATTRIBUTES": "+",
    "NO_ATTRIBUTES": "1.1"
}

LDAP_MODIFY_CODES = {
    "ADD": 0,
    "DELETE": 1,
    "REPLACE": 2
}


class LDAPStreamSocket(StreamSocket):

    def __init__(self, *args, **kwargs):
        self.ssp = kwargs.pop("ssp", None)
        self.sspcontext = kwargs.pop("sspcontext", None)
        self.sasl_wrap = kwargs.pop("sasl_wrap", False)
        self.encrypt = kwargs.pop("encrypt", False)
    
        super(LDAPStreamSocket, self).__init__(*args, **kwargs)

    def recv(self, x=None):
        pkt = super(LDAPStreamSocket, self).recv(x)
        if self.sasl_wrap:
            # Some non-Microsoft LDAP clients do not set the RRC flag to 12 when using GSS-API Kerberos AES tokens without encryption,
            # resulting in the payload not being at the end of the packet, which is however assumed by Scapy.
            # If that is the case, fix this before unwrapping
            # TODO add a condition here, this is only useful for AES
            if isinstance(self.ssp, KerberosSSP) and self.encrypt == False \
                and isinstance(pkt.Buffer.root, KRB_GSS_Wrap) and pkt.Buffer.root.RRC != 12:
                pkt.Buffer.root.Data += bytes(pkt.Buffer.payload)
                pkt.Buffer.payload = NoPayload()

            if isinstance(pkt, LDAP_SASL_Buffer):
                pkt = LDAP(
                    self.ssp.GSS_Unwrap(self.sspcontext, pkt.Buffer)
                    )
        return pkt

    def send(self, pkt, **kwargs):
        if self.sasl_wrap:
            pkt = LDAP_SASL_Buffer(
                    Buffer=self.ssp.GSS_Wrap(
                        self.sspcontext,
                        bytes(pkt),
                        conf_req_flag=self.encrypt,
                    )
                )
        return super(LDAPStreamSocket, self).send(pkt, **kwargs)


class LDAP_Server(Automaton):
    """
    LDAP server automaton

    :param data: the JSON file containing the LDAP server data
    :param ssp: the SSP to use

    Optional LDAP parameters
    :param ROOT_DSE: a dict representing the root DSE data for the LDAP server
                    The key (corresponding to the empty string) should be omitted,
                    only provide the root DSE attributes
    :param ACCEPT_EXTENSIBLE: controls whether the LDAP server should evaluate
                    extensible filters as true or false (default: False)
    :param REQUIRE_SIGNING: whether the LDAP server requires message signature.
                    Only available with SASL authentication, not simple bind
    :param REQUIRE_ENCRYPTION: whether the LDAP server requires message encryption.
                    Only available with SASL authentication, not simple bind.
                    Will be preferred over message signing if both are required.
    """

    pkt_cls = LDAP
    socketcls = LDAPStreamSocket

    def __init__(self, data, ssp, verb=2, *args, **kwargs):
        if "sock" not in kwargs:
            raise ValueError(
                "LDAP_Server cannot be started directly ! Use LDAP_Server.spawn"
            )
        Automaton.__init__(self, *args, **kwargs)
        
        
        self.verb = verb
        self.sock = kwargs.pop("sock")
        # Load LDAP data
        self.data_src = data
        with open(data, "r") as f:
            self.data = json.load(f)
        # Add root DSE to LDAP. Provide default values if user did not specify it
        self.ROOT_DSE = kwargs.pop("ROOT_DSE", None)
        if self.ROOT_DSE is not None:
            self.data[""] = self.ROOT_DSE
        else:
            self.data[""] = {
                "objectClass": ["top", "ScapyLDAProotDSE"],
                # RFC 4512 5.1
                "altServer": [],
                "namingContexts": [key for key in self.data.keys()],
                "supportedControl": [],
                "supportedExtension": [],
                "supportedFeatures": [],
                "supportedLDAPVersion": [3],
                "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO"],

                # Additional
                "defaultNamingContext": [list(self.data.keys())[0]],
                "rootDomainNamingContext": [list(self.data.keys())[0]],
            }

        # SSP handling
        self.sock.ssp = ssp
        if not isinstance(self.sock.ssp, SPNEGOSSP) \
            and not isinstance(self.sock.ssp, KerberosSSP):
            raise ValueError("Unsupported SSP")
        '''
        if isinstance(self.sock.ssp, SPNEGOSSP):
            if len(self.sock.ssp.ssps) != 1:
                raise ValueError("Unsupported SSP")
            if not isinstance(self.sock.ssp.ssps[0], KerberosSSP):
                raise ValueError("Unsupported SSP")
        '''
        # LDAP options
        self.ACCEPT_EXTENSIBLE = kwargs.pop("ACCEPT_EXTENSIBLE", False)
        self.REQUIRE_SIGNING = kwargs.pop("REQUIRE_SIGNING", False)
        self.REQUIRE_ENCRYPTION = kwargs.pop("REQUIRE_ENCRYPTION", False)

        # Session data
        self.messageID = None


    def vprint(self, s=""):
            """
            Verbose print (if enabled)
            """
            if self.verb >= 1:
                if conf.interactive:
                    log_interactive.info("> %s", s)
                else:
                    print("> %s" % s)

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.state()
    def RECEIVED_BIND_REQUEST(self):
        pass

    @ATMT.receive_condition(BEGIN)
    def receive_prebind_search_request(self, pkt):
        if LDAP_SearchRequest in pkt:
            # Before binding, only allow root DSE searches
            if pkt[LDAP_SearchRequest].baseObject.val.decode("utf-8") != "":
                resp = LDAP_SearchResponseResultDone(
                    resultCode=LDAP_STATUS_CODES["operationsError"],
                    matchedDN="",
                    diagnosticMessage=LDAP_ERROR_MESSAGES["SEARCH_BEFORE_BIND"],
                    referral=None,
                )
                resp = LDAP(
                    protocolOp=resp,
                    messageID=self.messageID
                )
                self.sock.send(resp)

            self.root_dse_search(pkt)
            raise self.BEGIN()


    @staticmethod
    def valid_root_dse_search(base, scope, filter):
        if base != "":
            return False
        if scope != LDAP_SCOPES["BASE"]:
            return False
        if not isinstance(filter, LDAP_FilterPresent):
            return False
        if not filter.present.val.decode("utf-8").lower() == "objectclass":
            return False
        return True
        
    def root_dse_search(self, pkt):
        # RFC 4512 - an LDAP server shall provide information about itself and other related servers
        # in the root DSE, which is named with the DN with zero RDNs (zero-length string)
        # This request should have BASE scope, (objectClass=*) filter. It can be performed before binding

        self.messageID = pkt.messageID
        self.vprint("Received a root DSE search")

        base = pkt[LDAP_SearchRequest].baseObject.val.decode("utf-8")
        scope = pkt[LDAP_SearchRequest].scope.val
        filter = pkt[LDAP_SearchRequest].filter.filter
        attributes = [attribute.type.val.decode("utf-8") for attribute in pkt[LDAP_SearchRequest].attributes]

        # Verify the validity of the root DSE search query
        if not LDAP_Server.valid_root_dse_search(base, scope, filter):
            resp = LDAP_SearchResponseResultDone(
                    resultCode=LDAP_STATUS_CODES["operationsError"],
                    matchedDN="",
                    diagnosticMessage=LDAP_ERROR_MESSAGES["INVALID_ROOT_DSE_SEARCH"],
                    referral=None,
                )
            resp = LDAP(
                protocolOp=resp,
                messageID=self.messageID
            )
            self.sock.send(resp)
        else:
            resp = self.perform_search(base, scope, filter, attributes)
            self.sock.send(resp)

    @ATMT.receive_condition(BEGIN)
    def receive_bind_request(self, pkt):
        # Here we handle bind requests emitted by new clients
        if LDAP_BindRequest in pkt:
            self.messageID = pkt.messageID
            ssp_blob = pkt.protocolOp.authentication.credentials
            mechanism = pkt.protocolOp.authentication.mechanism
            raise self.RECEIVED_BIND_REQUEST().action_parameters(pkt, mechanism, ssp_blob)

    @ATMT.action(receive_bind_request)
    def on_bind_request(self, pkt, mechanism, ssp_blob):
        
        # On reception of the bind request, see if we support the bind mechanism specified by the client
        # Try to adapt the current SSP when possible (GSSAPI <-> SPNEGOSSP)
        if self.sock.ssp is None:
            supported = False
            if mechanism.val == b"GSS-SPNEGO":
                if isinstance(self.sock.ssp, SPNEGOSSP):
                    supported = True
                elif isinstance(self.sock.ssp, KerberosSSP):
                    self.sock.ssp = SPNEGOSSP([self.sock.ssp])
                    supported = True
            elif mechanism.val == b"GSSAPI":
                if isinstance(self.sock.ssp, KerberosSSP):
                    supported = True
                elif isinstance(self.sock.ssp, SPNEGOSSP):
                    self.sock.ssp = self.sock.ssp.ssps[0]
                    supported = True

            if supported == False:
                log_runtime.warning(f"Client requested an unsupported authentication mechanism {mechanism.val}")
                bindresponse = LDAP_BindResponse(
                        resultCode=LDAP_STATUS_CODES["authMethodNotSupported"],
                        diagnosticMessage=LDAP_ERROR_MESSAGES["UNSUPPORTED_AUTH"],
                        serverSaslCreds=None,
                        serverSaslCredsWrap=None,
                        referral=None
                    )
                resp = LDAP(
                        messageID=self.messageID,
                        protocolOp=bindresponse,
                        Controls=None,
                    )
                self.sock.send(resp)
                raise self.BEGIN()

        self.sock.sspcontext, tok, status = self.sock.ssp.GSS_Accept_sec_context(
            self.sock.sspcontext,
            ssp_blob,
        )

        if tok and status != GSS_S_COMPLETE:
            bindresponse = LDAP_BindResponse(
                    resultCode=LDAP_STATUS_CODES["saslBindInProgress"],
                    serverSaslCreds=tok,
                    serverSaslCredsWrap=None,
                    referral=None
                )
            resp = LDAP(
                    messageID=self.messageID,
                    protocolOp=bindresponse,
                    Controls=None,
                )
            self.sock.send(resp)
            raise self.BEGIN()

        if status == GSS_S_COMPLETE:
            # Print the security layers supported by the client
            self.vprint("After accepting security context, req_flags are:")
            for flag in GSS_C_FLAGS:
                if flag & self.sock.sspcontext.flags:
                    self.vprint(flag.name)

            if mechanism.val == b"GSS-SPNEGO":
                # When using SPNEGO, the negotiation of the SASL SSF is based on
                # the client's specification of supported SSF mechanisms in the 
                # GSS initial exchange - e.g. in the Kerberos AP-REQ or NTLM flags
                conf_avail = False
                integ_avail = False
                if GSS_C_FLAGS.GSS_C_CONF_FLAG & self.sock.sspcontext.flags:
                    conf_avail = True
                elif GSS_C_FLAGS.GSS_C_INTEG_FLAG & self.sock.sspcontext.flags:
                    integ_avail = True
                
                # For NTLM in the GSSAPI-SPNEGO context, if a session key was negotiated,
                # assume that the client will encrypt exchanges.
                # This is assumed by Scapy (gssapi.py Gss_Unwrap, conf_req_flag set to True combined with 
                # ntlm.py Gss_Unwrap_Ex function) and corresponds to the behaviour of clients using GSSAPI
                if isinstance(self.sock.sspcontext.ssp, NTLMSSP):
                    if self.sock.sspcontext.chall_tok.NegotiateFlags.NEGOTIATE_KEY_EXCH \
                        and self.sock.sspcontext.SessionKey:
                        conf_avail = True
                
                if (self.REQUIRE_ENCRYPTION == True and not conf_avail) \
                or (self.REQUIRE_SIGNING == True and (not conf_avail and not integ_avail)):
                    bindresponse = LDAP_BindResponse(
                            resultCode=LDAP_STATUS_CODES["strongerAuthRequired"],
                            diagnosticMessage="Client supported Quality of Protection does not meet server requirements",
                            serverSaslCreds=None,
                            serverSaslCredsWrap=None,
                            referral=None
                        )
                    resp = LDAP(
                            messageID=self.messageID,
                            protocolOp=bindresponse,
                            Controls=None,
                        )
                    self.sock.send(resp)
                    raise self.BEGIN()

                bindresponse = LDAP_BindResponse(
                    resultCode=LDAP_STATUS_CODES["success"],
                    serverSaslCreds=tok,
                    serverSaslCredsWrap=None,
                    referral=None
                )
                resp = LDAP(
                    messageID=self.messageID,
                    protocolOp=bindresponse,
                    Controls=None,
                )
                self.sock.send(resp)
                # We always support confidentiality or integrity when the client requests it
                if conf_avail:
                    self.sock.sasl_wrap = True
                    self.sock.encrypt = True
                elif integ_avail:
                    self.sock.sasl_wrap = True

                raise self.BOUND()

            elif mechanism.val == b"GSSAPI":
                bindresponse = LDAP_BindResponse(
                    resultCode=LDAP_STATUS_CODES["saslBindInProgress"],
                    serverSaslCreds=tok,
                    serverSaslCredsWrap=None,
                    referral=None
                )
                resp = LDAP(
                    messageID=self.messageID,
                    protocolOp=bindresponse,
                    Controls=None,
                )
                self.sock.send(resp)
                raise self.GSSAPI_BIND_STEP_1()
        raise self.BEGIN()
    

    @ATMT.state()
    def GSSAPI_BIND_STEP_1(self):
        pass
    @ATMT.state()
    def GSSAPI_BIND_STEP_2(self):
        pass

    @ATMT.receive_condition(GSSAPI_BIND_STEP_1)
    def receive_GSSAPI_step_1(self, pkt):
        if LDAP_BindRequest in pkt:
            self.messageID = pkt.messageID

            # Note that max_output_token_size must be 0 if supported security layers is NONE
            krb_inner_token = self.sock.ssp.GSS_Wrap(
                    self.sock.sspcontext,
                    bytes(LDAP_SASL_GSSAPI_SsfCap(
                        supported_security_layers="NONE+INTEGRITY+CONFIDENTIALITY",
                        max_output_token_size=10485760
                        )
                    ),
                    conf_req_flag=False, # not encrypting this
                )
            bindresponse = LDAP_BindResponse(
                    resultCode=LDAP_STATUS_CODES["saslBindInProgress"],
                    serverSaslCreds=krb_inner_token,
                    serverSaslCredsWrap=None,
                    referral=None
                )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=bindresponse,
                Controls=None,
            )
            self.sock.send(resp)
            raise self.GSSAPI_BIND_STEP_2()

    @ATMT.receive_condition(GSSAPI_BIND_STEP_2)
    def receive_GSSAPI_step_2(self, pkt):
        if LDAP_BindRequest in pkt:
            self.messageID = pkt.messageID

            # Parse the security layers chosen by the client
            client_ssf_wrapped = pkt[LDAP_BindRequest].authentication.credentials

            # Some non-Microsoft LDAP clients do not set the RRC flag to 12 for Kerberos tokens without encryption.
            # This results in the payload not being at the end of the packet, which is assumed by Scapy.
            # Fix the issue by appending the "payload" detected by Scapy (which will be a part of the checksum) to the Data
            if client_ssf_wrapped.credentials.payload:
                if isinstance(client_ssf_wrapped.credentials.root, KRB_GSS_Wrap):
                    if client_ssf_wrapped.credentials.root.RRC != 12:
                        client_ssf_wrapped.credentials.root.Data += bytes(client_ssf_wrapped.credentials.payload)
                        client_ssf_wrapped.credentials.payload = NoPayload()
    
            client_ssf = self.sock.ssp.GSS_Unwrap(
                self.sock.sspcontext, signature=client_ssf_wrapped.credentials
                )
            client_ssf = LDAP_SASL_GSSAPI_SsfCap(client_ssf)
            self.vprint(f"Client supported security layers: {client_ssf.supported_security_layers}")
            self.vprint(f"Client max output token size: {client_ssf.max_output_token_size}")

            conf_avail = False
            integ_avail = False
            if client_ssf.supported_security_layers.CONFIDENTIALITY:
                conf_avail = True
            if client_ssf.supported_security_layers.INTEGRITY:
                integ_avail = True

            if (self.REQUIRE_ENCRYPTION == True and not conf_avail) \
            or (self.REQUIRE_SIGNING == True and (not conf_avail and not integ_avail)):
                bindresponse = LDAP_BindResponse(
                        resultCode=LDAP_STATUS_CODES["strongerAuthRequired"],
                        diagnosticMessage="Client supported Quality of Protection does not meet server requirements",
                        serverSaslCreds=None,
                        serverSaslCredsWrap=None,
                        referral=None
                    )
                resp = LDAP(
                        messageID=self.messageID,
                        protocolOp=bindresponse,
                        Controls=None,
                    )
                self.sock.send(resp)
                raise self.BEGIN()

            bindresponse = LDAP_BindResponse(
                    resultCode=LDAP_STATUS_CODES["success"],
                    serverSaslCreds=b"",
                    serverSaslCredsWrap=None,
                    referral=None
                )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=bindresponse,
                Controls=None,
            )
            self.sock.send(resp)
            if conf_avail:
                self.sock.sasl_wrap = True
                self.sock.encrypt = True
            elif integ_avail:
                self.sock.sasl_wrap = True
            raise self.BOUND()


    @ATMT.state()
    def BOUND(self):
        pass



    @ATMT.receive_condition(BOUND)
    def delete_request(self, pkt):
        if LDAP_DelRequest in pkt:
            self.vprint("Received an LDAP delete request")
            self.messageID = pkt[LDAP].messageID

            to_delete_entry = pkt[LDAP_DelRequest].entry.val.decode("utf-8")
            self.vprint(f"Entry to delete: '{to_delete_entry}'")
            resp = self.perform_delete(to_delete_entry)
            self.sock.send(resp)
            raise self.BOUND()

    @staticmethod
    def remove_entry(data, entry):
        deletion_occurred = False
        if isinstance(data, dict):
            for key in list(data.keys()):
                if key.lower() == entry.lower():
                    del data[key]
                    deletion_occurred = True
                elif isinstance(data[key], dict):
                    if LDAP_Server.remove_entry(data[key], entry):
                        deletion_occurred = True
        return deletion_occurred


    def perform_delete(self, to_delete_entry):
        try:
            deleted = LDAP_Server.remove_entry(self.data, to_delete_entry)
            if deleted is False:
                delresponse = LDAP_DelResponse(
                        resultCode=LDAP_STATUS_CODES["noSuchObject"],
                        diagnosticMessage=f"Entry '{to_delete_entry}' does not exist",
                        referral=None
                    )
                resp = LDAP(
                        messageID=self.messageID,
                        protocolOp=delresponse,
                        Controls=None,
                    )
                return resp

            # Commit changes by writing to file
            formatted_data = json.dumps(self.data, indent=4)
            with open(self.data_src, "w") as f:
                f.write(formatted_data)
            
            # If everything went well, send response
            delresponse = LDAP_DelResponse(
                resultCode=LDAP_STATUS_CODES["success"],
                referral=None
            )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=delresponse,
                Controls=None,
            )
            return resp
        except Exception as e:
            traceback.print_exc()
            self.vprint(e)
            delresponse = LDAP_DelResponse(
                resultCode=LDAP_STATUS_CODES["protocolError"],
                diagnosticMessage="Delete operation failed",
                referral=None
            )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=delresponse,
                Controls=None,
            )
            return resp


    @ATMT.receive_condition(BOUND)
    def add_request(self, pkt):
        if LDAP_AddRequest in pkt:
            self.vprint("Received an LDAP add request")
            self.messageID = pkt[LDAP].messageID

            to_create_entry = pkt[LDAP_AddRequest].entry.val.decode("utf-8")
            to_create_attributes = []
            for attribute in pkt[LDAP_AddRequest].attributes:
                attribute_name = attribute.type.val.decode("utf-8")
                attribute_values = [item.value.val for item in attribute.values]
                self.vprint(f"{attribute_name} -> {attribute_values}")
                to_create_attributes.append((attribute_name, attribute_values))

            resp = self.perform_add(to_create_entry, to_create_attributes)
            self.sock.send(resp)
            raise self.BOUND()

    def perform_add(self, to_create_entry, to_create_attributes):
        try:
            parent = to_create_entry.split(',', 1)[1]
            parent = LDAP_Server.find_base(self.data, parent)
            if parent is None:
                addresponse = LDAP_ModifyResponse(
                        resultCode=LDAP_STATUS_CODES["noSuchObject"],
                        diagnosticMessage=f"Parent for entry '{to_create_entry}' does not exist",
                        referral=None
                    )
                resp = LDAP(
                        messageID=self.messageID,
                        protocolOp=addresponse,
                        Controls=None,
                    )
                return resp
            
            for key in parent.keys():
                if to_create_entry.lower() == key.lower():
                    addresponse = LDAP_ModifyResponse(
                            resultCode=LDAP_STATUS_CODES["entryAlreadyExists"],
                            diagnosticMessage=f"The entry '{to_create_entry}' already exists",
                            referral=None
                        )
                    resp = LDAP(
                            messageID=self.messageID,
                            protocolOp=addresponse,
                            Controls=None,
                        )
                    return resp
            
            parent[to_create_entry] = {}
            for attribute in to_create_attributes:
                parent[to_create_entry][attribute[0]] = [value.decode('utf-8') for value in attribute[1]]

            # Commit changes by writing to file
            formatted_data = json.dumps(self.data, indent=4)
            with open(self.data_src, "w") as f:
                f.write(formatted_data)
            
            # If everything went well, send response
            addresponse = LDAP_AddResponse(
                resultCode=LDAP_STATUS_CODES["success"],
                referral=None
            )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=addresponse,
                Controls=None,
            )
            return resp
        except Exception as e:
            self.vprint(e)
            addresponse = LDAP_AddResponse(
                resultCode=LDAP_STATUS_CODES["protocolError"],
                diagnosticMessage="Add operation failed",
                referral=None
            )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=addresponse,
                Controls=None,
            )
            return resp


    @ATMT.receive_condition(BOUND)
    def modify_request(self, pkt):
        # The entire list of modifications MUST be performed in the order they are listed as a single atomic operation.
        # If any of the change operations requested fails, then no change should happen. If successful, all changes happened

        if LDAP_ModifyRequest in pkt:
            self.vprint("Received an LDAP modify request")
            self.messageID = pkt[LDAP].messageID
            
            target_object = pkt[LDAP_ModifyRequest].object.val.decode("utf-8")
            changes = []
            for change in pkt[LDAP_ModifyRequest].changes:
                op = change.operation.val
                modif_type = change.modification.type.val.decode("utf-8")
                # Keep bytes to handle non-readable stuff
                modif_values = [item.value.val for item in change.modification.values]
                changes.append((op, modif_type, modif_values))

            self.vprint(f"Target object: '{target_object}'")
            for change in changes:
                self.vprint(f"Operation: {change[0]}")
                self.vprint(f"Attribute: {change[1]}")
                self.vprint(f"Values: {change[2]}")

            resp = self.perform_modify(target_object, changes)
            self.sock.send(resp)
            raise self.BOUND()


    def perform_modify(self, target_object, changes):

        def modify_add(entry, attribute, values):
            # add values listed to the modification attribute,
            # creating the attribute if necessary.
            existing_values = []

            for key in entry.keys():
                if attribute.lower() == key.lower():
                    attribute = key
                    if not isinstance(entry[key], list):
                        existing_values.append(entry[key])
                    else:
                        existing_values = entry[key][:]
                    break
            for value in values:
                existing_values.append(value.decode("utf-8"))
            entry[attribute] = existing_values

        def modify_delete(entry, attribute, values):
            # delete values listed from the modification attribute.
            # If no values are listed, or if all current values of the
            # attribute are listed, the entire attribute is removed.
            for key in entry.keys():
                if attribute.lower() == key.lower():
                    existing_values = []
                    if not isinstance(entry[key], list):
                        existing_values.append(entry[key])
                    else:
                        existing_values = entry[key][:]
                    if len(values) == 0:
                        existing_values.clear()
                    else:
                        values_to_remove = {v.decode("utf-8") for v in values}
                        existing_values[:] = [x for x in existing_values if x not in values_to_remove]
                    if len(existing_values) == 0:
                        del entry[key]
                    else:
                        entry[key] = existing_values
                    return
            raise LDAP_Exception(
                resultCode=LDAP_STATUS_CODES["noSuchAttribute"],
                diagnosticMessage=f"The attribute '{attribute}' does not exist in target entry"
            )

        def modify_replace(entry, attribute, values):
            # replace all existing values of the modification
            # attribute with the new values listed, creating the attribute
            # if it did not already exist.  A replace with no value will
            # delete the entire attribute if it exists, and it is ignored
            # if the attribute does not exist.
            for key in entry.keys():
                if attribute.lower() == key.lower():
                    if len(values) == 0:
                        del entry[key]
                    else:
                        entry[key] = [value.decode("utf-8") for value in values]
                    return
            if len(values) > 0:
                entry[attribute] = [value.decode("utf-8") for value in values]


        try:
            entry = LDAP_Server.find_base(self.data, target_object)
            if entry is None:
                self.vprint("Could not find the specified base")
                modifyresponse = LDAP_ModifyResponse(
                    resultCode=LDAP_STATUS_CODES["noSuchObject"],
                    diagnosticMessage=f"Could not find the object {target_object}",
                    referral=None
                )
                resp = LDAP(
                    messageID=self.messageID,
                    protocolOp=modifyresponse,
                    Controls=None,
                )
                return resp
            
            # This is used to rollback to original value if something fails
            entry_rollback = copy.deepcopy(entry)

            # Perform the changes. If something went wrong, rollback and send error
            try:
                for change in changes:
                    if change[0] == LDAP_MODIFY_CODES["ADD"]:
                        modify_add(entry, change[1], change[2])
                    elif change[0] == LDAP_MODIFY_CODES["DELETE"]:
                        modify_delete(entry, change[1], change[2])
                    elif change[0] == LDAP_MODIFY_CODES["REPLACE"]:
                        modify_replace(entry, change[1], change[2])
            except LDAP_Exception as e:
                entry.clear()
                entry.update(entry_rollback)
                modifyresponse = LDAP_ModifyResponse(
                    resultCode=e.resultCode,
                    diagnosticMessage=e.diagnosticMessage,
                    referral=None
                )
                resp = LDAP(
                    messageID=self.messageID,
                    protocolOp=modifyresponse,
                    Controls=None,
                )
                return resp      

            # Commit changes by writing to file
            formatted_data = json.dumps(self.data, indent=4)
            with open(self.data_src, "w") as f:
                f.write(formatted_data)

            # If everything went well, send response
            modifyresponse = LDAP_ModifyResponse(
                resultCode=LDAP_STATUS_CODES["success"],
                referral=None
            )
            resp = LDAP(
                messageID=self.messageID,
                protocolOp=modifyresponse,
                Controls=None,
            )
            return resp
        except Exception as e:
                self.vprint(e)
                entry.clear()
                entry.update(entry_rollback)
                modifyresponse = LDAP_ModifyResponse(
                    resultCode=LDAP_STATUS_CODES["protocolError"],
                    diagnosticMessage="Modify operation failed",
                    referral=None
                )
                resp = LDAP(
                    messageID=self.messageID,
                    protocolOp=modifyresponse,
                    Controls=None,
                )
                return resp   


    @ATMT.receive_condition(BOUND)
    def search_request(self, pkt):
        if LDAP_SearchRequest in pkt:
            self.vprint("Received an LDAP search request")
            self.messageID = pkt[LDAP].messageID

            base = pkt[LDAP_SearchRequest].baseObject.val.decode("utf-8")
            scope = pkt[LDAP_SearchRequest].scope.val
            attributes = [attribute.type.val.decode() for attribute in pkt[LDAP_SearchRequest].attributes]
            filter = pkt[LDAP_SearchRequest].filter.filter
            self.vprint(f"Search request scope: {scope}")
            self.vprint(f"Search request attributes: {attributes}")
            self.vprint(f"Search request filter: {filter}")

            if base == "":
                self.root_dse_search(pkt)
            else:
                resp = self.perform_search(base, scope, filter, attributes)
                self.sock.send(resp)
            raise self.BOUND()


    @ATMT.state(final=1)
    def END(self):
        print("State=END")

    @staticmethod
    def find_base(data, base):
        for key in data.keys():
            if base.lower() == key.lower():
                return data[key]
        for value in data.values():
            if isinstance(value, dict):
                result = LDAP_Server.find_base(value, base)
                if result is not None:
                    return result
        return None
    
    @staticmethod
    def to_unicode(obj):
        if isinstance(obj, (int, float)):
            obj = str(obj)
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("utf-8")    
        if isinstance(obj, str):
            return obj
        raise UnicodeError("Unable to convert type %s to unicode: %r" % (obj.__class__.__name__, obj))
    
    @staticmethod
    def check_equality(value1, value2):
        # Exact match should never happen, as the filter value will be bytes,
        # and the entry value will be str or int from the parsed JSON
        if value1 == value2:
            return True
        try:
            if int(value1) == int(value2):
                return True
        except (TypeError, ValueError):
            pass
        try:
            if LDAP_Server.to_unicode(value1).lower() == LDAP_Server.to_unicode(value2).lower():
                return True
        except UnicodeError:
            pass
        return False

    @staticmethod
    def check_greater_or_equal(value1, value2):
        try:
            if int(value1) >= int(value2):
                return True
        except (TypeError, ValueError):
            pass
        try:
            if LDAP_Server.to_unicode(value1).lower() >= LDAP_Server.to_unicode(value2).lower():
                return True
        except UnicodeError:
            pass
        return False

    @staticmethod
    def check_less_or_equal(value1, value2):
        try:
            if int(value1) <= int(value2):
                return True
        except (TypeError, ValueError):
            pass
        try:
            if LDAP_Server.to_unicode(value1).lower() <= LDAP_Server.to_unicode(value2).lower():
                return True
        except UnicodeError:
            pass
        return False

    @staticmethod
    def evaluate_filter_equal(filter_value, values):
        # Attributes can be single value or lists, so convert to list
        if not isinstance(values, list):
            values = [values]
        # Stopping at first match
        for value in values:
            if LDAP_Server.check_equality(filter_value, value):
                return True
        return False
    
    @staticmethod
    def evaluate_filter_greater_or_equal(filter_value, values):
        if not isinstance(values, list):
            values = [values]
        for value in values:
            if LDAP_Server.check_greater_or_equal(value, filter_value):
                return True
        return False

    @staticmethod
    def evaluate_filter_less_or_equal(filter_value, values):
        if not isinstance(values, list):
            values = [values]
        for value in values:
            if LDAP_Server.check_less_or_equal(value, filter_value):
                return True
        return False
    
    def perform_search(self, base, scope, filter, attributes):
        resp = None
        try:
            results = self.get_search_results(base, scope, filter, attributes)
        except Exception as e:
            traceback.print_exc()
            self.vprint(e)
            searchresp = LDAP_SearchResponseResultDone(
                        resultCode=LDAP_STATUS_CODES["protocolError"],
                        matchedDN="",
                        diagnosticMessage=LDAP_ERROR_MESSAGES["GENERIC_SEARCH_FAILED"],
                        referral=None,
                    )
            resp = LDAP(
                protocolOp=searchresp,
                messageID=self.messageID
            )
            return resp

        if results:
            resp = results[0]
            for search_response_entry in results[1:]:
                resp = resp / search_response_entry
        search_res_done = LDAP(
                protocolOp=LDAP_SearchResponseResultDone(
                    referral=None,
                    resultCode=0,
                ),
                messageID=self.messageID
            )
        if resp:
            resp = resp / search_res_done
        else:
            resp = search_res_done
        return resp

    def get_search_results(self, base, scope, filter, attributes):
        """
        Perform an LDAP search operation over the server's data.

        :param base: DN to start search from
        :param scope: 0=BASE, 1=LEVEL, 2=SUBTREE
        :param filter: dict with attribute and value to match
        :param attributes: list of attributes to return
        :return: list of LDAP packets each wrapping an LDAP_SearchResponseEntry object
        """

        results = []

        def compare_filter(entry, filter):
            # This function compares a specific filter with the entry
            entry = {k.lower(): v for k, v in entry.items()}

            # If the filter is a presence filter, just check if the
            # filter's "present" attribute is in the entry's keys
            if isinstance(filter, LDAP_FilterPresent):
                if filter.present.val.decode("utf-8").lower() in entry.keys():
                    return True
                return False
            # If the filter is an extensible match filter, raise an exception or accept
            # depending on the server's configuration
            if isinstance(filter, LDAP_FilterExtensibleMatch):
                return self.ACCEPT_EXTENSIBLE

            # FIXME implement substring filters
            if isinstance(filter, LDAP_SubstringFilter):
                return True
            
            # If this any other filter type, values must be compared
            filter_key = filter.attributeType.val.decode().lower()
            # The filter value will be bytes
            filter_value = filter.attributeValue.val
            values = entry.get(filter_key)
            
            # The filter's attribute is not present in the entry, return False
            if values is None:
                return False

            # Perform comparison, equality and approximate matches are checking for equality
            if isinstance(filter, LDAP_FilterEqual) or isinstance(filter, LDAP_FilterApproxMatch):
                return LDAP_Server.evaluate_filter_equal(filter_value, values)
            if isinstance(filter, LDAP_FilterGreaterOrEqual):
                return LDAP_Server.evaluate_filter_greater_or_equal(filter_value, values)
            if isinstance(filter, LDAP_FilterLessOrEqual):
                return LDAP_Server.evaluate_filter_less_or_equal(filter_value, values)
            return False

        def match_filter(entry, filter):
            # This function recursively handles a filter element
            filter = filter.filter if hasattr(filter, "filter") else filter
            
            # AND: all subfilters must match
            if isinstance(filter, LDAP_FilterAnd):
                return all(match_filter(entry, subf) for subf in filter.vals)

            # OR: at least one subfilter must match
            elif isinstance(filter, LDAP_FilterOr):
                return any(match_filter(entry, subf) for subf in filter.vals)

            # NOT: the subfilter must not match
            elif isinstance(filter, LDAP_FilterNot):
                return not match_filter(entry, filter.val)

            # Comparison filter (e.g., LDAP_FilterEqual, LDAP_FilterGreaterOrEqual, etc.)
            # Performs the actual comparison between filter value and entry value
            else:
                return compare_filter(entry, filter)
            

        def get_attribute_values(val):
            if isinstance(val, dict):
                # Do not return sub-entries as attribute values
                return None
            if isinstance(val, list):
                values = []
                for v in val:
                    v = str(v)
                    if v.startswith("base64:"):
                        v = base64.b64decode(val.split("base64:")[1])
                    values.append(LDAP_AttributeValue(value=ASN1_STRING(v)))
            else:
                val = str(val)
                if val.startswith("base64:"):
                    val = base64.b64decode(val.split("base64:")[1])
                values = [LDAP_AttributeValue(value=ASN1_STRING(val))]
            return values

        def make_entry(dn, entry, attributes):
            # If an entry matched a filter, this function constructs the LDAP_SearchResponseEntry
            attrs = []

            # If the client asked for all attributes, return each one for the entry
            if LDAP_SEARCH_ATTRIBUTES["ALL_ATTRIBUTES"] in attributes:
                for attr, values in entry.items():
                    values = get_attribute_values(values)
                    if values is not None:
                        attrs.append(
                            LDAP_PartialAttribute(
                                type=ASN1_STRING(attr),
                                values=values
                            )
                        )
            # If the client asked for no attributes, do not return any attribute
            elif LDAP_SEARCH_ATTRIBUTES["NO_ATTRIBUTES"] in attributes:
                pass
            # Otherwise, get the desired attributes
            else:
                entry = {k.lower(): v for k, v in entry.items()}
                for attr in attributes:
                    if attr.lower() in entry:
                        values = entry[attr.lower()]
                        values = get_attribute_values(values)
                        attrs.append(
                            LDAP_PartialAttribute(
                                type=ASN1_STRING(attr),
                                values=values
                            )
                        )

            search_response_entry = LDAP_SearchResponseEntry(
                objectName=ASN1_STRING(dn),
                attributes=attrs
            )
            return LDAP(
                protocolOp=search_response_entry,
                messageID=self.messageID
            )

        # For BASE search, only look for matches at the base level
        def search_base(dn, entry):
            if match_filter(entry, filter):
                results.append(make_entry(dn, entry, attributes))

        # For LEVEL search, look for matches in child elements (dicts)
        def search_level(dn, entry):
            for k, v in entry.items():
                if isinstance(v, dict):
                    if match_filter(v, filter):
                        results.append(make_entry(k, v, attributes))

        # For SUBTREE search, look for matches in base and recursively
        def search_subtree(dn, entry):
            if match_filter(entry, filter):
                results.append(make_entry(dn, entry, attributes))
            for k, v in entry.items():
                if isinstance(v, dict):
                    search_subtree(k, v)

        entry = LDAP_Server.find_base(self.data, base)
        if not entry:
            self.vprint(f"Could not find the specified base '{base}' in server data")
            return results
        self.vprint(f"Found the specified base '{base}'")

        if scope == LDAP_SCOPES["BASE"]:
            # Only immediate attributes, skip dicts which represent subitems
            flat_entry = {k: v for k, v in entry.items() if not isinstance(v, dict)}
            search_base(base, flat_entry)
        elif scope == LDAP_SCOPES["LEVEL"]:  # LEVEL
            search_level(base, entry)
        elif scope == LDAP_SCOPES["SUBTREE"]:  # SUBTREE
            search_subtree(base, entry)

        return results


class ldapserver:
    r"""
    Spawns a simple ldapserver

    ldapserver parameters:

        :param port:  (optional) the port to bind on, default 389
        :param iface:  (optional) the interface to bind on, default conf.iface
        :param data: the JSON file containing the LDAP server data
        :param ssp: (optional) the SSP to use.

        More LDAP-specific optional parameters are available - see the LDAP_Server class
    """

    def __init__(
        self,
        data: str,
        iface: str = "eth0",
        port: int = 389,
        verb: int = 2,
        ssp=None,
        **kwargs,
    ):
        # Verb
        if verb >= 2:
            log_runtime.info("-- Scapy %s LDAP Server --" % conf.version)
            log_runtime.info("SSP: %s." % (conf.color_theme.yellow(ssp or "NTLM (guest)")))
        # Start LDAP Server
        self.srv = LDAP_Server.spawn(
            # TCP server
            port=port,
            iface=iface or conf.loopback_name,
            verb=verb,
            # LDAP server
            data=data,
            ssp=ssp,
            # LDAP arguments
            **kwargs,
        )

    def close(self):
        """
        Close the ldapserver if started in background mode (bg=True)
        """
        if self.srv:
            try:
                self.srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.srv.close()


if __name__ == "__main__":
    from scapy.utils import AutoArgparse
    AutoArgparse(ldapserver)
