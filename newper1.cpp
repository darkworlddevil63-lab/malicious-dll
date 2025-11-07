#define _WIN32_DCOM
#include <windows.h>
#include <comdef.h>
#include <wbemidl.h>
#include <iostream>

int main() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return 1;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
                                RPC_C_AUTHN_LEVEL_DEFAULT,
                                RPC_C_IMP_LEVEL_IMPERSONATE,
                                NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) { CoUninitialize(); return 1; }

    // ---- declare everything BEFORE any goto ----
    IWbemLocator*      pLoc              = NULL;
    IWbemServices*     pSvc              = NULL;
    IWbemClassObject*  pFilterClass      = NULL;
    IWbemClassObject*  pFilterInstance   = NULL;
    IWbemClassObject*  pConsumerClass    = NULL;
    IWbemClassObject*  pConsumerInstance = NULL;
    IWbemClassObject*  pBindingClass     = NULL;
    IWbemClassObject*  pBindingInstance  = NULL;
    VARIANT v; VariantInit(&v);
    // --------------------------------------------

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                            IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) goto cleanup;

    // 5th arg must be LONG, not NULL
    hres = pLoc->ConnectServer(_bstr_t(L"root\\subscription"),
                               NULL, NULL, 0, 0 /* lSecurityFlags */,
                               0, 0, &pSvc);
    if (FAILED(hres)) goto cleanup;

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                             RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL, EOAC_NONE);
    if (FAILED(hres)) goto cleanup;

    // Event Filter
    hres = pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &pFilterClass, NULL);
    if (FAILED(hres)) goto cleanup;

    hres = pFilterClass->SpawnInstance(0, &pFilterInstance);
    if (FAILED(hres)) goto cleanup;

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"WinStartupFilter");
    pFilterInstance->Put(L"Name", 0, &v, 0); VariantClear(&v);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"root\\cimv2");
    pFilterInstance->Put(L"EventNamespace", 0, &v, 0); VariantClear(&v);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"WQL");
    pFilterInstance->Put(L"QueryLanguage", 0, &v, 0); VariantClear(&v);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(
        L"SELECT * FROM Win32_StartupCommand WHERE Command = 'explorer.exe'");
    pFilterInstance->Put(L"Query", 0, &v, 0); VariantClear(&v);

    pSvc->PutInstance(pFilterInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // Consumer
    pSvc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, NULL, &pConsumerClass, NULL);
    pConsumerClass->SpawnInstance(0, &pConsumerInstance);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"WinStartupConsumer");
    pConsumerInstance->Put(L"Name", 0, &v, 0); VariantClear(&v);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(
        L"C:\\Users\\i_rajesh.chandrappa\\Downloads\\message.exe");
    pConsumerInstance->Put(L"CommandLineTemplate", 0, &v, 0); VariantClear(&v);

    pSvc->PutInstance(pConsumerInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // Binding
    pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, NULL, &pBindingClass, NULL);
    pBindingClass->SpawnInstance(0, &pBindingInstance);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"__EventFilter.Name=\"WinStartupFilter\"");
    pBindingInstance->Put(L"Filter", 0, &v, 0); VariantClear(&v);

    v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"CommandLineEventConsumer.Name=\"WinStartupConsumer\"");
    pBindingInstance->Put(L"Consumer", 0, &v, 0); VariantClear(&v);

    pSvc->PutInstance(pBindingInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

cleanup:
    if (pBindingInstance)  pBindingInstance->Release();
    if (pBindingClass)     pBindingClass->Release();
    if (pConsumerInstance) pConsumerInstance->Release();
    if (pConsumerClass)    pConsumerClass->Release();
    if (pFilterInstance)   pFilterInstance->Release();
    if (pFilterClass)      pFilterClass->Release();
    if (pSvc)              pSvc->Release();
    if (pLoc)              pLoc->Release();
    VariantClear(&v);
    CoUninitialize();
    return FAILED(hres) ? 1 : 0;
}
