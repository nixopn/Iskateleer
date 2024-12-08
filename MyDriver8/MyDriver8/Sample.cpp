#include <ntddk.h>
#include <wdm.h>












PVOID g_CallbackHandle = NULL;

PVOID proc = NULL;
PVOID proc8 = NULL;
PVOID proc12 = NULL;
PVOID proc28 = NULL;
PVOID proc38 = NULL;

ULONG proc28opas = NULL;
UCHAR proc38zarazh = NULL;











VOID UnregisterMyCallbacks() {
    if (g_CallbackHandle) {
        ObUnRegisterCallbacks(g_CallbackHandle);
        g_CallbackHandle = NULL;
    }
}

_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS PreProcessHandleCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);

_IRQL_requires_max_(APC_LEVEL)
void PostProcessHandleCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation);



void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "Callback: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) created, creator %Ix:%Ix\n"
            "    command line %wZ\n"
            "    file name %wZ (FileOpenNameAvailable: %d)\n",
            Process,
            (PVOID)ProcessId,
            (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
            (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
            CreateInfo->CommandLine,
            CreateInfo->ImageFileName,
            CreateInfo->FileOpenNameAvailable
            
        );
        proc = ProcessId;
    }
    else {
        // Завершение процесса
        DbgPrint("Process Closed: %dn", (ULONG_PTR)ProcessId);
        return;
    }
}






void OnThreadNotify(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN CreateInfo
) {
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    if (CreateInfo) {
        // Уведомление о создании потока
        //DbgPrintEx(
        //    DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        //    "Thread Created: Thread ID = 0x%p, Process ID = 0x%pn",
        //    (PVOID)ThreadId,
        //    (PVOID)ProcessId

        //);
        proc8 = ProcessId;
        //proc == proc8 &&
        if (proc8 == proc28 &&  proc8 == proc38) {
            //realzapisetr();
            ///*zapis()*/;
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "Attention process 0x%pn is a potential threat   \n"
                "Process 0x%pn was injected with dll",
                (PVOID)proc12,
                (PVOID)proc28

            );
        }
    }
    else {
        // Уведомление о завершении потока
        //DbgPrintEx(
            //DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
           // "Thread Closed: Thread ID = 0x%p, Process ID = 0x%pn",
          //  (PVOID)ThreadId,
         //   (PVOID)ProcessId
        //);
    }
}



VOID imageCallback(__in PUNICODE_STRING FullImageName,
    __in HANDLE ProcessId,
    __in PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ImageInfo);

    proc38 = ProcessId;
}

VOID UnloadDriver(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);





    PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);



    UnregisterMyCallbacks();

    PsRemoveLoadImageNotifyRoutine(imageCallback);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Iskateleer");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Iskateleer");

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("Driver Unloaded Successfully.n");



}

_IRQL_requires_max_(APC_LEVEL)
OB_PREOP_CALLBACK_STATUS PreProcessHandleCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    PAGED_CODE();
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);


    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        PEPROCESS openedProcess = (PEPROCESS)OperationInformation->Object;
        HANDLE targetPID = PsGetProcessId(openedProcess);
        HANDLE sourcePID = PsGetCurrentProcessId();


        targetPID = nullptr;
        sourcePID = nullptr;

    }

    return OB_PREOP_SUCCESS;
}


_IRQL_requires_max_(APC_LEVEL)
void PostProcessHandleCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation) {
    PAGED_CODE();
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);

    ACCESS_MASK AccessRights = OperationInformation->Parameters->CreateHandleInformation.GrantedAccess;

    if (AccessRights != 0x0) {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {

            PEPROCESS openedProcess = (PEPROCESS)OperationInformation->Object;
            HANDLE targetPID = PsGetProcessId(openedProcess);
            HANDLE sourcePID = PsGetCurrentProcessId();

            if (targetPID == sourcePID) {
                /*DbgPrint("Process %d created a handle to itself with access rights %d\n", sourcePID, AccessRights);*/
            }
            else {
                /*DbgPrint("Process %d created a handle to process %d with access rights %d\n", sourcePID, targetPID, AccessRights);*/
            }
            proc12 = sourcePID;
            proc28 = targetPID;
        }
    }
}

typedef struct _HANDLES_NOTIFY_STRUCT {
    POBJECT_TYPE ObjectType;
    ULONG Operations;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
    PVOID RegistrationContext;
} HANDLES_NOTIFY_STRUCT, * PHANDLES_NOTIFY_STRUCT;

NTSTATUS RegisterHandlesOperationsNotifier(IN PHANDLES_NOTIFY_STRUCT HandlesNotifyStruct, OUT PVOID* RegistrationHandle) {
    OB_OPERATION_REGISTRATION OperationRegistration;
    OperationRegistration.ObjectType = &HandlesNotifyStruct->ObjectType;
    OperationRegistration.Operations = HandlesNotifyStruct->Operations;
    OperationRegistration.PostOperation = HandlesNotifyStruct->PostOperation;
    OperationRegistration.PreOperation = HandlesNotifyStruct->PreOperation;

    UNICODE_STRING Altitude;
    RtlInitUnicodeString(&Altitude, L"389020");

    OB_CALLBACK_REGISTRATION CallbackRegistration;
    CallbackRegistration.Altitude = Altitude;
    CallbackRegistration.OperationRegistration = &OperationRegistration;
    CallbackRegistration.OperationRegistrationCount = 1;
    CallbackRegistration.RegistrationContext = HandlesNotifyStruct->RegistrationContext;
    CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;

    return ObRegisterCallbacks(&CallbackRegistration, RegistrationHandle);
}



extern "C"






NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    auto status = STATUS_SUCCESS;

    DbgPrint("Driver Loaded Successfully.n");


    do
    {
        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) {
            KdPrint(((PCSTR)status));
            break;
        }
    } while (false);

    do
    {
        status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
        if (!NT_SUCCESS(status)) {
            KdPrint(((PCSTR)status));
            break;
        }
    } while (false);


    do
    {
        status = PsSetLoadImageNotifyRoutine(imageCallback);
        if (!NT_SUCCESS(status)) {
            KdPrint(((PCSTR)status));
            break;
        }
    } while (false);

    PVOID registrationHandle = NULL;

    
    HANDLES_NOTIFY_STRUCT handlesNotifyStruct;
    handlesNotifyStruct.ObjectType = *PsProcessType; 
    handlesNotifyStruct.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; 
    handlesNotifyStruct.PreOperation = PreProcessHandleCallback; 
    handlesNotifyStruct.PostOperation = PostProcessHandleCallback; 
    handlesNotifyStruct.RegistrationContext = NULL; 

    
    status = RegisterHandlesOperationsNotifier(&handlesNotifyStruct, &registrationHandle);

    if (!NT_SUCCESS(status)) {
        
        KdPrint(("Failed to register handle operations notifier: 0x%Xn", status));
        return status;
    }

    g_CallbackHandle = registrationHandle;


    


    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Iskateleer");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Iskateleer");
    PDEVICE_OBJECT DeviceObject = nullptr;
    status = STATUS_SUCCESS;
    do {
        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
            0, FALSE, &DeviceObject);
        if (!NT_SUCCESS(status)) {
            DbgPrint( "failed to create device (0x%08X)\n",
                status);
            break;
        }
        
        DeviceObject->Flags |= DO_DIRECT_IO;
        status = IoCreateSymbolicLink(&symLink, &devName);
        if (!NT_SUCCESS(status)) {
            DbgPrint( "failed to create symbolic link (0x%08X)\n",
                status);
            break;
        }
    } while (false);
    if (!NT_SUCCESS(status)) {
        if (DeviceObject)
            IoDeleteDevice(DeviceObject);
    }
    


    DriverObject->DriverUnload = UnloadDriver;
    return STATUS_SUCCESS;
}

// aaaa wwww



