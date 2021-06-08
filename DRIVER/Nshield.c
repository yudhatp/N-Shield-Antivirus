//file kernel driver
//untuk melakukan monitoring terhadap process yang dijalankan atau diakhiri
//(c)2013 By Yudha Tri Putra

#include "ntifs.h"
#include "precomp.h"

#define IOCTL_START_PROCESS_MONITOR     CTL_CODE(0xF100, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_MONITOR_DATA  CTL_CODE(0xF100, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OPEN_PROCESS              CTL_CODE(0xF100, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_VM_READ 0x0010  

#define MAXPATHLEN 255

BOOLEAN CreateProcessNotifyRoutineActivated = FALSE;

void UnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchIoCtl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

PKEVENT ProcessMonitorEvent;
HANDLE HostProcessId;

typedef struct _ProcessMonitorCallbackInfo
{
    HANDLE ParentId;
    HANDLE  ProcessId;
	BOOLEAN Create;
	WCHAR S[MAXPATHLEN];
}TProcessMonitorCallbackInfo, *PProcessMonitorCallbackInfo;

PProcessMonitorCallbackInfo ProcessMonitorCallbackInfo;

VOID ProcessCallback(IN HANDLE ParentId, IN HANDLE ProcessId, IN BOOLEAN Create)
{
	if (HostProcessId != PsGetCurrentProcessId())
	{
		ProcessMonitorCallbackInfo->ParentId = ParentId;
		ProcessMonitorCallbackInfo->ProcessId = ProcessId;
		ProcessMonitorCallbackInfo->Create = Create;
		KeSetEvent(ProcessMonitorEvent, 0, FALSE);
		KeClearEvent(ProcessMonitorEvent);
	}
}

typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase;
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;

extern PServiceDescriptorTableEntry KeServiceDescriptorTable;

PVOID GetSystemRoutineAddress(WCHAR *Name)
{
  UNICODE_STRING RoutineName;
  PVOID RoutineAddress = NULL;
    
  RtlInitUnicodeString(&RoutineName, Name);

  try
  {
      RoutineAddress = MmGetSystemRoutineAddress(&RoutineName);
  }
  except (EXCEPTION_EXECUTE_HANDLER)
  {
      RoutineAddress = NULL;
  }
    
  return RoutineAddress;
}

typedef NTSTATUS (*_ZwQueryInformationProcess)(__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __out PVOID ProcessInformation, __in ULONG ProcessInformationLength, __out_opt PULONG ReturnLength);
		
_ZwQueryInformationProcess ZwQueryInformationProcess;


typedef struct _OpenProcessInfo
{
    HANDLE       ProcessId;
    ACCESS_MASK  DesiredAccess;
}TOpenProcessInfo, *POpenProcessInfo;

typedef struct _OpenProcessCallbackInfo
{
    HANDLE  ProcessHandle;
}TOpenProcessCallbackInfo, *POpenProcessCallbackInfo;

NTSTATUS OpenProcess(IN HANDLE ProcessId, IN ACCESS_MASK DesiredAccess, OUT PHANDLE ProcessHandle)
{
    NTSTATUS Status;
    PEPROCESS ProcessObject;
	HANDLE Process;
	
	__try 
	{
	    Status = PsLookupProcessByProcessId(ProcessId, &ProcessObject);
	
	    if (Status == STATUS_SUCCESS) 
        {                            
            Status = ObOpenObjectByPointer (ProcessObject, 0, NULL, DesiredAccess, *PsProcessType, KernelMode, &Process); 
		    if (Status == STATUS_SUCCESS) 
	        { 	
                *ProcessHandle = Process; 
	        }
        } 			
	}							
	__except( EXCEPTION_EXECUTE_HANDLER )  
	{   
	}	
	
    return Status;
}

NTSTATUS GetProcessImageName(IN HANDLE ProcessId, OUT PWCHAR ProcessPath)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG ProcessInformationLength;
	HANDLE ProcessHandle;
    PVOID ProcessInformation;
    
	if(KeGetCurrentIrql() == PASSIVE_LEVEL)
	{
		__try 
		{	    
			if (!ZwQueryInformationProcess)
			{
				return Status;
			}
		
			Status = OpenProcess(ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ProcessHandle);

			if (Status == STATUS_SUCCESS) 
			{   
				Status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, 0, &ProcessInformationLength);

				if (STATUS_INFO_LENGTH_MISMATCH != Status) 
				{
					ZwClose(ProcessHandle);
					return Status;
				}

				ProcessInformation = ExAllocatePoolWithTag(NonPagedPool, ProcessInformationLength, 'TgPI');

				if (NULL == ProcessInformation) 
				{
					ZwClose(ProcessHandle);
					return STATUS_INSUFFICIENT_RESOURCES;   
				}
			
				__try 
				{
					Status = ZwQueryInformationProcess( ProcessHandle, ProcessImageFileName, ProcessInformation, ProcessInformationLength, &ProcessInformationLength);
				}							
				__except( EXCEPTION_EXECUTE_HANDLER )  
				{   
					ZwClose(ProcessHandle);
					ExFreePool(ProcessInformation);
					return  STATUS_UNSUCCESSFUL;						
				}	
		
				ZwClose(ProcessHandle);
			
				if (Status == STATUS_SUCCESS) 
				{ 
					if (ProcessInformationLength > MAXPATHLEN)
					{			    
						ExFreePool(ProcessInformation);
						return  STATUS_UNSUCCESSFUL;
					}		
					
					__try 
					{			   				        
						wcsncat(ProcessPath, ((PUNICODE_STRING)ProcessInformation)->Buffer, ProcessInformationLength);	
					}
					__except( EXCEPTION_EXECUTE_HANDLER )  
					{   
						ExFreePool(ProcessInformation);
						return  STATUS_UNSUCCESSFUL;						
					}	
				}
 
				ExFreePool(ProcessInformation);
			}
		}
		__except( EXCEPTION_EXECUTE_HANDLER )  
		{       
			Status = STATUS_UNSUCCESSFUL;						
		}
	}

    return Status;
}

void UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
    NTSTATUS        Status;
    UNICODE_STRING  DeviceName;
		
	if (CreateProcessNotifyRoutineActivated) 
	{
		Status = PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
		if (Status == STATUS_SUCCESS)
		{
			CreateProcessNotifyRoutineActivated = FALSE;	
        }
	}	
	
	if (ProcessMonitorEvent != NULL)
    {
		KeClearEvent(ProcessMonitorEvent);
        ObfDereferenceObject(ProcessMonitorEvent);
        ProcessMonitorEvent = NULL;
    }
	
    IoDeleteDevice(DriverObject->DeviceObject);

    RtlInitUnicodeString(&DeviceName, L"\\DosDevices\\NSHIELD");
    IoDeleteSymbolicLink(&DeviceName);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS           Status;
    UNICODE_STRING     DriverName;
    UNICODE_STRING     DeviceName;
    PDEVICE_OBJECT     DeviceObject;

    RtlInitUnicodeString(&DriverName, L"\\Device\\NSHIELD");
    Status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	
    if(Status != STATUS_SUCCESS)
      return Status;
	  	  
    RtlInitUnicodeString(&DeviceName, L"\\DosDevices\\NSHIELD"); 
    Status = IoCreateSymbolicLink(&DeviceName, &DriverName);

    if(Status != STATUS_SUCCESS)
    {
        IoDeleteDevice(DeviceObject);
        return Status;
    }
	
    DriverObject->DriverUnload                         = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoCtl;
		
	ProcessMonitorCallbackInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(TProcessMonitorCallbackInfo), 'TgPM');
	
	ZwQueryInformationProcess = GetSystemRoutineAddress(L"ZwQueryInformationProcess");

    return Status;
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

typedef struct _ProcessMonitorInfo
{
    HANDLE ProcessMonitorEvent;
	HANDLE HostProcessId;
}
TProcessMonitorInfo, *PProcessMonitorInfo;

NTSTATUS DispatchIoCtl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS            Status = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION  IrpStack  = IoGetCurrentIrpStackLocation(Irp);
		
    switch(IrpStack->Parameters.DeviceIoControl.IoControlCode)
    {					
		case IOCTL_START_PROCESS_MONITOR:
	    { 
		    if (IrpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(TProcessMonitorInfo)) 
			{
			    __try
				{
		            TProcessMonitorInfo ProcessMonitorInfo = *(PProcessMonitorInfo)Irp->AssociatedIrp.SystemBuffer;

		            HostProcessId = ProcessMonitorInfo.HostProcessId;
		            Status = ObReferenceObjectByHandle( (HANDLE)ProcessMonitorInfo.ProcessMonitorEvent,  EVENT_MODIFY_STATE, *ExEventObjectType, UserMode, (PVOID*)&ProcessMonitorEvent, NULL);

			        if (Status == STATUS_SUCCESS)
			        {
				        if (!CreateProcessNotifyRoutineActivated) 
				        {
					        Status = PsSetCreateProcessNotifyRoutine(ProcessCallback, FALSE);
					        if (Status == STATUS_SUCCESS)
					        {
						        CreateProcessNotifyRoutineActivated = TRUE;				
					        }
				        }
			        }
			        Irp->IoStatus.Information = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
				}
	            __except( EXCEPTION_EXECUTE_HANDLER )  
                {   					
                } 
			}			
            break;
	    }
		
		case IOCTL_GET_PROCESS_MONITOR_DATA:
	    { 
		    if (IrpStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(TProcessMonitorCallbackInfo)) 
			{
			    __try
				{
			        if (ProcessMonitorCallbackInfo != NULL)
			        {
					    PWSTR Path = NULL;
					
				        Path = ExAllocatePoolWithTag(NonPagedPool, MAXPATHLEN, 'TgPH');
                        if (Path != NULL)
						{
				            GetProcessImageName(ProcessMonitorCallbackInfo->ProcessId, Path);
									
					        *ProcessMonitorCallbackInfo->S = L'\0';
                            wcsncat(ProcessMonitorCallbackInfo->S, Path, MAXPATHLEN);
						
							ExFreePool(Path);
						}
					
			            memcpy(Irp->AssociatedIrp.SystemBuffer, ProcessMonitorCallbackInfo, IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
                        Irp->IoStatus.Information = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

			            Status = STATUS_SUCCESS;
			        }
				}
	            __except( EXCEPTION_EXECUTE_HANDLER )  
                {   					
                }
			}	
						
            break;
	    }
		
		case IOCTL_OPEN_PROCESS:
		{			
			if (IrpStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(TOpenProcessCallbackInfo)) 
			{
			    TOpenProcessInfo OpenProcessInfo = *(POpenProcessInfo)Irp->AssociatedIrp.SystemBuffer; 
                HANDLE ProcessHandle = NULL;
		        POpenProcessCallbackInfo OpenProcessCallbackInfo = NULL;
			
			    __try
				{
				    Status = OpenProcess(OpenProcessInfo.ProcessId, OpenProcessInfo.DesiredAccess, &ProcessHandle);
			        if (Status == STATUS_SUCCESS)
				    {
                        OpenProcessCallbackInfo->ProcessHandle = ProcessHandle;
						
						memcpy(Irp->AssociatedIrp.SystemBuffer, OpenProcessCallbackInfo, IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
                        Irp->IoStatus.Information = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
				    }		        
				}
	            __except( EXCEPTION_EXECUTE_HANDLER )  
                {   					
                }
			}	
								
            break;
		}
							
        default: break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
		
    return Status;
}


























