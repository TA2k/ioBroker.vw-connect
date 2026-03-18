.class public abstract Ltechnology/cariad/cat/genx/VehicleAntennaImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/InternalVehicleAntenna;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Inner;,
        Ltechnology/cariad/cat/genx/VehicleAntennaImpl$Outer;,
        Ltechnology/cariad/cat/genx/VehicleAntennaImpl$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00f4\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0005\n\u0002\u0008\u000b\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u001b\n\u0002\u0018\u0002\n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008 \u0018\u00002\u00020\u0001:\u0004\u0096\u0001\u0097\u0001Bc\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\u0008\u0012\u0006\u0010\u000b\u001a\u00020\n\u0012\u0006\u0010\r\u001a\u00020\u000c\u0012\u000c\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000e\u0012\u0006\u0010\u0012\u001a\u00020\u0011\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u0013\u0012\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u0013\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u001a\u0010\u001b\u001a\u0004\u0018\u00010\u001a2\u0006\u0010\u0019\u001a\u00020\u0018H\u0086@\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u0016\u0010!\u001a\u0008\u0012\u0004\u0012\u00020\u001e0\u001dH\u0096@\u00a2\u0006\u0004\u0008\u001f\u0010 J\u001a\u0010$\u001a\u0004\u0018\u00010\"2\u0006\u0010#\u001a\u00020\"H\u0096@\u00a2\u0006\u0004\u0008$\u0010%J\u001d\u0010*\u001a\u00020)2\u000c\u0010(\u001a\u0008\u0012\u0004\u0012\u00020\'0&H\u0016\u00a2\u0006\u0004\u0008*\u0010+J\u0019\u0010-\u001a\u0004\u0018\u00010,2\u0006\u0010\u0007\u001a\u00020\u0006H\u0017\u00a2\u0006\u0004\u0008-\u0010.J\u001f\u00102\u001a\u00020)2\u0006\u00100\u001a\u00020/2\u0006\u00101\u001a\u00020,H\u0016\u00a2\u0006\u0004\u00082\u00103J\u000f\u00104\u001a\u00020)H\u0016\u00a2\u0006\u0004\u00084\u00105J\u000f\u00106\u001a\u00020)H\u0016\u00a2\u0006\u0004\u00086\u00105J\u001f\u00108\u001a\u00020)2\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u00107\u001a\u00020\u0013H\u0016\u00a2\u0006\u0004\u00088\u00109J\u000f\u0010:\u001a\u00020)H\u0016\u00a2\u0006\u0004\u0008:\u00105J\u000f\u0010<\u001a\u00020;H\u0016\u00a2\u0006\u0004\u0008<\u0010=J\u000f\u0010>\u001a\u00020)H\u0002\u00a2\u0006\u0004\u0008>\u00105J<\u0010G\u001a\u00020F2\n\u0010@\u001a\u00060;j\u0002`?2\u0006\u0010A\u001a\u00020\u001e2\u0006\u0010C\u001a\u00020B2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010E\u001a\u00020DH\u0082 \u00a2\u0006\u0004\u0008G\u0010HJ\u0010\u0010I\u001a\u00020)H\u0083 \u00a2\u0006\u0004\u0008I\u00105J\u0018\u0010J\u001a\u00020\u001e2\u0006\u0010E\u001a\u00020DH\u0083 \u00a2\u0006\u0004\u0008J\u0010KJ\u0010\u0010L\u001a\u00020\u001eH\u0083 \u00a2\u0006\u0004\u0008L\u0010MJ\u0018\u0010N\u001a\u00020\"2\u0006\u0010#\u001a\u00020\"H\u0083 \u00a2\u0006\u0004\u0008N\u0010OJ\u0018\u0010P\u001a\u00020F2\u0006\u0010\u0019\u001a\u00020/H\u0083 \u00a2\u0006\u0004\u0008P\u0010QR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010R\u001a\u0004\u0008S\u0010TR\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010UR\u0014\u0010\t\u001a\u00020\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u0010VR\u001a\u0010\u000b\u001a\u00020\n8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000b\u0010W\u001a\u0004\u0008X\u0010YR\u001a\u0010\r\u001a\u00020\u000c8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\r\u0010Z\u001a\u0004\u0008[\u0010\\R\u001a\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000e8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0010\u0010]R\u0017\u0010\u0014\u001a\u00020\u00138\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0014\u0010^\u001a\u0004\u0008_\u0010`R\u0017\u0010\u0015\u001a\u00020\u00138\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0015\u0010^\u001a\u0004\u0008a\u0010`R \u0010c\u001a\u000e\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u00020\u001a0b8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008c\u0010dR*\u0010\u0007\u001a\u00020\u00062\u0006\u0010e\u001a\u00020\u00068\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0007\u0010f\u001a\u0004\u0008g\u0010h\"\u0004\u0008i\u0010jR\"\u0010k\u001a\u00020F8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008k\u0010l\u001a\u0004\u0008m\u0010n\"\u0004\u0008o\u0010pR\u001a\u0010r\u001a\u0008\u0012\u0004\u0012\u00020\u00130q8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008r\u0010sR \u0010u\u001a\u0008\u0012\u0004\u0012\u00020\u00130t8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008u\u0010v\u001a\u0004\u0008u\u0010wR\u001a\u0010x\u001a\u0008\u0012\u0004\u0012\u00020\u00130q8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008x\u0010sR \u0010y\u001a\u0008\u0012\u0004\u0012\u00020\u00130t8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008y\u0010v\u001a\u0004\u0008y\u0010wR\u001a\u0010z\u001a\u00020\u00118\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008z\u0010{\u001a\u0004\u0008|\u0010}R*\u0010\u0080\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u007f0~0q8\u0016X\u0096\u0004\u00a2\u0006\u000f\n\u0005\u0008\u0080\u0001\u0010s\u001a\u0006\u0008\u0081\u0001\u0010\u0082\u0001R*\u0010\u0083\u0001\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\'0&0q8\u0016X\u0096\u0004\u00a2\u0006\u000f\n\u0005\u0008\u0083\u0001\u0010s\u001a\u0006\u0008\u0084\u0001\u0010\u0082\u0001R3\u0010\u0087\u0001\u001a\u0016\u0012\u0011\u0012\u000f\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u00020,0\u0086\u00010\u0085\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u0087\u0001\u0010\u0088\u0001\u001a\u0006\u0008\u0089\u0001\u0010\u008a\u0001R%\u0010\u008c\u0001\u001a\t\u0012\u0005\u0012\u00030\u008b\u00010q8\u0016X\u0096\u0004\u00a2\u0006\u000f\n\u0005\u0008\u008c\u0001\u0010s\u001a\u0006\u0008\u008d\u0001\u0010\u0082\u0001R\u001c\u0010\u008f\u0001\u001a\u0005\u0018\u00010\u008e\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u008f\u0001\u0010\u0090\u0001R\'\u0010\u0092\u0001\u001a\n\u0012\u0005\u0012\u00030\u0091\u00010\u0085\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u0092\u0001\u0010\u0088\u0001\u001a\u0006\u0008\u0093\u0001\u0010\u008a\u0001R&\u0010\u0094\u0001\u001a\t\u0012\u0004\u0012\u00020\u00060\u0085\u00018\u0016X\u0096\u0004\u00a2\u0006\u0010\n\u0006\u0008\u0094\u0001\u0010\u0088\u0001\u001a\u0006\u0008\u0095\u0001\u0010\u008a\u0001\u00a8\u0006\u0098\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntennaImpl;",
        "Ltechnology/cariad/cat/genx/InternalVehicleAntenna;",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "credentialsStore",
        "Landroid/content/Context;",
        "context",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "information",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkedParametersRequestValues",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "deviceInformation",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Ljava/lang/ref/WeakReference;",
        "Ltechnology/cariad/cat/genx/ScanningManager;",
        "scanningManager",
        "Lvy0/b0;",
        "coroutineScope",
        "",
        "initialBLEState",
        "initialWifiState",
        "<init>",
        "(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZ)V",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;",
        "getTransport",
        "(Ltechnology/cariad/cat/genx/TransportType;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Llx0/o;",
        "",
        "getLamVersion-IoAF18A",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "getLamVersion",
        "",
        "lamSecret",
        "calculateQPM1",
        "([BLkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "Lt41/g;",
        "beaconProximities",
        "Llx0/b0;",
        "updateBeaconProximities",
        "(Ljava/util/Set;)V",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "update",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ltechnology/cariad/cat/genx/GenXError;",
        "",
        "cgxTransportType",
        "error",
        "onErrorEncountered",
        "(BLtechnology/cariad/cat/genx/GenXError;)V",
        "onIncompatibleAntennaVersion",
        "()V",
        "onIncompatibleAppVersion",
        "enabled",
        "setClientManagerState",
        "(Ltechnology/cariad/cat/genx/TransportType;Z)V",
        "close",
        "",
        "toString",
        "()Ljava/lang/String;",
        "updateReachabilityJob",
        "Ltechnology/cariad/cat/genx/VIN;",
        "vin",
        "antenna",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "localKeyPair",
        "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
        "remoteCredentials",
        "",
        "nativeCreate",
        "(Ljava/lang/String;ILtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)J",
        "nativeDestroy",
        "nativeUpdateRemoteCredentials",
        "(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)I",
        "nativeGetLamVersion",
        "()I",
        "nativeCreateQPM1",
        "([B)[B",
        "nativeGetTransport",
        "(B)J",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "getCredentialsStore",
        "()Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "Landroid/content/Context;",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "getDeviceInformation",
        "()Ltechnology/cariad/cat/genx/DeviceInformation;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Ljava/lang/ref/WeakReference;",
        "Z",
        "getInitialBLEState",
        "()Z",
        "getInitialWifiState",
        "Ljava/util/concurrent/ConcurrentHashMap;",
        "transports",
        "Ljava/util/concurrent/ConcurrentHashMap;",
        "value",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "getInformation",
        "()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "setInformation",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V",
        "reference",
        "J",
        "getReference",
        "()J",
        "setReference",
        "(J)V",
        "Lyy0/j1;",
        "_isBluetoothEnabled",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "isBluetoothEnabled",
        "Lyy0/a2;",
        "()Lyy0/a2;",
        "_isWifiEnabled",
        "isWifiEnabled",
        "antennaCoroutineScope",
        "Lvy0/b0;",
        "getAntennaCoroutineScope$genx_release",
        "()Lvy0/b0;",
        "",
        "Lt41/b;",
        "beaconsToSearch",
        "getBeaconsToSearch",
        "()Lyy0/j1;",
        "foundBeacons",
        "getFoundBeacons",
        "Lyy0/i1;",
        "Llx0/l;",
        "encounteredError",
        "Lyy0/i1;",
        "getEncounteredError",
        "()Lyy0/i1;",
        "Ltechnology/cariad/cat/genx/Reachability;",
        "reachability",
        "getReachability",
        "Lvy0/i1;",
        "reachabilityJob",
        "Lvy0/i1;",
        "Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;",
        "softwareStackIncompatibility",
        "getSoftwareStackIncompatibility",
        "informationUpdated",
        "getInformationUpdated",
        "Outer",
        "Inner",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final _isBluetoothEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isWifiEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final antennaCoroutineScope:Lvy0/b0;

.field private final beaconsToSearch:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final context:Landroid/content/Context;

.field private final credentialsStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

.field private final deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

.field private final encounteredError:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final foundBeacons:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

.field private information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

.field private final informationUpdated:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final initialBLEState:Z

.field private final initialWifiState:Z

.field private final isBluetoothEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isWifiEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final linkedParametersRequestValues:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

.field private final reachability:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private reachabilityJob:Lvy0/i1;

.field private reference:J

.field private final scanningManager:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "Ltechnology/cariad/cat/genx/ScanningManager;",
            ">;"
        }
    .end annotation
.end field

.field private final softwareStackIncompatibility:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final transports:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ltechnology/cariad/cat/genx/TransportType;",
            "Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZ)V
    .locals 16
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
            "Landroid/content/Context;",
            "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
            "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
            "Ltechnology/cariad/cat/genx/DeviceInformation;",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Ljava/lang/ref/WeakReference<",
            "Ltechnology/cariad/cat/genx/ScanningManager;",
            ">;",
            "Lvy0/b0;",
            "ZZ)V"
        }
    .end annotation

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    move-object/from16 v4, p4

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    const-string v9, "credentialsStore"

    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "context"

    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "information"

    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "linkedParametersRequestValues"

    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "deviceInformation"

    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "genXDispatcher"

    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "scanningManager"

    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v9, "coroutineScope"

    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object v1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->credentialsStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    .line 3
    iput-object v2, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->context:Landroid/content/Context;

    .line 4
    iput-object v4, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->linkedParametersRequestValues:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 5
    iput-object v5, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 6
    iput-object v6, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 7
    iput-object v7, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->scanningManager:Ljava/lang/ref/WeakReference;

    move/from16 v2, p9

    .line 8
    iput-boolean v2, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->initialBLEState:Z

    move/from16 v4, p10

    .line 9
    iput-boolean v4, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->initialWifiState:Z

    .line 10
    new-instance v5, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v5}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object v5, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 11
    iput-object v3, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 12
    new-instance v12, Ltechnology/cariad/cat/genx/n;

    const/4 v5, 0x1

    invoke-direct {v12, v0, v3, v5}, Ltechnology/cariad/cat/genx/n;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;I)V

    .line 13
    new-instance v9, Lt51/j;

    .line 14
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v14

    .line 15
    const-string v5, "getName(...)"

    .line 16
    invoke-static {v5}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v15

    .line 17
    const-string v10, "GenX"

    sget-object v11, Lt51/g;->a:Lt51/g;

    const/4 v13, 0x0

    invoke-direct/range {v9 .. v15}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    invoke-static {v9}, Lt51/a;->a(Lt51/j;)V

    .line 19
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    move-result-object v5

    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    move-result-object v5

    .line 20
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    move-result-object v6

    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    move-result-object v6

    invoke-static {v6}, Ltechnology/cariad/cat/genx/AntennaKt;->getCgxAntenna(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/CGXAntenna;

    move-result-object v6

    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/CGXAntenna;->getRawValue()I

    move-result v6

    .line 21
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    move-result-object v7

    .line 22
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    move-result-object v3

    move-object/from16 p2, v0

    move-object/from16 p6, v1

    move-object/from16 p7, v3

    move-object/from16 p3, v5

    move/from16 p4, v6

    move-object/from16 p5, v7

    .line 23
    invoke-direct/range {p2 .. p7}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->nativeCreate(Ljava/lang/String;ILtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)J

    move-result-wide v0

    move-object/from16 v3, p2

    iput-wide v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reference:J

    .line 24
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->_isBluetoothEnabled:Lyy0/j1;

    .line 25
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 26
    iput-object v1, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->isBluetoothEnabled:Lyy0/a2;

    .line 27
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->_isWifiEnabled:Lyy0/j1;

    .line 28
    new-instance v1, Lyy0/l1;

    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 29
    iput-object v1, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->isWifiEnabled:Lyy0/a2;

    .line 30
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    move-result-object v0

    invoke-static {v8, v0}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    move-result-object v0

    new-instance v1, Lvy0/a0;

    const-string v2, "VehicleAntenna"

    invoke-direct {v1, v2}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    invoke-static {v0, v1}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    move-result-object v0

    .line 31
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$special$$inlined$CoroutineExceptionHandler$1;

    sget-object v2, Lvy0/y;->d:Lvy0/y;

    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$special$$inlined$CoroutineExceptionHandler$1;-><init>(Lvy0/y;Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)V

    .line 32
    invoke-static {v0, v1}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->antennaCoroutineScope:Lvy0/b0;

    .line 33
    sget-object v0, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getAlertBeaconUUID()Ljava/util/UUID;

    move-result-object v1

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getStandardBeaconUUID()Ljava/util/UUID;

    move-result-object v2

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getLegacyBeaconUUID()Ljava/util/UUID;

    move-result-object v0

    filled-new-array {v1, v2, v0}, [Ljava/util/UUID;

    move-result-object v0

    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    .line 34
    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    .line 36
    check-cast v2, Ljava/util/UUID;

    .line 37
    new-instance v4, Lt41/b;

    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v5

    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    move-result v5

    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    move-result-object v6

    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    move-result v6

    invoke-direct {v4, v2, v5, v6}, Lt41/b;-><init>(Ljava/util/UUID;SS)V

    .line 38
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 39
    :cond_0
    new-instance v0, Lt41/b;

    sget-object v2, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getPairingBeaconUUID()Ljava/util/UUID;

    move-result-object v2

    const/16 v4, 0x51

    const/16 v5, 0x4d

    invoke-direct {v0, v2, v4, v5}, Lt41/b;-><init>(Ljava/util/UUID;SS)V

    invoke-static {v1, v0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-static {v0}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    .line 40
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->beaconsToSearch:Lyy0/j1;

    .line 41
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->foundBeacons:Lyy0/j1;

    .line 42
    sget-object v0, Lxy0/a;->e:Lxy0/a;

    const/4 v1, 0x1

    invoke-static {v1, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->encounteredError:Lyy0/i1;

    .line 43
    iget-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    move-result-object v0

    const-string v2, "<get-values>(...)"

    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    .line 44
    move-object v2, v0

    check-cast v2, Ljava/util/Collection;

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_1

    .line 45
    :cond_1
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 46
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getReachability()Lyy0/a2;

    move-result-object v2

    invoke-interface {v2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    move-result-object v2

    sget-object v4, Ltechnology/cariad/cat/genx/Reachability;->REACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    if-ne v2, v4, :cond_2

    goto :goto_2

    .line 47
    :cond_3
    :goto_1
    sget-object v4, Ltechnology/cariad/cat/genx/Reachability;->UNREACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 48
    :goto_2
    invoke-static {v4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reachability:Lyy0/j1;

    .line 49
    sget-object v0, Lxy0/a;->e:Lxy0/a;

    invoke-static {v1, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    move-result-object v2

    iput-object v2, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->softwareStackIncompatibility:Lyy0/i1;

    .line 50
    invoke-static {v1, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    move-result-object v0

    iput-object v0, v3, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->informationUpdated:Lyy0/i1;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZILkotlin/jvm/internal/g;)V
    .locals 14

    move/from16 v0, p11

    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_0

    .line 54
    new-instance v2, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    const/16 v7, 0xf

    const/4 v8, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-direct/range {v2 .. v8}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;-><init>(IIIIILkotlin/jvm/internal/g;)V

    move-object v7, v2

    goto :goto_0

    :cond_0
    move-object/from16 v7, p4

    :goto_0
    and-int/lit16 v1, v0, 0x100

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    move v12, v2

    goto :goto_1

    :cond_1
    move/from16 v12, p9

    :goto_1
    and-int/lit16 v0, v0, 0x200

    if-eqz v0, :cond_2

    move v13, v2

    :goto_2
    move-object v3, p0

    move-object v4, p1

    move-object/from16 v5, p2

    move-object/from16 v6, p3

    move-object/from16 v8, p5

    move-object/from16 v9, p6

    move-object/from16 v10, p7

    move-object/from16 v11, p8

    goto :goto_3

    :cond_2
    move/from16 v13, p10

    goto :goto_2

    .line 55
    :goto_3
    invoke-direct/range {v3 .. v13}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStore;Landroid/content/Context;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/DeviceInformation;Ltechnology/cariad/cat/genx/GenXDispatcher;Ljava/lang/ref/WeakReference;Lvy0/b0;ZZ)V

    return-void
.end method

.method public static synthetic B(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$5(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic H(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->close$lambda$1(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic M(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$2(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic T(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->_init_$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic U(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$3$1(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic V(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->close$lambda$3(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final _init_$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getAntenna(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/Antenna;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    new-instance v1, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v2, "init(): "

    .line 16
    .line 17
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v0, ", "

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/TransportType;)Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getTransport$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/TransportType;)Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getTransports$p(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/util/concurrent/ConcurrentHashMap;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b(Ljava/util/Set;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->updateBeaconProximities$lambda$0(Ljava/util/Set;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final calculateQPM1$lambda$0([B)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "calculateQPM1(): lamSecret = "

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final calculateQPM1$lambda$1(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;[B)[B
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->nativeCreateQPM1([B)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic calculateQPM1$suspendImpl(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;[BLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntennaImpl;",
            "[B",
            "Lkotlin/coroutines/Continuation<",
            "-[B>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/j;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {v3, v0, p1}, Ltechnology/cariad/cat/genx/j;-><init>(I[B)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    new-instance v1, Ltechnology/cariad/cat/genx/u0;

    .line 35
    .line 36
    const/4 v2, 0x6

    .line 37
    invoke-direct {v1, v2, p0, p1}, Ltechnology/cariad/cat/genx/u0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0, v1, p2}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->dispatchSuspendedWithValue(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$1(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const-string v0, "close(): Close all "

    .line 8
    .line 9
    const-string v1, " transports"

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final close$lambda$3(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Llx0/b0;
    .locals 4

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reference:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->nativeDestroy()V

    .line 10
    .line 11
    .line 12
    iput-wide v2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reference:J

    .line 13
    .line 14
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->antennaCoroutineScope:Lvy0/b0;

    .line 15
    .line 16
    const-string v0, "close()"

    .line 17
    .line 18
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method

.method public static synthetic d(Ljava/util/List;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$4$1(Ljava/util/List;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getTransport$lambda$0$0(Ltechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$3$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static getLamVersion-IoAF18A$suspendImpl(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntennaImpl;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->L$0:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    check-cast p1, Llx0/o;

    .line 44
    .line 45
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    new-instance v2, Ltechnology/cariad/cat/genx/o;

    .line 64
    .line 65
    const/4 v4, 0x3

    .line 66
    invoke-direct {v2, p0, v4}, Ltechnology/cariad/cat/genx/o;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;I)V

    .line 67
    .line 68
    .line 69
    const/4 p0, 0x0

    .line 70
    iput-object p0, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->L$0:Ljava/lang/Object;

    .line 71
    .line 72
    iput v3, v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$getLamVersion$1;->label:I

    .line 73
    .line 74
    invoke-static {p1, v2, v0}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->dispatchSuspendedWithResult(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    if-ne p0, v1, :cond_3

    .line 79
    .line 80
    return-object v1

    .line 81
    :cond_3
    return-object p0
.end method

.method private static final getLamVersion_IoAF18A$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Llx0/o;
    .locals 1

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->nativeGetLamVersion()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v0, Llx0/o;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method private static final getTransport$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/TransportType;)Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/TransportType;->getCgxValue$genx_release()B

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->nativeGetTransport(B)J

    .line 23
    .line 24
    .line 25
    move-result-wide v2

    .line 26
    const-wide/16 v0, 0x0

    .line 27
    .line 28
    cmp-long v0, v2, v0

    .line 29
    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    new-instance v0, Ltechnology/cariad/cat/genx/s;

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-direct {v0, p1, v1}, Ltechnology/cariad/cat/genx/s;-><init>(Ltechnology/cariad/cat/genx/TransportType;I)V

    .line 36
    .line 37
    .line 38
    const-string p1, "GenX"

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    invoke-static {p0, p1, v1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 42
    .line 43
    .line 44
    return-object v1

    .line 45
    :cond_1
    iget-object v5, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->context:Landroid/content/Context;

    .line 46
    .line 47
    iget-object v6, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->linkedParametersRequestValues:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 48
    .line 49
    iget-object v8, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->scanningManager:Ljava/lang/ref/WeakReference;

    .line 50
    .line 51
    iget-object v9, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->antennaCoroutineScope:Lvy0/b0;

    .line 52
    .line 53
    sget-object v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    aget v0, v0, v1

    .line 60
    .line 61
    const/4 v1, 0x1

    .line 62
    if-eq v0, v1, :cond_3

    .line 63
    .line 64
    const/4 v1, 0x2

    .line 65
    if-eq v0, v1, :cond_2

    .line 66
    .line 67
    const/4 v0, 0x0

    .line 68
    :goto_0
    move v10, v0

    .line 69
    goto :goto_1

    .line 70
    :cond_2
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->isWifiEnabled()Lyy0/a2;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    check-cast v0, Ljava/lang/Boolean;

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    goto :goto_0

    .line 85
    :cond_3
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->isBluetoothEnabled()Lyy0/a2;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    check-cast v0, Ljava/lang/Boolean;

    .line 94
    .line 95
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    goto :goto_0

    .line 100
    :goto_1
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 101
    .line 102
    move-object v7, p0

    .line 103
    move-object v4, p1

    .line 104
    invoke-direct/range {v1 .. v10}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;-><init>(JLtechnology/cariad/cat/genx/TransportType;Landroid/content/Context;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/InternalVehicleAntenna;Ljava/lang/ref/WeakReference;Lvy0/b0;Z)V

    .line 105
    .line 106
    .line 107
    iget-object p0, v7, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 108
    .line 109
    invoke-interface {p0, v4, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    invoke-direct {v7}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->updateReachabilityJob()V

    .line 113
    .line 114
    .line 115
    return-object v1
.end method

.method private static final getTransport$lambda$0$0(Ltechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "getTransport(): Unable to retrieve Transport for "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic h([B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->calculateQPM1$lambda$0([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic k()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->update$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;[B)[B
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->calculateQPM1$lambda$1(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;[B)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final native nativeCreate(Ljava/lang/String;ILtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/CredentialStore;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)J
.end method

.method private final native nativeCreateQPM1([B)[B
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeDestroy()V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeGetLamVersion()I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeGetTransport(B)J
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method private final native nativeUpdateRemoteCredentials(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public static synthetic q(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Llx0/o;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getLamVersion_IoAF18A$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Llx0/o;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final update$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "update(): LocalKeyPair cannot be updated"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final update$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "update(): LocalKeyPair cannot be updated"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final update$lambda$2(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->nativeUpdateRemoteCredentials(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method private static final update$lambda$3$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "update(): Failed to update RemoteCredentials and Beacons"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final update$lambda$3$1(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "update(): Successfully updated remoteCredentials of "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method private static final update$lambda$4$1(Ljava/util/List;)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "update(): Updated local beacons to search for to "

    .line 15
    .line 16
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final update$lambda$5(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "update(): Antenna information updated to "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final updateBeaconProximities$lambda$0(Ljava/util/Set;)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "updateBeaconProximities(): beaconProximities = "

    .line 15
    .line 16
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private final updateReachabilityJob()V
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reachabilityJob:Lvy0/i1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v1, "updateReachabilityJob() called"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->antennaCoroutineScope:Lvy0/b0;

    .line 11
    .line 12
    new-instance v1, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$updateReachabilityJob$1;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    const/4 v3, 0x3

    .line 19
    invoke-static {v0, v2, v2, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reachabilityJob:Lvy0/i1;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public calculateQPM1([BLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([B",
            "Lkotlin/coroutines/Continuation<",
            "-[B>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->calculateQPM1$suspendImpl(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;[BLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public close()V
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/s0;

    .line 2
    .line 3
    const/16 v0, 0x15

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v7, "getName(...)"

    .line 15
    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reachabilityJob:Lvy0/i1;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const-string v1, "close()"

    .line 36
    .line 37
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    const/4 v0, 0x0

    .line 41
    iput-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reachabilityJob:Lvy0/i1;

    .line 42
    .line 43
    new-instance v11, Ltechnology/cariad/cat/genx/o;

    .line 44
    .line 45
    const/4 v0, 0x1

    .line 46
    invoke-direct {v11, p0, v0}, Ltechnology/cariad/cat/genx/o;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;I)V

    .line 47
    .line 48
    .line 49
    new-instance v8, Lt51/j;

    .line 50
    .line 51
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v13

    .line 55
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v14

    .line 59
    const-string v9, "GenX"

    .line 60
    .line 61
    sget-object v10, Lt51/d;->a:Lt51/d;

    .line 62
    .line 63
    const/4 v12, 0x0

    .line 64
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 68
    .line 69
    .line 70
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    const-string v1, "<get-values>(...)"

    .line 77
    .line 78
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    check-cast v0, Ljava/lang/Iterable;

    .line 82
    .line 83
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_1

    .line 92
    .line 93
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    check-cast v1, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 98
    .line 99
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    new-instance v1, Ltechnology/cariad/cat/genx/o;

    .line 113
    .line 114
    const/4 v2, 0x2

    .line 115
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/o;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;I)V

    .line 116
    .line 117
    .line 118
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 119
    .line 120
    .line 121
    return-void
.end method

.method public final getAntennaCoroutineScope$genx_release()Lvy0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->antennaCoroutineScope:Lvy0/b0;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getBeaconsToSearch()Lyy0/a2;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getBeaconsToSearch()Lyy0/j1;

    move-result-object p0

    return-object p0
.end method

.method public getBeaconsToSearch()Lyy0/j1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/j1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->beaconsToSearch:Lyy0/j1;

    return-object p0
.end method

.method public final getCredentialsStore()Ltechnology/cariad/cat/genx/crypto/CredentialStore;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->credentialsStore:Ltechnology/cariad/cat/genx/crypto/CredentialStore;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->deviceInformation:Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEncounteredError()Lyy0/i1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->encounteredError:Lyy0/i1;

    return-object p0
.end method

.method public bridge synthetic getEncounteredError()Lyy0/i;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getEncounteredError()Lyy0/i1;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getFoundBeacons()Lyy0/a2;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getFoundBeacons()Lyy0/j1;

    move-result-object p0

    return-object p0
.end method

.method public getFoundBeacons()Lyy0/j1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/j1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->foundBeacons:Lyy0/j1;

    return-object p0
.end method

.method public getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInformationUpdated()Lyy0/i1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->informationUpdated:Lyy0/i1;

    return-object p0
.end method

.method public bridge synthetic getInformationUpdated()Lyy0/i;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformationUpdated()Lyy0/i1;

    move-result-object p0

    return-object p0
.end method

.method public final getInitialBLEState()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->initialBLEState:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getInitialWifiState()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->initialWifiState:Z

    .line 2
    .line 3
    return p0
.end method

.method public getLamVersion-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getLamVersion-IoAF18A$suspendImpl(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic getReachability()Lyy0/a2;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getReachability()Lyy0/j1;

    move-result-object p0

    return-object p0
.end method

.method public getReachability()Lyy0/j1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/j1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reachability:Lyy0/j1;

    return-object p0
.end method

.method public final getReference()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reference:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getSoftwareStackIncompatibility()Lyy0/i1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i1;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->softwareStackIncompatibility:Lyy0/i1;

    return-object p0
.end method

.method public bridge synthetic getSoftwareStackIncompatibility()Lyy0/i;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getSoftwareStackIncompatibility()Lyy0/i1;

    move-result-object p0

    return-object p0
.end method

.method public final getTransport(Ltechnology/cariad/cat/genx/TransportType;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/TransportType;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    new-instance v1, Ltechnology/cariad/cat/genx/u0;

    .line 16
    .line 17
    const/4 v2, 0x5

    .line 18
    invoke-direct {v1, v2, p0, p1}, Ltechnology/cariad/cat/genx/u0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0, v1, p2}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->dispatchSuspendedWithValue(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    return-object v0
.end method

.method public isBluetoothEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->isBluetoothEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isWifiEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->isWifiEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public onErrorEncountered(BLtechnology/cariad/cat/genx/GenXError;)V
    .locals 1

    .line 1
    const-string v0, "error"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ltechnology/cariad/cat/genx/TransportTypeKt;->getTransportType(B)Ltechnology/cariad/cat/genx/TransportType;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getEncounteredError()Lyy0/i1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance v0, Llx0/l;

    .line 15
    .line 16
    invoke-direct {v0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p0, v0}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public onIncompatibleAntennaVersion()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getSoftwareStackIncompatibility()Lyy0/i1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;->ANTENNA_VERSION:Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;

    .line 6
    .line 7
    invoke-interface {p0, v0}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public onIncompatibleAppVersion()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getSoftwareStackIncompatibility()Lyy0/i1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;->APPLICATION_VERSION:Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;

    .line 6
    .line 7
    invoke-interface {p0, v0}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public setClientManagerState(Ltechnology/cariad/cat/genx/TransportType;Z)V
    .locals 3

    .line 1
    const-string v0, "transportType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    aget v0, v0, v1

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    const/4 v2, 0x0

    .line 16
    if-eq v0, v1, :cond_2

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    if-eq v0, v1, :cond_1

    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    if-ne v0, v1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->_isWifiEnabled:Lyy0/j1;

    .line 32
    .line 33
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v0, Lyy0/c2;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->_isBluetoothEnabled:Lyy0/j1;

    .line 47
    .line 48
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    check-cast v0, Lyy0/c2;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    :goto_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->transports:Ljava/util/concurrent/ConcurrentHashMap;

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 67
    .line 68
    if-eqz p0, :cond_3

    .line 69
    .line 70
    invoke-interface {p0, p2}, Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;->setClientManagerState(Z)V

    .line 71
    .line 72
    .line 73
    :cond_3
    return-void
.end method

.method public setInformation(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 7
    .line 8
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 15
    .line 16
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformationUpdated()Lyy0/i1;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {p0, p1}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public final setReference(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reference:J

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-wide v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->reference:J

    .line 6
    .line 7
    new-instance p0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "VehicleAntennaImpl(identifier="

    .line 10
    .line 11
    invoke-direct {p0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", reference="

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ")"

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public update(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 21
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "information"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    const-string v3, "GenX"

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    new-instance v2, Ltechnology/cariad/cat/genx/s0;

    .line 32
    .line 33
    const/16 v5, 0x12

    .line 34
    .line 35
    invoke-direct {v2, v5}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0, v3, v4, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 39
    .line 40
    .line 41
    :cond_0
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 46
    .line 47
    .line 48
    move-result-object v5

    .line 49
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-nez v2, :cond_1

    .line 54
    .line 55
    new-instance v2, Ltechnology/cariad/cat/genx/s0;

    .line 56
    .line 57
    const/16 v5, 0x13

    .line 58
    .line 59
    invoke-direct {v2, v5}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 60
    .line 61
    .line 62
    invoke-static {v0, v3, v4, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 63
    .line 64
    .line 65
    :cond_1
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 82
    .line 83
    const-string v12, "getName(...)"

    .line 84
    .line 85
    if-nez v2, :cond_3

    .line 86
    .line 87
    new-instance v2, Ltechnology/cariad/cat/genx/n;

    .line 88
    .line 89
    const/4 v5, 0x0

    .line 90
    invoke-direct {v2, v0, v1, v5}, Ltechnology/cariad/cat/genx/n;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;I)V

    .line 91
    .line 92
    .line 93
    invoke-static {v2}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    if-eqz v2, :cond_2

    .line 98
    .line 99
    new-instance v1, Ltechnology/cariad/cat/genx/s0;

    .line 100
    .line 101
    const/16 v4, 0x14

    .line 102
    .line 103
    invoke-direct {v1, v4}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-static {v0, v3, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 107
    .line 108
    .line 109
    return-object v2

    .line 110
    :cond_2
    new-instance v8, Ltechnology/cariad/cat/genx/o;

    .line 111
    .line 112
    const/4 v2, 0x0

    .line 113
    invoke-direct {v8, v0, v2}, Ltechnology/cariad/cat/genx/o;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;I)V

    .line 114
    .line 115
    .line 116
    new-instance v5, Lt51/j;

    .line 117
    .line 118
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v10

    .line 122
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v11

    .line 126
    const-string v6, "GenX"

    .line 127
    .line 128
    const/4 v9, 0x0

    .line 129
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 136
    .line 137
    .line 138
    move-result-object v13

    .line 139
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 140
    .line 141
    .line 142
    move-result-object v16

    .line 143
    const/16 v19, 0x1b

    .line 144
    .line 145
    const/16 v20, 0x0

    .line 146
    .line 147
    const/4 v14, 0x0

    .line 148
    const/4 v15, 0x0

    .line 149
    const/16 v17, 0x0

    .line 150
    .line 151
    const/16 v18, 0x0

    .line 152
    .line 153
    invoke-static/range {v13 .. v20}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->copy-SoBU8ic$default(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSILjava/lang/Object;)Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-virtual {v0, v2}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->setInformation(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V

    .line 158
    .line 159
    .line 160
    :cond_3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getBeaconsToSearch()Lyy0/j1;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    :cond_4
    move-object v3, v2

    .line 165
    check-cast v3, Lyy0/c2;

    .line 166
    .line 167
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v13

    .line 171
    move-object v5, v13

    .line 172
    check-cast v5, Ljava/util/List;

    .line 173
    .line 174
    check-cast v5, Ljava/lang/Iterable;

    .line 175
    .line 176
    new-instance v6, Ljava/util/ArrayList;

    .line 177
    .line 178
    const/16 v8, 0xa

    .line 179
    .line 180
    invoke-static {v5, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 181
    .line 182
    .line 183
    move-result v8

    .line 184
    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 185
    .line 186
    .line 187
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 188
    .line 189
    .line 190
    move-result-object v5

    .line 191
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 192
    .line 193
    .line 194
    move-result v8

    .line 195
    if-eqz v8, :cond_6

    .line 196
    .line 197
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v8

    .line 201
    check-cast v8, Lt41/b;

    .line 202
    .line 203
    iget-object v9, v8, Lt41/b;->d:Ljava/util/UUID;

    .line 204
    .line 205
    sget-object v10, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 206
    .line 207
    invoke-virtual {v10}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getPairingBeaconUUID()Ljava/util/UUID;

    .line 208
    .line 209
    .line 210
    move-result-object v10

    .line 211
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v9

    .line 215
    if-eqz v9, :cond_5

    .line 216
    .line 217
    goto :goto_1

    .line 218
    :cond_5
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    .line 219
    .line 220
    .line 221
    move-result v9

    .line 222
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    .line 223
    .line 224
    .line 225
    move-result v10

    .line 226
    iget-object v8, v8, Lt41/b;->d:Ljava/util/UUID;

    .line 227
    .line 228
    const-string v11, "proximityUUID"

    .line 229
    .line 230
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    new-instance v11, Lt41/b;

    .line 234
    .line 235
    invoke-direct {v11, v8, v9, v10}, Lt41/b;-><init>(Ljava/util/UUID;SS)V

    .line 236
    .line 237
    .line 238
    move-object v8, v11

    .line 239
    :goto_1
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    goto :goto_0

    .line 243
    :cond_6
    invoke-static {v6}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    .line 244
    .line 245
    .line 246
    move-result-object v14

    .line 247
    new-instance v8, Ltechnology/cariad/cat/genx/p;

    .line 248
    .line 249
    const/4 v5, 0x0

    .line 250
    invoke-direct {v8, v14, v5}, Ltechnology/cariad/cat/genx/p;-><init>(Ljava/util/List;I)V

    .line 251
    .line 252
    .line 253
    new-instance v5, Lt51/j;

    .line 254
    .line 255
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v10

    .line 259
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v11

    .line 263
    const-string v6, "GenX"

    .line 264
    .line 265
    const/4 v9, 0x0

    .line 266
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v3, v13, v14}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-result v3

    .line 276
    if-eqz v3, :cond_4

    .line 277
    .line 278
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 279
    .line 280
    .line 281
    move-result-object v13

    .line 282
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    .line 283
    .line 284
    .line 285
    move-result v18

    .line 286
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    .line 287
    .line 288
    .line 289
    move-result v17

    .line 290
    const/16 v19, 0x7

    .line 291
    .line 292
    const/16 v20, 0x0

    .line 293
    .line 294
    const/4 v14, 0x0

    .line 295
    const/4 v15, 0x0

    .line 296
    const/16 v16, 0x0

    .line 297
    .line 298
    invoke-static/range {v13 .. v20}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->copy-SoBU8ic$default(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SSILjava/lang/Object;)Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 299
    .line 300
    .line 301
    move-result-object v2

    .line 302
    invoke-virtual {v0, v2}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->setInformation(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V

    .line 303
    .line 304
    .line 305
    new-instance v8, Ltechnology/cariad/cat/genx/q;

    .line 306
    .line 307
    const/4 v2, 0x0

    .line 308
    invoke-direct {v8, v1, v2}, Ltechnology/cariad/cat/genx/q;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;I)V

    .line 309
    .line 310
    .line 311
    new-instance v5, Lt51/j;

    .line 312
    .line 313
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 314
    .line 315
    .line 316
    move-result-object v10

    .line 317
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object v11

    .line 321
    const-string v6, "GenX"

    .line 322
    .line 323
    sget-object v7, Lt51/f;->a:Lt51/f;

    .line 324
    .line 325
    const/4 v9, 0x0

    .line 326
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 330
    .line 331
    .line 332
    return-object v4
.end method

.method public updateBeaconProximities(Ljava/util/Set;)V
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lt41/g;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "beaconProximities"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/m;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/m;-><init>(ILjava/util/Set;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getFoundBeacons()Lyy0/j1;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast p1, Ljava/lang/Iterable;

    .line 40
    .line 41
    new-instance v1, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 44
    .line 45
    .line 46
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-eqz v2, :cond_2

    .line 55
    .line 56
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    move-object v3, v2

    .line 61
    check-cast v3, Lt41/g;

    .line 62
    .line 63
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->getBeaconsToSearch()Lyy0/j1;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    check-cast v4, Lyy0/c2;

    .line 68
    .line 69
    invoke-virtual {v4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    check-cast v4, Ljava/util/List;

    .line 74
    .line 75
    invoke-virtual {v3}, Lt41/g;->a()Lt41/b;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    invoke-interface {v4, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-eqz v4, :cond_0

    .line 84
    .line 85
    instance-of v4, v3, Lt41/e;

    .line 86
    .line 87
    if-nez v4, :cond_1

    .line 88
    .line 89
    instance-of v3, v3, Lt41/d;

    .line 90
    .line 91
    if-eqz v3, :cond_0

    .line 92
    .line 93
    :cond_1
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_2
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    check-cast v0, Lyy0/c2;

    .line 102
    .line 103
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    const/4 p1, 0x0

    .line 107
    invoke-virtual {v0, p1, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    return-void
.end method
