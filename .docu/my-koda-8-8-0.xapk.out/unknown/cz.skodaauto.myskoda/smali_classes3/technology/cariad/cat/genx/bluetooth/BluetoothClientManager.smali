.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/ClientManager;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00c4\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0011\n\u0002\u0010\t\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008\u0000\u0018\u00002\u00020\u0001B/\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0008\u0012\u0006\u0010\n\u001a\u00020\u0008\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0011\u0010\u000e\u001a\u0004\u0018\u00010\rH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u0019\u0010\u000e\u001a\u0004\u0018\u00010\r2\u0006\u0010\u0011\u001a\u00020\u0010H\u0000\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u0011\u0010\u0014\u001a\u0004\u0018\u00010\rH\u0016\u00a2\u0006\u0004\u0008\u0014\u0010\u000fJ\u000f\u0010\u0018\u001a\u00020\u0015H\u0001\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u0017\u0010\u001b\u001a\u00020\u00152\u0006\u0010\u001a\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u000f\u0010\u001d\u001a\u00020\u0015H\u0016\u00a2\u0006\u0004\u0008\u001d\u0010\u0017J\u000f\u0010\u001f\u001a\u00020\u0015H\u0000\u00a2\u0006\u0004\u0008\u001e\u0010\u0017J\u0017\u0010$\u001a\u00020\u00152\u0006\u0010!\u001a\u00020 H\u0000\u00a2\u0006\u0004\u0008\"\u0010#J\u000f\u0010&\u001a\u00020\u0015H\u0000\u00a2\u0006\u0004\u0008%\u0010\u0017J\u0017\u0010(\u001a\u00020\u00152\u0006\u0010!\u001a\u00020 H\u0000\u00a2\u0006\u0004\u0008\'\u0010#J\u000f\u0010*\u001a\u00020\u0015H\u0000\u00a2\u0006\u0004\u0008)\u0010\u0017J\u001f\u00100\u001a\u00020\u00152\u0006\u0010,\u001a\u00020+2\u0006\u0010-\u001a\u00020\u0019H\u0000\u00a2\u0006\u0004\u0008.\u0010/J\u001d\u00104\u001a\u00020\u00152\u000c\u0010-\u001a\u0008\u0012\u0004\u0012\u00020\u001901H\u0000\u00a2\u0006\u0004\u00082\u00103J\'\u0010:\u001a\u00020\u00152\u000c\u00107\u001a\u0008\u0012\u0004\u0012\u000206052\u0008\u00109\u001a\u0004\u0018\u000108H\u0003\u00a2\u0006\u0004\u0008:\u0010;J\'\u0010<\u001a\u00020\u00152\u000c\u00107\u001a\u0008\u0012\u0004\u0012\u000206052\u0008\u00109\u001a\u0004\u0018\u000108H\u0003\u00a2\u0006\u0004\u0008<\u0010;R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010=\u001a\u0004\u0008>\u0010?R\u0017\u0010\u0005\u001a\u00020\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010@\u001a\u0004\u0008A\u0010BR\u001a\u0010\u0007\u001a\u00020\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010C\u001a\u0004\u0008D\u0010ER\u0017\u0010\t\u001a\u00020\u00088\u0006\u00a2\u0006\u000c\n\u0004\u0008\t\u0010F\u001a\u0004\u0008G\u0010HR\u0017\u0010\n\u001a\u00020\u00088\u0006\u00a2\u0006\u000c\n\u0004\u0008\n\u0010F\u001a\u0004\u0008I\u0010HR\"\u0010K\u001a\u00020J8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008K\u0010L\u001a\u0004\u0008M\u0010N\"\u0004\u0008O\u0010PR\u001a\u0010R\u001a\u00020Q8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008R\u0010S\u001a\u0004\u0008T\u0010UR\u0014\u0010W\u001a\u00020V8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008W\u0010XR$\u0010Z\u001a\u0004\u0018\u00010Y8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008Z\u0010[\u001a\u0004\u0008\\\u0010]\"\u0004\u0008^\u0010_R \u0010a\u001a\u0008\u0012\u0004\u0012\u00020\u00100`8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008a\u0010b\u001a\u0004\u0008c\u0010dR&\u0010f\u001a\u000e\u0012\u0004\u0012\u00020\u0019\u0012\u0004\u0012\u00020 0e8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008f\u0010g\u001a\u0004\u0008h\u0010iR\u0014\u0010k\u001a\u00020j8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008k\u0010lR\u001a\u0010n\u001a\u00020m8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008n\u0010o\u001a\u0004\u0008p\u0010qR\u0016\u0010r\u001a\u00020\u00108\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008r\u0010sR\u0014\u0010t\u001a\u00020j8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008t\u0010lR\u0018\u0010v\u001a\u0004\u0018\u00010u8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008v\u0010wR\u001a\u0010y\u001a\u00020x8\u0002X\u0082\u0004\u00a2\u0006\u000c\n\u0004\u0008y\u0010z\u0012\u0004\u0008{\u0010\u0017R\u0018\u0010}\u001a\u0004\u0018\u00010|8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008}\u0010~R\u0015\u0010\u007f\u001a\u00020\u00108VX\u0096\u0004\u00a2\u0006\u0007\u001a\u0005\u0008\u007f\u0010\u0080\u0001R\u0017\u0010\u0081\u0001\u001a\u00020\u00108VX\u0096\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u0081\u0001\u0010\u0080\u0001\u00a8\u0006\u0082\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;",
        "Ltechnology/cariad/cat/genx/ClientManager;",
        "Landroid/content/Context;",
        "context",
        "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
        "bluetoothScanMode",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "",
        "bluetoothConnectRetryCount",
        "bluetoothConnectRetryDelay",
        "<init>",
        "(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;Ltechnology/cariad/cat/genx/GenXDispatcher;II)V",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "startScanningForClients",
        "()Ltechnology/cariad/cat/genx/GenXError;",
        "",
        "forceStart",
        "startScanningForClients$genx_release",
        "(Z)Ltechnology/cariad/cat/genx/GenXError;",
        "stopScanningForClients",
        "Llx0/b0;",
        "stopScan$genx_release",
        "()V",
        "stopScan",
        "",
        "identifier",
        "removeClient",
        "(Ljava/lang/String;)V",
        "close",
        "propagateClientManagerState$genx_release",
        "propagateClientManagerState",
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;",
        "bluetoothClient",
        "deviceDisconnected$genx_release",
        "(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V",
        "deviceDisconnected",
        "removeAllClientsThatShouldBeRemoved$genx_release",
        "removeAllClientsThatShouldBeRemoved",
        "deviceShouldBeRemovedAfterAdvertisementStopped$genx_release",
        "deviceShouldBeRemovedAfterAdvertisementStopped",
        "cancelNoResponseCancellationJob$genx_release",
        "cancelNoResponseCancellationJob",
        "Ltechnology/cariad/cat/genx/CoreGenXStatus;",
        "status",
        "message",
        "reportCoreGenXScanError$genx_release",
        "(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V",
        "reportCoreGenXScanError",
        "Lkotlin/Function0;",
        "logScanning$genx_release",
        "(Lay0/a;)V",
        "logScanning",
        "",
        "Landroid/bluetooth/le/ScanFilter;",
        "scanFilters",
        "Landroid/bluetooth/le/ScanSettings;",
        "settings",
        "startScan",
        "(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V",
        "startTimerToRestartScanIfNotResponsive",
        "Landroid/content/Context;",
        "getContext",
        "()Landroid/content/Context;",
        "Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
        "getBluetoothScanMode",
        "()Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "I",
        "getBluetoothConnectRetryCount",
        "()I",
        "getBluetoothConnectRetryDelay",
        "",
        "reference",
        "J",
        "getReference",
        "()J",
        "setReference",
        "(J)V",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "getTransportType",
        "()Ltechnology/cariad/cat/genx/TransportType;",
        "Lvy0/b0;",
        "mainScope",
        "Lvy0/b0;",
        "Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "delegate",
        "Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "getDelegate",
        "()Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "setDelegate",
        "(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V",
        "Lyy0/j1;",
        "isBleEnabled",
        "Lyy0/j1;",
        "isBleEnabled$genx_release",
        "()Lyy0/j1;",
        "Ljava/util/concurrent/ConcurrentHashMap;",
        "clients",
        "Ljava/util/concurrent/ConcurrentHashMap;",
        "getClients$genx_release",
        "()Ljava/util/concurrent/ConcurrentHashMap;",
        "Ljava/util/concurrent/Semaphore;",
        "scanningSemaphore",
        "Ljava/util/concurrent/Semaphore;",
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
        "scanning",
        "Ljava/util/concurrent/atomic/AtomicBoolean;",
        "getScanning$genx_release",
        "()Ljava/util/concurrent/atomic/AtomicBoolean;",
        "scanningWasRequested",
        "Z",
        "scanResultSemaphore",
        "Lvy0/i1;",
        "noResponseCancellationJob",
        "Lvy0/i1;",
        "Landroid/bluetooth/le/ScanCallback;",
        "scanCallback",
        "Landroid/bluetooth/le/ScanCallback;",
        "getScanCallback$annotations",
        "Landroid/content/BroadcastReceiver;",
        "bluetoothStateReceiver",
        "Landroid/content/BroadcastReceiver;",
        "isEnabled",
        "()Z",
        "isScanningRequired",
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
.field private final bluetoothConnectRetryCount:I

.field private final bluetoothConnectRetryDelay:I

.field private final bluetoothScanMode:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

.field private bluetoothStateReceiver:Landroid/content/BroadcastReceiver;

.field private final clients:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/String;",
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;",
            ">;"
        }
    .end annotation
.end field

.field private final context:Landroid/content/Context;

.field private delegate:Ltechnology/cariad/cat/genx/ClientManagerDelegate;

.field private final genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

.field private final isBleEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final mainScope:Lvy0/b0;

.field private noResponseCancellationJob:Lvy0/i1;

.field private reference:J

.field private final scanCallback:Landroid/bluetooth/le/ScanCallback;

.field private final scanResultSemaphore:Ljava/util/concurrent/Semaphore;

.field private final scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private final scanningSemaphore:Ljava/util/concurrent/Semaphore;

.field private scanningWasRequested:Z

.field private final transportType:Ltechnology/cariad/cat/genx/TransportType;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;Ltechnology/cariad/cat/genx/GenXDispatcher;II)V
    .locals 7

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bluetoothScanMode"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "genXDispatcher"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 20
    .line 21
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothScanMode:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 22
    .line 23
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 24
    .line 25
    iput p4, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothConnectRetryCount:I

    .line 26
    .line 27
    iput p5, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothConnectRetryDelay:I

    .line 28
    .line 29
    sget-object p2, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 30
    .line 31
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->transportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 32
    .line 33
    invoke-static {}, Lvy0/e0;->e()Lpw0/a;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->mainScope:Lvy0/b0;

    .line 38
    .line 39
    sget-object p2, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 40
    .line 41
    invoke-virtual {p2, p1}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBleEnabled(Landroid/content/Context;)Z

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isBleEnabled:Lyy0/j1;

    .line 54
    .line 55
    new-instance p2, Ljava/util/concurrent/ConcurrentHashMap;

    .line 56
    .line 57
    invoke-direct {p2}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 61
    .line 62
    new-instance p2, Ljava/util/concurrent/Semaphore;

    .line 63
    .line 64
    const/4 p3, 0x1

    .line 65
    invoke-direct {p2, p3}, Ljava/util/concurrent/Semaphore;-><init>(I)V

    .line 66
    .line 67
    .line 68
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 69
    .line 70
    new-instance p2, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 71
    .line 72
    const/4 p4, 0x0

    .line 73
    invoke-direct {p2, p4}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 74
    .line 75
    .line 76
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 77
    .line 78
    new-instance p2, Ljava/util/concurrent/Semaphore;

    .line 79
    .line 80
    invoke-direct {p2, p3}, Ljava/util/concurrent/Semaphore;-><init>(I)V

    .line 81
    .line 82
    .line 83
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanResultSemaphore:Ljava/util/concurrent/Semaphore;

    .line 84
    .line 85
    new-instance p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;

    .line 86
    .line 87
    invoke-direct {p2, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V

    .line 88
    .line 89
    .line 90
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanCallback:Landroid/bluetooth/le/ScanCallback;

    .line 91
    .line 92
    new-instance p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;

    .line 93
    .line 94
    invoke-direct {p2, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$bluetoothStateReceiver$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V

    .line 95
    .line 96
    .line 97
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothStateReceiver:Landroid/content/BroadcastReceiver;

    .line 98
    .line 99
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 100
    .line 101
    const/4 p2, 0x5

    .line 102
    invoke-direct {v3, p2}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 103
    .line 104
    .line 105
    new-instance v0, Lt51/j;

    .line 106
    .line 107
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    const-string p2, "getName(...)"

    .line 112
    .line 113
    invoke-static {p2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v6

    .line 117
    const-string v1, "GenX"

    .line 118
    .line 119
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 120
    .line 121
    const/4 v4, 0x0

    .line 122
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 129
    .line 130
    .line 131
    move-result-object p3

    .line 132
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/TransportType;->getCgxValue$genx_release()B

    .line 133
    .line 134
    .line 135
    move-result p3

    .line 136
    invoke-static {p0, p3}, Ltechnology/cariad/cat/genx/ClientManagerKt;->nativeCreate(Ltechnology/cariad/cat/genx/ClientManager;B)J

    .line 137
    .line 138
    .line 139
    move-result-wide p3

    .line 140
    invoke-virtual {p0, p3, p4}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->setReference(J)V

    .line 141
    .line 142
    .line 143
    :try_start_0
    iget-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothStateReceiver:Landroid/content/BroadcastReceiver;

    .line 144
    .line 145
    new-instance p4, Landroid/content/IntentFilter;

    .line 146
    .line 147
    const-string p5, "android.bluetooth.adapter.action.STATE_CHANGED"

    .line 148
    .line 149
    invoke-direct {p4, p5}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p1, p3, p4}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 153
    .line 154
    .line 155
    return-void

    .line 156
    :catch_0
    move-exception v0

    .line 157
    move-object p1, v0

    .line 158
    move-object v4, p1

    .line 159
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 160
    .line 161
    const/4 p1, 0x6

    .line 162
    invoke-direct {v3, p1}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 163
    .line 164
    .line 165
    new-instance v0, Lt51/j;

    .line 166
    .line 167
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    invoke-static {p2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    const-string v1, "GenX"

    .line 176
    .line 177
    sget-object v2, Lt51/e;->a:Lt51/e;

    .line 178
    .line 179
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 183
    .line 184
    .line 185
    const/4 p1, 0x0

    .line 186
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothStateReceiver:Landroid/content/BroadcastReceiver;

    .line 187
    .line 188
    return-void
.end method

.method public static synthetic B()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->close$lambda$2$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic E()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic H()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->_init_$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic M(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeAllClientsThatShouldBeRemoved$lambda$1$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic T()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScanningForClients$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic U(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceShouldBeRemovedAfterAdvertisementStopped$lambda$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic V()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScanningForClients$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic W(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceShouldBeRemovedAfterAdvertisementStopped$lambda$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final _init_$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): Create BluetoothClientManager"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final _init_$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): Cannot register Bluetooth state change receiver"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final synthetic access$getScanCallback$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Landroid/bluetooth/le/ScanCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanCallback:Landroid/bluetooth/le/ScanCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getScanResultSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanResultSemaphore:Ljava/util/concurrent/Semaphore;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getScanningSemaphore$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Ljava/util/concurrent/Semaphore;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getScanningWasRequested$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningWasRequested:Z

    .line 2
    .line 3
    return p0
.end method

.method public static final synthetic access$startTimerToRestartScanIfNotResponsive(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startTimerToRestartScanIfNotResponsive(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeAllClientsThatShouldBeRemoved$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final cancelNoResponseCancellationJob$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "cancelNoResponseCancellationJob(): cancelling the noResponseCancellationJob"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$2$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close(): Cannot unregister Bluetooth state change receiver"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$3(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->nativeDestroy(Ltechnology/cariad/cat/genx/ClientManager;)V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    invoke-virtual {p0, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->setReference(J)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScanningForClients$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final deviceDisconnected$lambda$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "deviceDisconnected(): device = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final deviceDisconnected$lambda$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/genx/ClientManagerDelegate;->clientDidBecameUnreachable(Ltechnology/cariad/cat/genx/Client;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0
.end method

.method private static final deviceShouldBeRemovedAfterAdvertisementStopped$lambda$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "deviceShouldBeRemovedAfterAdvertisementStopped(): device = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final deviceShouldBeRemovedAfterAdvertisementStopped$lambda$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/genx/ClientManagerDelegate;->clientDidBecameUnreachable(Ltechnology/cariad/cat/genx/Client;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0
.end method

.method public static synthetic e0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$6()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceDisconnected$lambda$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->propagateClientManagerState$lambda$0$0(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic getScanCallback$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic h0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic j()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$4()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic k(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceDisconnected$lambda$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k0(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeClient$lambda$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->cancelNoResponseCancellationJob$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l0(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->reportCoreGenXScanError$lambda$0$0(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$5()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final propagateClientManagerState$lambda$0$0(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-interface {p0, v0, p1}, Ltechnology/cariad/cat/genx/ClientManagerDelegate;->clientManagerDidUpdatedState(ZLtechnology/cariad/cat/genx/TransportType;)V

    .line 10
    .line 11
    .line 12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public static synthetic q(Z)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$lambda$1(Z)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic q0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->close$lambda$3(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScan$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final removeAllClientsThatShouldBeRemoved$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "removeAllClientsThatShouldBeRemoved()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final removeAllClientsThatShouldBeRemoved$lambda$1$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ClientDelegate;->shouldClientBeRemovedAfterAdvertisementStopped()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceShouldBeRemovedAfterAdvertisementStopped$genx_release(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 15
    .line 16
    .line 17
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0
.end method

.method private static final removeClient$lambda$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "removeClient(): Removed client with identifier = "

    .line 2
    .line 3
    const-string v1, "."

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final reportCoreGenXScanError$lambda$0$0(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;-><init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-interface {p0, v0, p1}, Ltechnology/cariad/cat/genx/ClientManagerDelegate;->clientManagerDidEncounteredError(Ltechnology/cariad/cat/genx/GenXError;Ltechnology/cariad/cat/genx/TransportType;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private final startScan(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanFilter;",
            ">;",
            "Landroid/bluetooth/le/ScanSettings;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->mainScope:Lvy0/b0;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, p1, p2, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startScan$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x3

    .line 10
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method private static final startScanningForClients$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$1(Z)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "startScanningForClients(): forceStart = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

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

.method private static final startScanningForClients$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): Already scanning. -> Ignore"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): BLE not enabled. -> Error"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): \'android.permission.ACCESS_FINE_LOCATION\' required but missing. -> Error"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$5()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): \'android.permission.BLUETOOTH_SCAN\' required but missing. -> Error"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$6()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): \'android.permission.BLUETOOTH_CONNECT\' required but missing. -> Error"

    .line 2
    .line 3
    return-object v0
.end method

.method private final startTimerToRestartScanIfNotResponsive(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanFilter;",
            ">;",
            "Landroid/bluetooth/le/ScanSettings;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->mainScope:Lvy0/b0;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, p1, p2, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$startTimerToRestartScanIfNotResponsive$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x3

    .line 10
    invoke-static {v0, v2, v2, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->noResponseCancellationJob:Lvy0/i1;

    .line 15
    .line 16
    return-void
.end method

.method private static final stopScan$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScan()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopScanningForClients$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForClients()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopScanningForClients$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForClients(): BLE not enabled. -> Error"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopScanningForClients$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForClients(): \'android.permission.BLUETOOTH_SCAN\' required but missing. -> Error"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic x0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->_init_$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public final cancelNoResponseCancellationJob$genx_release()V
    .locals 9

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->noResponseCancellationJob:Lvy0/i1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-direct {v5, v2}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v7

    .line 18
    const-string v3, "getName(...)"

    .line 19
    .line 20
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v8

    .line 24
    const-string v3, "GenX"

    .line 25
    .line 26
    sget-object v4, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    iput-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->noResponseCancellationJob:Lvy0/i1;

    .line 39
    .line 40
    return-void
.end method

.method public close()V
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 2
    .line 3
    const/16 v0, 0x1c

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

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
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScan$genx_release()V

    .line 32
    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningWasRequested:Z

    .line 36
    .line 37
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 38
    .line 39
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanResultSemaphore:Ljava/util/concurrent/Semaphore;

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 50
    .line 51
    .line 52
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    const-string v1, "<get-values>(...)"

    .line 59
    .line 60
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    check-cast v0, Ljava/lang/Iterable;

    .line 64
    .line 65
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_0

    .line 74
    .line 75
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 80
    .line 81
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->close()V

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 88
    .line 89
    .line 90
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothStateReceiver:Landroid/content/BroadcastReceiver;

    .line 91
    .line 92
    if-eqz v0, :cond_1

    .line 93
    .line 94
    :try_start_0
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 95
    .line 96
    invoke-virtual {v1, v0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :catch_0
    move-exception v0

    .line 101
    move-object v12, v0

    .line 102
    new-instance v11, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 103
    .line 104
    const/16 v0, 0x1d

    .line 105
    .line 106
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 107
    .line 108
    .line 109
    new-instance v8, Lt51/j;

    .line 110
    .line 111
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v13

    .line 115
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v14

    .line 119
    const-string v9, "GenX"

    .line 120
    .line 121
    sget-object v10, Lt51/e;->a:Lt51/e;

    .line 122
    .line 123
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 127
    .line 128
    .line 129
    :cond_1
    :goto_1
    const/4 v0, 0x0

    .line 130
    iput-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothStateReceiver:Landroid/content/BroadcastReceiver;

    .line 131
    .line 132
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    if-eqz v1, :cond_2

    .line 137
    .line 138
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    .line 139
    .line 140
    .line 141
    :cond_2
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->setDelegate(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->cancelNoResponseCancellationJob$genx_release()V

    .line 145
    .line 146
    .line 147
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getReference()J

    .line 148
    .line 149
    .line 150
    move-result-wide v0

    .line 151
    const-wide/16 v2, 0x0

    .line 152
    .line 153
    cmp-long v0, v0, v2

    .line 154
    .line 155
    if-eqz v0, :cond_3

    .line 156
    .line 157
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/d;

    .line 162
    .line 163
    const/4 v2, 0x2

    .line 164
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/d;-><init>(Ljava/lang/Object;I)V

    .line 165
    .line 166
    .line 167
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 168
    .line 169
    .line 170
    :cond_3
    return-void
.end method

.method public final deviceDisconnected$genx_release(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 8

    .line 1
    const-string v0, "bluetoothClient"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 11
    .line 12
    const/4 v1, 0x7

    .line 13
    invoke-direct {v4, v1, v0}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lt51/j;

    .line 17
    .line 18
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    const-string v2, "getName(...)"

    .line 23
    .line 24
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    const-string v2, "GenX"

    .line 29
    .line 30
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 40
    .line 41
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 50
    .line 51
    if-eqz v0, :cond_0

    .line 52
    .line 53
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->close()V

    .line 54
    .line 55
    .line 56
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/s;

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    invoke-direct {v1, p0, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/s;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 64
    .line 65
    .line 66
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public final deviceShouldBeRemovedAfterAdvertisementStopped$genx_release(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 8

    .line 1
    const-string v0, "bluetoothClient"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 11
    .line 12
    const/4 v1, 0x6

    .line 13
    invoke-direct {v4, v1, v0}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lt51/j;

    .line 17
    .line 18
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    const-string v2, "getName(...)"

    .line 23
    .line 24
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    const-string v2, "GenX"

    .line 29
    .line 30
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 40
    .line 41
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 50
    .line 51
    if-eqz v0, :cond_0

    .line 52
    .line 53
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->close()V

    .line 54
    .line 55
    .line 56
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/s;

    .line 61
    .line 62
    const/4 v2, 0x2

    .line 63
    invoke-direct {v1, p0, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/s;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 64
    .line 65
    .line 66
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public final getBluetoothConnectRetryCount()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothConnectRetryCount:I

    .line 2
    .line 3
    return p0
.end method

.method public final getBluetoothConnectRetryDelay()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothConnectRetryDelay:I

    .line 2
    .line 3
    return p0
.end method

.method public final getBluetoothScanMode()Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothScanMode:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getClients$genx_release()Ljava/util/concurrent/ConcurrentHashMap;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/String;",
            "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->delegate:Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReference()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->reference:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getScanning$genx_release()Ljava/util/concurrent/atomic/AtomicBoolean;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTransportType()Ltechnology/cariad/cat/genx/TransportType;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->transportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isBleEnabled$genx_release()Lyy0/j1;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/j1;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->isBleEnabled:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEnabled()Z
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBleEnabled(Landroid/content/Context;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isScanningRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final logScanning$genx_release(Lay0/a;)V
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/Logging;->INSTANCE:Ltechnology/cariad/cat/genx/Logging;

    .line 7
    .line 8
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Logging;->isScanResponseLoggingEnabled$genx_release()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    new-instance v1, Lt51/j;

    .line 15
    .line 16
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string p0, "getName(...)"

    .line 21
    .line 22
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    const-string v2, "GenX"

    .line 27
    .line 28
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    move-object v4, p1

    .line 32
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    return-void
.end method

.method public final propagateClientManagerState$genx_release()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/b;

    .line 12
    .line 13
    const/4 v3, 0x4

    .line 14
    invoke-direct {v2, v0, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/b;-><init>(Ljava/io/Closeable;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public final removeAllClientsThatShouldBeRemoved$genx_release()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 2
    .line 3
    const/16 v0, 0x16

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

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
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_0

    .line 46
    .line 47
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/util/Map$Entry;

    .line 52
    .line 53
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    check-cast v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 58
    .line 59
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/s;

    .line 64
    .line 65
    invoke-direct {v3, v1, p0}, Ltechnology/cariad/cat/genx/bluetooth/s;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V

    .line 66
    .line 67
    .line 68
    invoke-interface {v2, v3}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    return-void
.end method

.method public removeClient(Ljava/lang/String;)V
    .locals 8

    .line 1
    const-string v0, "identifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->clients:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->close()V

    .line 17
    .line 18
    .line 19
    :cond_0
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/d;

    .line 20
    .line 21
    const/4 v0, 0x3

    .line 22
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/bluetooth/d;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    new-instance v1, Lt51/j;

    .line 26
    .line 27
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    const-string p0, "getName(...)"

    .line 32
    .line 33
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v7

    .line 37
    const-string v2, "GenX"

    .line 38
    .line 39
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 40
    .line 41
    const/4 v5, 0x0

    .line 42
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public final reportCoreGenXScanError$genx_release(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "message"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Lal/i;

    .line 22
    .line 23
    invoke-direct {v2, v0, p1, p2, p0}, Lal/i;-><init>(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public setDelegate(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->delegate:Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    return-void
.end method

.method public setReference(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->reference:J

    .line 2
    .line 3
    return-void
.end method

.method public startScanningForClients()Ltechnology/cariad/cat/genx/GenXError;
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 2
    .line 3
    const/4 v0, 0x7

    .line 4
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

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
    sget-object v2, Lt51/d;->a:Lt51/d;

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
    const/4 v0, 0x0

    .line 31
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScanningForClients$genx_release(Z)Ltechnology/cariad/cat/genx/GenXError;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public final startScanningForClients$genx_release(Z)Ltechnology/cariad/cat/genx/GenXError;
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->acquireUninterruptibly()V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lfw0/n;

    .line 7
    .line 8
    const/16 v0, 0x9

    .line 9
    .line 10
    invoke-direct {v4, v0, p1}, Lfw0/n;-><init>(IZ)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lt51/j;

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v0, "getName(...)"

    .line 20
    .line 21
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    const-string v2, "GenX"

    .line 26
    .line 27
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    const/4 v1, 0x1

    .line 37
    iput-boolean v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningWasRequested:Z

    .line 38
    .line 39
    sget-object v1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 40
    .line 41
    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBleEnabled(Landroid/content/Context;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->propagateClientManagerState$genx_release()V

    .line 48
    .line 49
    .line 50
    const/4 v3, 0x0

    .line 51
    if-nez p1, :cond_0

    .line 52
    .line 53
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-eqz p1, :cond_0

    .line 60
    .line 61
    new-instance v7, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 62
    .line 63
    const/16 p1, 0x17

    .line 64
    .line 65
    invoke-direct {v7, p1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 66
    .line 67
    .line 68
    new-instance v4, Lt51/j;

    .line 69
    .line 70
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v9

    .line 74
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v10

    .line 78
    const-string v5, "GenX"

    .line 79
    .line 80
    sget-object v6, Lt51/d;->a:Lt51/d;

    .line 81
    .line 82
    const/4 v8, 0x0

    .line 83
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 90
    .line 91
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 92
    .line 93
    .line 94
    return-object v3

    .line 95
    :cond_0
    const-string p1, "GenX"

    .line 96
    .line 97
    if-nez v2, :cond_1

    .line 98
    .line 99
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 100
    .line 101
    const/16 v1, 0x18

    .line 102
    .line 103
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-static {p0, p1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 107
    .line 108
    .line 109
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 110
    .line 111
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 112
    .line 113
    .line 114
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 115
    .line 116
    sget-object p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$Disabled;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$Disabled;

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 119
    .line 120
    .line 121
    return-object p0

    .line 122
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 123
    .line 124
    invoke-virtual {v1, v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isFineLocationPermissionRequiredAndGranted(Landroid/content/Context;)Z

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    if-nez v0, :cond_2

    .line 129
    .line 130
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 131
    .line 132
    const/16 v1, 0x19

    .line 133
    .line 134
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 135
    .line 136
    .line 137
    invoke-static {p0, p1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 138
    .line 139
    .line 140
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 143
    .line 144
    .line 145
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 146
    .line 147
    sget-object p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$LocationPermissionRequiredButMissing;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$LocationPermissionRequiredButMissing;

    .line 148
    .line 149
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 150
    .line 151
    .line 152
    return-object p0

    .line 153
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 154
    .line 155
    invoke-virtual {v1, v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBluetoothScanPermissionRequiredAndGranted(Landroid/content/Context;)Z

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    if-nez v0, :cond_3

    .line 160
    .line 161
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 162
    .line 163
    const/16 v1, 0x1a

    .line 164
    .line 165
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 166
    .line 167
    .line 168
    invoke-static {p0, p1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 169
    .line 170
    .line 171
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 172
    .line 173
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 174
    .line 175
    .line 176
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 177
    .line 178
    sget-object p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothScanPermissionRequiredButMissing;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothScanPermissionRequiredButMissing;

    .line 179
    .line 180
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 181
    .line 182
    .line 183
    return-object p0

    .line 184
    :cond_3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 185
    .line 186
    invoke-virtual {v1, v0}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBluetoothConnectPermissionRequiredAndGranted(Landroid/content/Context;)Z

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    if-nez v0, :cond_4

    .line 191
    .line 192
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 193
    .line 194
    const/16 v1, 0x1b

    .line 195
    .line 196
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 197
    .line 198
    .line 199
    invoke-static {p0, p1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 200
    .line 201
    .line 202
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 203
    .line 204
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 205
    .line 206
    .line 207
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 208
    .line 209
    sget-object p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothConnectPermissionRequiredButMissing;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothConnectPermissionRequiredButMissing;

    .line 210
    .line 211
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 212
    .line 213
    .line 214
    return-object p0

    .line 215
    :cond_4
    new-instance p1, Landroid/bluetooth/le/ScanFilter$Builder;

    .line 216
    .line 217
    invoke-direct {p1}, Landroid/bluetooth/le/ScanFilter$Builder;-><init>()V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getOuterAntennaServiceUUID$genx_release()Landroid/os/ParcelUuid;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-virtual {p1, v0}, Landroid/bluetooth/le/ScanFilter$Builder;->setServiceUuid(Landroid/os/ParcelUuid;)Landroid/bluetooth/le/ScanFilter$Builder;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    invoke-virtual {p1}, Landroid/bluetooth/le/ScanFilter$Builder;->build()Landroid/bluetooth/le/ScanFilter;

    .line 229
    .line 230
    .line 231
    move-result-object p1

    .line 232
    new-instance v0, Landroid/bluetooth/le/ScanFilter$Builder;

    .line 233
    .line 234
    invoke-direct {v0}, Landroid/bluetooth/le/ScanFilter$Builder;-><init>()V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->getInnerAntennaServiceUUID$genx_release()Landroid/os/ParcelUuid;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    invoke-virtual {v0, v1}, Landroid/bluetooth/le/ScanFilter$Builder;->setServiceUuid(Landroid/os/ParcelUuid;)Landroid/bluetooth/le/ScanFilter$Builder;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanFilter$Builder;->build()Landroid/bluetooth/le/ScanFilter;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    new-instance v1, Landroid/bluetooth/le/ScanSettings$Builder;

    .line 250
    .line 251
    invoke-direct {v1}, Landroid/bluetooth/le/ScanSettings$Builder;-><init>()V

    .line 252
    .line 253
    .line 254
    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->bluetoothScanMode:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 255
    .line 256
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->getValue()I

    .line 257
    .line 258
    .line 259
    move-result v2

    .line 260
    invoke-virtual {v1, v2}, Landroid/bluetooth/le/ScanSettings$Builder;->setScanMode(I)Landroid/bluetooth/le/ScanSettings$Builder;

    .line 261
    .line 262
    .line 263
    move-result-object v1

    .line 264
    invoke-virtual {v1}, Landroid/bluetooth/le/ScanSettings$Builder;->build()Landroid/bluetooth/le/ScanSettings;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    filled-new-array {p1, v0}, [Landroid/bluetooth/le/ScanFilter;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 273
    .line 274
    .line 275
    move-result-object p1

    .line 276
    invoke-direct {p0, p1, v1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->startScan(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;)V

    .line 277
    .line 278
    .line 279
    return-object v3
.end method

.method public final stopScan$genx_release()V
    .locals 7
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

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
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->cancelNoResponseCancellationJob$genx_release()V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->mainScope:Lvy0/b0;

    .line 34
    .line 35
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$stopScan$2;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Lkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public stopScanningForClients()Ltechnology/cariad/cat/genx/GenXError;
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

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
    sget-object v2, Lt51/d;->a:Lt51/d;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanResultSemaphore:Ljava/util/concurrent/Semaphore;

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/util/concurrent/Semaphore;->acquireUninterruptibly()V

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningWasRequested:Z

    .line 42
    .line 43
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeAllClientsThatShouldBeRemoved$genx_release()V

    .line 44
    .line 45
    .line 46
    sget-object v1, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;

    .line 47
    .line 48
    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 49
    .line 50
    invoke-virtual {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBleEnabled(Landroid/content/Context;)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    const-string v3, "GenX"

    .line 55
    .line 56
    if-nez v2, :cond_0

    .line 57
    .line 58
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 59
    .line 60
    const/4 v2, 0x3

    .line 61
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 62
    .line 63
    .line 64
    invoke-static {p0, v3, v4, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->propagateClientManagerState$genx_release()V

    .line 68
    .line 69
    .line 70
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 71
    .line 72
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 76
    .line 77
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 78
    .line 79
    .line 80
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 81
    .line 82
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$Disabled;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$Disabled;

    .line 83
    .line 84
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 85
    .line 86
    .line 87
    return-object p0

    .line 88
    :cond_0
    iget-object v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->context:Landroid/content/Context;

    .line 89
    .line 90
    invoke-virtual {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth;->isBluetoothScanPermissionRequiredAndGranted(Landroid/content/Context;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_1

    .line 95
    .line 96
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/t;

    .line 97
    .line 98
    const/4 v2, 0x4

    .line 99
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/bluetooth/t;-><init>(I)V

    .line 100
    .line 101
    .line 102
    invoke-static {p0, v3, v4, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 103
    .line 104
    .line 105
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanning:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 106
    .line 107
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 108
    .line 109
    .line 110
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->scanningSemaphore:Ljava/util/concurrent/Semaphore;

    .line 111
    .line 112
    invoke-virtual {p0}, Ljava/util/concurrent/Semaphore;->release()V

    .line 113
    .line 114
    .line 115
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 116
    .line 117
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothScanPermissionRequiredButMissing;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothScanPermissionRequiredButMissing;

    .line 118
    .line 119
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 120
    .line 121
    .line 122
    return-object p0

    .line 123
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->stopScan$genx_release()V

    .line 124
    .line 125
    .line 126
    return-object v4
.end method
