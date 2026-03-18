.class public final Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\\\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u0000 ?2\u00020\u0001:\u0001?B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0019\u0010\u0008\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00020\u0006H\u0002\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\r\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\r\u0010\r\u001a\u00020\n\u00a2\u0006\u0004\u0008\r\u0010\u000cJ\r\u0010\u000e\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000e\u0010\u000cJ\u000f\u0010\u000f\u001a\u00020\nH\u0007\u00a2\u0006\u0004\u0008\u000f\u0010\u000cJ\u000f\u0010\u0010\u001a\u00020\nH\u0007\u00a2\u0006\u0004\u0008\u0010\u0010\u000cJ\u000f\u0010\u0011\u001a\u00020\nH\u0007\u00a2\u0006\u0004\u0008\u0011\u0010\u000cJ\u001f\u0010\u0015\u001a\u00020\n2\u000e\u0010\u0014\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00130\u0012H\u0007\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0015\u0010\u0017\u001a\u00020\n2\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0017\u0010\u0005J\u0017\u0010\u0018\u001a\u00020\n2\u0006\u0010\u0003\u001a\u00020\u0002H\u0007\u00a2\u0006\u0004\u0008\u0018\u0010\u0005R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0019\u001a\u0004\u0008\u001a\u0010\u001bR\u0016\u0010\u001d\u001a\u00020\u001c8\u0002@\u0002X\u0082.\u00a2\u0006\u0006\n\u0004\u0008\u001d\u0010\u001eR\u0016\u0010 \u001a\u00020\u001f8\u0002@\u0002X\u0082.\u00a2\u0006\u0006\n\u0004\u0008 \u0010!R\u0016\u0010#\u001a\u00020\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008#\u0010$R\u0016\u0010%\u001a\u00020\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008%\u0010$R\u0016\u0010&\u001a\u00020\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008&\u0010$R\u0016\u0010(\u001a\u00020\'8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008(\u0010)R\"\u0010+\u001a\u00020*8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008+\u0010,\u001a\u0004\u0008-\u0010.\"\u0004\u0008/\u00100R\"\u00101\u001a\u00020*8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u00081\u0010,\u001a\u0004\u00082\u0010.\"\u0004\u00083\u00100R\"\u00104\u001a\u00020\"8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u00084\u0010$\u001a\u0004\u00085\u00106\"\u0004\u00087\u00108R\u001f\u0010;\u001a\n :*\u0004\u0018\u000109098\u0006\u00a2\u0006\u000c\n\u0004\u0008;\u0010<\u001a\u0004\u0008=\u0010>\u00a8\u0006@"
    }
    d2 = {
        "Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;",
        "",
        "Landroid/content/Context;",
        "context",
        "<init>",
        "(Landroid/content/Context;)V",
        "",
        "key",
        "getManifestMetadataValue",
        "(Ljava/lang/String;)Ljava/lang/String;",
        "Llx0/b0;",
        "ensureInitialized",
        "()V",
        "reinitialize",
        "applySettings",
        "start",
        "stop",
        "restartBackgroundScan",
        "Ljava/util/ArrayList;",
        "Landroid/bluetooth/le/ScanResult;",
        "scanResults",
        "processScanResults",
        "(Ljava/util/ArrayList;)V",
        "performPeriodicProcessing",
        "runBackupScan",
        "Landroid/content/Context;",
        "getContext",
        "()Landroid/content/Context;",
        "Lorg/altbeacon/beacon/service/ScanHelper;",
        "scanHelper",
        "Lorg/altbeacon/beacon/service/ScanHelper;",
        "Lorg/altbeacon/beacon/service/ScanState;",
        "scanState",
        "Lorg/altbeacon/beacon/service/ScanState;",
        "",
        "initialized",
        "Z",
        "started",
        "longScanForcingEnabled",
        "",
        "lastCycleEnd",
        "J",
        "",
        "strategyFailureDetectionCount",
        "I",
        "getStrategyFailureDetectionCount",
        "()I",
        "setStrategyFailureDetectionCount",
        "(I)V",
        "lastStrategyFailureDetectionCount",
        "getLastStrategyFailureDetectionCount",
        "setLastStrategyFailureDetectionCount",
        "disableOnFailure",
        "getDisableOnFailure",
        "()Z",
        "setDisableOnFailure",
        "(Z)V",
        "Ljava/util/concurrent/ExecutorService;",
        "kotlin.jvm.PlatformType",
        "executor",
        "Ljava/util/concurrent/ExecutorService;",
        "getExecutor",
        "()Ljava/util/concurrent/ExecutorService;",
        "Companion",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$Companion;

.field private static final TAG:Ljava/lang/String;


# instance fields
.field private final context:Landroid/content/Context;

.field private disableOnFailure:Z

.field private final executor:Ljava/util/concurrent/ExecutorService;

.field private initialized:Z

.field private lastCycleEnd:J

.field private lastStrategyFailureDetectionCount:I

.field private longScanForcingEnabled:Z

.field private scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

.field private scanState:Lorg/altbeacon/beacon/service/ScanState;

.field private started:Z

.field private strategyFailureDetectionCount:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->Companion:Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$Companion;

    .line 8
    .line 9
    const-string v0, "IntentScanCoord"

    .line 10
    .line 11
    sput-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-static {p1}, Ljava/util/concurrent/Executors;->newFixedThreadPool(I)Ljava/util/concurrent/ExecutorService;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->executor:Ljava/util/concurrent/ExecutorService;

    .line 17
    .line 18
    return-void
.end method

.method public static synthetic a(Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->runBackupScan$lambda$0(Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$getScanHelper$p(Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;)Lorg/altbeacon/beacon/service/ScanHelper;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getTAG$cp()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method private final getManifestMetadataValue(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Landroid/content/ComponentName;

    .line 8
    .line 9
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 10
    .line 11
    const-class v2, Lorg/altbeacon/beacon/service/BeaconService;

    .line 12
    .line 13
    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 14
    .line 15
    .line 16
    const/16 p0, 0x80

    .line 17
    .line 18
    invoke-virtual {v0, v1, p0}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string v0, "context.getPackageManage\u2026T_META_DATA\n            )"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Landroid/content/pm/PackageItemInfo;->metaData:Landroid/os/Bundle;

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    return-object p0

    .line 40
    :catch_0
    :cond_0
    const/4 p0, 0x0

    .line 41
    return-object p0
.end method

.method private static final runBackupScan$lambda$0(Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;Landroid/content/Context;)V
    .locals 10

    .line 1
    const-string v0, "this$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "$context"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-wide/16 v0, 0x1388

    .line 12
    .line 13
    :try_start_0
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    :catch_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 17
    .line 18
    if-eqz v0, :cond_7

    .line 19
    .line 20
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->anyBeaconsDetectedThisCycle()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    sget-object p1, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 28
    .line 29
    const-string v0, "We have belatedly detected beacons with the intent scan.  No need to do a backup scan."

    .line 30
    .line 31
    new-array v2, v1, [Ljava/lang/Object;

    .line 32
    .line 33
    invoke-static {p1, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iput v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 37
    .line 38
    iput v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastStrategyFailureDetectionCount:I

    .line 39
    .line 40
    goto/16 :goto_3

    .line 41
    .line 42
    :cond_0
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 43
    .line 44
    const-string v2, "Starting backup scan"

    .line 45
    .line 46
    new-array v3, v1, [Ljava/lang/Object;

    .line 47
    .line 48
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    const-string v2, "bluetooth"

    .line 52
    .line 53
    invoke-virtual {p1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    const-string v3, "null cannot be cast to non-null type android.bluetooth.BluetoothManager"

    .line 58
    .line 59
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    check-cast v2, Landroid/bluetooth/BluetoothManager;

    .line 63
    .line 64
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothManager;->getAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    new-instance v3, Lkotlin/jvm/internal/b0;

    .line 69
    .line 70
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 71
    .line 72
    .line 73
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 74
    .line 75
    .line 76
    move-result-wide v4

    .line 77
    if-eqz v2, :cond_5

    .line 78
    .line 79
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothAdapter;->getBluetoothLeScanner()Landroid/bluetooth/le/BluetoothLeScanner;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    if-eqz v2, :cond_4

    .line 84
    .line 85
    new-instance v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$runBackupScan$1$callback$1;

    .line 86
    .line 87
    invoke-direct {v0, p0, v3, v2}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator$runBackupScan$1$callback$1;-><init>(Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;Lkotlin/jvm/internal/b0;Landroid/bluetooth/le/BluetoothLeScanner;)V

    .line 88
    .line 89
    .line 90
    :try_start_1
    invoke-virtual {v2, v0}, Landroid/bluetooth/le/BluetoothLeScanner;->startScan(Landroid/bluetooth/le/ScanCallback;)V

    .line 91
    .line 92
    .line 93
    :cond_1
    iget-boolean v6, v3, Lkotlin/jvm/internal/b0;->d:Z

    .line 94
    .line 95
    if-nez v6, :cond_2

    .line 96
    .line 97
    sget-object v6, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 98
    .line 99
    const-string v7, "Waiting for beacon detection..."

    .line 100
    .line 101
    new-array v8, v1, [Ljava/lang/Object;

    .line 102
    .line 103
    invoke-static {v6, v7, v8}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_1

    .line 104
    .line 105
    .line 106
    const-wide/16 v6, 0x3e8

    .line 107
    .line 108
    :try_start_2
    invoke-static {v6, v7}, Ljava/lang/Thread;->sleep(J)V
    :try_end_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/IllegalStateException; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/lang/NullPointerException; {:try_start_2 .. :try_end_2} :catch_1

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :catch_1
    move-exception v0

    .line 113
    goto :goto_1

    .line 114
    :catch_2
    :goto_0
    :try_start_3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 115
    .line 116
    .line 117
    move-result-wide v6

    .line 118
    sub-long/2addr v6, v4

    .line 119
    const-wide/16 v8, 0x7530

    .line 120
    .line 121
    cmp-long v6, v6, v8

    .line 122
    .line 123
    if-lez v6, :cond_1

    .line 124
    .line 125
    sget-object v4, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 126
    .line 127
    const-string v5, "Timeout running backup scan to look for beacons"

    .line 128
    .line 129
    new-array v6, v1, [Ljava/lang/Object;

    .line 130
    .line 131
    invoke-static {v4, v5, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    :cond_2
    invoke-virtual {v2, v0}, Landroid/bluetooth/le/BluetoothLeScanner;->stopScan(Landroid/bluetooth/le/ScanCallback;)V

    .line 135
    .line 136
    .line 137
    iget-boolean v0, v3, Lkotlin/jvm/internal/b0;->d:Z

    .line 138
    .line 139
    if-eqz v0, :cond_5

    .line 140
    .line 141
    iget v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 142
    .line 143
    iget v2, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastStrategyFailureDetectionCount:I

    .line 144
    .line 145
    if-ne v0, v2, :cond_3

    .line 146
    .line 147
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 148
    .line 149
    const-string v2, "We have detected a beacon with the backup scan without a filter.  We never detected one with the intent scan with a filter.  This technique will not work."

    .line 150
    .line 151
    new-array v3, v1, [Ljava/lang/Object;

    .line 152
    .line 153
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    :cond_3
    iget v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 157
    .line 158
    iput v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastStrategyFailureDetectionCount:I

    .line 159
    .line 160
    add-int/lit8 v0, v0, 0x1

    .line 161
    .line 162
    iput v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I
    :try_end_3
    .catch Ljava/lang/IllegalStateException; {:try_start_3 .. :try_end_3} :catch_3
    .catch Ljava/lang/NullPointerException; {:try_start_3 .. :try_end_3} :catch_1

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :goto_1
    sget-object v2, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 166
    .line 167
    const-string v3, "NullPointerException. Cannot run backup scan"

    .line 168
    .line 169
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    invoke-static {v2, v3, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    goto :goto_2

    .line 177
    :catch_3
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 178
    .line 179
    const-string v2, "Bluetooth is off.  Cannot run backup scan"

    .line 180
    .line 181
    new-array v3, v1, [Ljava/lang/Object;

    .line 182
    .line 183
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_4
    const-string v2, "Cannot get scanner"

    .line 188
    .line 189
    new-array v3, v1, [Ljava/lang/Object;

    .line 190
    .line 191
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    :cond_5
    :goto_2
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 195
    .line 196
    const-string v2, "backup scan complete"

    .line 197
    .line 198
    new-array v1, v1, [Ljava/lang/Object;

    .line 199
    .line 200
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->disableOnFailure:Z

    .line 204
    .line 205
    if-eqz v0, :cond_6

    .line 206
    .line 207
    iget v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 208
    .line 209
    if-lez v0, :cond_6

    .line 210
    .line 211
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->handleStategyFailover()V

    .line 216
    .line 217
    .line 218
    :cond_6
    new-instance p1, Ljava/util/ArrayList;

    .line 219
    .line 220
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->processScanResults(Ljava/util/ArrayList;)V

    .line 224
    .line 225
    .line 226
    :goto_3
    return-void

    .line 227
    :cond_7
    const-string p0, "scanHelper"

    .line 228
    .line 229
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    const/4 p0, 0x0

    .line 233
    throw p0
.end method


# virtual methods
.method public final applySettings()V
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 6
    .line 7
    invoke-static {v1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {v0, v1}, Lorg/altbeacon/beacon/service/ScanState;->applyChanges(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->reinitialize()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->restartBackgroundScan()V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    const-string p0, "scanState"

    .line 22
    .line 23
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    throw p0
.end method

.method public final ensureInitialized()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->initialized:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->initialized:Z

    .line 7
    .line 8
    new-instance v0, Lorg/altbeacon/beacon/service/ScanHelper;

    .line 9
    .line 10
    iget-object v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/service/ScanHelper;-><init>(Landroid/content/Context;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 16
    .line 17
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->reinitialize()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public final getContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDisableOnFailure()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->disableOnFailure:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getExecutor()Ljava/util/concurrent/ExecutorService;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->executor:Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLastStrategyFailureDetectionCount()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastStrategyFailureDetectionCount:I

    .line 2
    .line 3
    return p0
.end method

.method public final getStrategyFailureDetectionCount()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 2
    .line 3
    return p0
.end method

.method public final performPeriodicProcessing(Landroid/content/Context;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->processScanResults(Ljava/util/ArrayList;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->runBackupScan(Landroid/content/Context;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final processScanResults(Ljava/util/ArrayList;)V
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Landroid/bluetooth/le/ScanResult;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "scanResults"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->ensureInitialized()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const-string v1, "scanHelper"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    if-eqz v0, :cond_3

    .line 21
    .line 22
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Landroid/bluetooth/le/ScanResult;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    iget-object v3, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 31
    .line 32
    if-eqz v3, :cond_2

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanResult;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanResult;->getRssi()I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanResult;->getScanRecord()Landroid/bluetooth/le/ScanRecord;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    invoke-virtual {v1}, Landroid/bluetooth/le/ScanRecord;->getBytes()[B

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    :cond_1
    move-object v6, v2

    .line 53
    invoke-virtual {v0}, Landroid/bluetooth/le/ScanResult;->getTimestampNanos()J

    .line 54
    .line 55
    .line 56
    move-result-wide v0

    .line 57
    const/16 v2, 0x3e8

    .line 58
    .line 59
    int-to-long v7, v2

    .line 60
    div-long v7, v0, v7

    .line 61
    .line 62
    invoke-virtual/range {v3 .. v8}, Lorg/altbeacon/beacon/service/ScanHelper;->processScanResult(Landroid/bluetooth/BluetoothDevice;I[BJ)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw v2

    .line 70
    :cond_3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 71
    .line 72
    .line 73
    move-result-wide v3

    .line 74
    iget-object p1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 75
    .line 76
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    const-string v0, "getInstanceForApplication(context)"

    .line 81
    .line 82
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getForegroundScanPeriod()J

    .line 86
    .line 87
    .line 88
    move-result-wide v5

    .line 89
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBackgroundMode()Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_4

    .line 94
    .line 95
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBackgroundScanPeriod()J

    .line 96
    .line 97
    .line 98
    move-result-wide v5

    .line 99
    :cond_4
    iget-wide v7, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastCycleEnd:J

    .line 100
    .line 101
    sub-long v7, v3, v7

    .line 102
    .line 103
    cmp-long p1, v7, v5

    .line 104
    .line 105
    if-lez p1, :cond_6

    .line 106
    .line 107
    sget-object p1, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 108
    .line 109
    const/4 v0, 0x0

    .line 110
    new-array v0, v0, [Ljava/lang/Object;

    .line 111
    .line 112
    const-string v5, "End of scan cycle"

    .line 113
    .line 114
    invoke-static {p1, v5, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    iput-wide v3, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastCycleEnd:J

    .line 118
    .line 119
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 120
    .line 121
    if-eqz p0, :cond_5

    .line 122
    .line 123
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledLeScanCallback()Lorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-interface {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;->onCycleEnd()V

    .line 128
    .line 129
    .line 130
    return-void

    .line 131
    :cond_5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw v2

    .line 135
    :cond_6
    return-void
.end method

.method public final reinitialize()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->initialized:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->ensureInitialized()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 10
    .line 11
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanState;->restore(Landroid/content/Context;)Lorg/altbeacon/beacon/service/ScanState;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    new-instance v0, Lorg/altbeacon/beacon/service/ScanState;

    .line 18
    .line 19
    iget-object v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/service/ScanState;-><init>(Landroid/content/Context;)V

    .line 22
    .line 23
    .line 24
    :cond_1
    iput-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 25
    .line 26
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 27
    .line 28
    .line 29
    move-result-wide v1

    .line 30
    invoke-virtual {v0, v1, v2}, Lorg/altbeacon/beacon/service/ScanState;->setLastScanStartTimeMillis(J)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 34
    .line 35
    const-string v1, "scanHelper"

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    if-eqz v0, :cond_b

    .line 39
    .line 40
    iget-object v3, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 41
    .line 42
    const-string v4, "scanState"

    .line 43
    .line 44
    if-eqz v3, :cond_a

    .line 45
    .line 46
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/ScanState;->getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-virtual {v0, v3}, Lorg/altbeacon/beacon/service/ScanHelper;->setMonitoringStatus(Lorg/altbeacon/beacon/service/MonitoringStatus;)V

    .line 51
    .line 52
    .line 53
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 54
    .line 55
    if-eqz v0, :cond_9

    .line 56
    .line 57
    iget-object v3, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 58
    .line 59
    if-eqz v3, :cond_8

    .line 60
    .line 61
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/ScanState;->getRangedRegionState()Ljava/util/Map;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-virtual {v0, v3}, Lorg/altbeacon/beacon/service/ScanHelper;->setRangedRegionState(Ljava/util/Map;)V

    .line 66
    .line 67
    .line 68
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 69
    .line 70
    if-eqz v0, :cond_7

    .line 71
    .line 72
    iget-object v3, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 73
    .line 74
    if-eqz v3, :cond_6

    .line 75
    .line 76
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/ScanState;->getBeaconParsers()Ljava/util/Set;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-virtual {v0, v3}, Lorg/altbeacon/beacon/service/ScanHelper;->setBeaconParsers(Ljava/util/Set;)V

    .line 81
    .line 82
    .line 83
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 84
    .line 85
    if-eqz v0, :cond_5

    .line 86
    .line 87
    iget-object v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 88
    .line 89
    if-eqz v1, :cond_4

    .line 90
    .line 91
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/ScanState;->getExtraBeaconDataTracker()Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-virtual {v0, v1}, Lorg/altbeacon/beacon/service/ScanHelper;->setExtraDataBeaconTracker(Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;)V

    .line 96
    .line 97
    .line 98
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 99
    .line 100
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getActiveSettings()Lorg/altbeacon/beacon/AppliedSettings;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-virtual {v0}, Lorg/altbeacon/beacon/AppliedSettings;->getLongScanForcingEnabled()Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    const-string v1, "longScanForcingEnabled"

    .line 113
    .line 114
    invoke-direct {p0, v1}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->getManifestMetadataValue(Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    const/4 v2, 0x0

    .line 119
    const-string v3, "BeaconService"

    .line 120
    .line 121
    if-eqz v1, :cond_2

    .line 122
    .line 123
    const-string v4, "true"

    .line 124
    .line 125
    invoke-virtual {v1, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    if-eqz v1, :cond_2

    .line 130
    .line 131
    const-string v0, "Setting longScanForcingEnabled in the AndroidManifest.xml is deprecated for AndoridBeaconLibrary.  Please set this value using the Settings API."

    .line 132
    .line 133
    new-array v1, v2, [Ljava/lang/Object;

    .line 134
    .line 135
    invoke-static {v3, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    const/4 v0, 0x1

    .line 139
    :cond_2
    if-eqz v0, :cond_3

    .line 140
    .line 141
    const-string v1, "longScanForcingEnabled to keep scans going on Android N for > 30 minutes"

    .line 142
    .line 143
    new-array v2, v2, [Ljava/lang/Object;

    .line 144
    .line 145
    invoke-static {v3, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_3
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->longScanForcingEnabled:Z

    .line 149
    .line 150
    return-void

    .line 151
    :cond_4
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v2

    .line 155
    :cond_5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw v2

    .line 159
    :cond_6
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw v2

    .line 163
    :cond_7
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw v2

    .line 167
    :cond_8
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw v2

    .line 171
    :cond_9
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    throw v2

    .line 175
    :cond_a
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    throw v2

    .line 179
    :cond_b
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    throw v2
.end method

.method public final restartBackgroundScan()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->ensureInitialized()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    new-array v1, v1, [Ljava/lang/Object;

    .line 8
    .line 9
    const-string v2, "restarting background scan"

    .line 10
    .line 11
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 15
    .line 16
    const-string v1, "scanHelper"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->stopAndroidOBackgroundScan()V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 29
    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBeaconParsers()Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/service/ScanHelper;->startAndroidOBackgroundScan(Ljava/util/Set;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    const-string p0, "scanState"

    .line 41
    .line 42
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v2

    .line 46
    :cond_1
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v2

    .line 50
    :cond_2
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v2
.end method

.method public final runBackupScan(Landroid/content/Context;)V
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->started:Z

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 12
    .line 13
    const-string p1, "Not doing backup scan because we are not started"

    .line 14
    .line 15
    new-array v0, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->anyBeaconsDetectedThisCycle()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    sget-object p1, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 32
    .line 33
    const-string v0, "We have detected beacons with the intent scan.  No need to do a backup scan."

    .line 34
    .line 35
    new-array v2, v1, [Ljava/lang/Object;

    .line 36
    .line 37
    invoke-static {p1, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iput v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 41
    .line 42
    iput v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastStrategyFailureDetectionCount:I

    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 46
    .line 47
    const-string v2, "Starting background thread to do backup scan"

    .line 48
    .line 49
    new-array v1, v1, [Ljava/lang/Object;

    .line 50
    .line 51
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->executor:Ljava/util/concurrent/ExecutorService;

    .line 55
    .line 56
    new-instance v1, Lno/nordicsemi/android/ble/o0;

    .line 57
    .line 58
    const/4 v2, 0x1

    .line 59
    invoke-direct {v1, v2, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_2
    const-string p0, "scanHelper"

    .line 67
    .line 68
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const/4 p0, 0x0

    .line 72
    throw p0
.end method

.method public final setDisableOnFailure(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->disableOnFailure:Z

    .line 2
    .line 3
    return-void
.end method

.method public final setLastStrategyFailureDetectionCount(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastStrategyFailureDetectionCount:I

    .line 2
    .line 3
    return-void
.end method

.method public final setStrategyFailureDetectionCount(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->strategyFailureDetectionCount:I

    .line 2
    .line 3
    return-void
.end method

.method public final start()V
    .locals 9

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->started:Z

    .line 3
    .line 4
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->ensureInitialized()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 8
    .line 9
    invoke-static {v1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "getInstanceForApplication(context)"

    .line 14
    .line 15
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v2, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 19
    .line 20
    const-string v3, "scanHelper"

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    if-eqz v2, :cond_9

    .line 24
    .line 25
    new-instance v5, Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 26
    .line 27
    invoke-direct {v5}, Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, v5}, Lorg/altbeacon/beacon/service/ScanHelper;->setExtraDataBeaconTracker(Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, v0}, Lorg/altbeacon/beacon/BeaconManager;->setScannerInSameProcess(Z)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 37
    .line 38
    if-eqz v0, :cond_8

    .line 39
    .line 40
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->reloadParsers()V

    .line 41
    .line 42
    .line 43
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 44
    .line 45
    const-string v2, "starting background scan"

    .line 46
    .line 47
    const/4 v5, 0x0

    .line 48
    new-array v6, v5, [Ljava/lang/Object;

    .line 49
    .line 50
    invoke-static {v0, v2, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance v0, Ljava/util/HashSet;

    .line 54
    .line 55
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 56
    .line 57
    .line 58
    new-instance v2, Ljava/util/HashSet;

    .line 59
    .line 60
    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v1}, Lorg/altbeacon/beacon/BeaconManager;->getRangedRegions()Ljava/util/Collection;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    invoke-interface {v6}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    if-eqz v7, :cond_1

    .line 76
    .line 77
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    check-cast v7, Lorg/altbeacon/beacon/Region;

    .line 82
    .line 83
    invoke-virtual {v7}, Lorg/altbeacon/beacon/Region;->getIdentifiers()Ljava/util/List;

    .line 84
    .line 85
    .line 86
    move-result-object v8

    .line 87
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 88
    .line 89
    .line 90
    move-result v8

    .line 91
    if-nez v8, :cond_0

    .line 92
    .line 93
    invoke-virtual {v2, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_0
    invoke-virtual {v0, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_1
    invoke-virtual {v1}, Lorg/altbeacon/beacon/BeaconManager;->getMonitoredRegions()Ljava/util/Collection;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 110
    .line 111
    .line 112
    move-result v6

    .line 113
    if-eqz v6, :cond_3

    .line 114
    .line 115
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    check-cast v6, Lorg/altbeacon/beacon/Region;

    .line 120
    .line 121
    invoke-virtual {v6}, Lorg/altbeacon/beacon/Region;->getIdentifiers()Ljava/util/List;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    if-nez v7, :cond_2

    .line 130
    .line 131
    invoke-virtual {v2, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_2
    invoke-virtual {v0, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_3
    invoke-virtual {v2}, Ljava/util/HashSet;->size()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    if-lez v1, :cond_5

    .line 144
    .line 145
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-lez v1, :cond_4

    .line 150
    .line 151
    sget-object v1, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 152
    .line 153
    const-string v2, "Wildcard regions are being used for beacon ranging or monitoring.  The wildcard regions are ignored with intent scan strategy active."

    .line 154
    .line 155
    new-array v5, v5, [Ljava/lang/Object;

    .line 156
    .line 157
    invoke-static {v1, v2, v5}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_4
    move-object v0, v2

    .line 162
    :cond_5
    :goto_2
    iget-object v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 163
    .line 164
    if-eqz v1, :cond_7

    .line 165
    .line 166
    iget-object v2, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 167
    .line 168
    if-eqz v2, :cond_6

    .line 169
    .line 170
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanState;->getBeaconParsers()Ljava/util/Set;

    .line 171
    .line 172
    .line 173
    move-result-object v2

    .line 174
    new-instance v3, Ljava/util/ArrayList;

    .line 175
    .line 176
    invoke-direct {v3, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v1, v2, v3}, Lorg/altbeacon/beacon/service/ScanHelper;->startAndroidOBackgroundScan(Ljava/util/Set;Ljava/util/List;)V

    .line 180
    .line 181
    .line 182
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 183
    .line 184
    .line 185
    move-result-wide v0

    .line 186
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->lastCycleEnd:J

    .line 187
    .line 188
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    iget-object p0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 193
    .line 194
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->scheduleForIntentScanStrategy(Landroid/content/Context;)V

    .line 195
    .line 196
    .line 197
    return-void

    .line 198
    :cond_6
    const-string p0, "scanState"

    .line 199
    .line 200
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw v4

    .line 204
    :cond_7
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw v4

    .line 208
    :cond_8
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    throw v4

    .line 212
    :cond_9
    invoke-static {v3}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw v4
.end method

.method public final stop()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->ensureInitialized()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->TAG:Ljava/lang/String;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    new-array v2, v1, [Ljava/lang/Object;

    .line 8
    .line 9
    const-string v3, "stopping background scan"

    .line 10
    .line 11
    invoke-static {v0, v3, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->scanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->stopAndroidOBackgroundScan()V

    .line 19
    .line 20
    .line 21
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object v2, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->context:Landroid/content/Context;

    .line 26
    .line 27
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->cancelSchedule(Landroid/content/Context;)V

    .line 28
    .line 29
    .line 30
    iput-boolean v1, p0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->started:Z

    .line 31
    .line 32
    return-void

    .line 33
    :cond_0
    const-string p0, "scanHelper"

    .line 34
    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    throw p0
.end method
