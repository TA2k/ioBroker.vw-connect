.class public Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;
.super Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/TargetApi;
    value = 0x12
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String; = "CycledLeScannerForJellyBeanMr2"


# instance fields
.field private leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;


# direct methods
.method public constructor <init>(Landroid/content/Context;JJZLorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p8}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;-><init>(Landroid/content/Context;JJZLorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;)Landroid/bluetooth/BluetoothAdapter$LeScanCallback;
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->getLeScanCallback()Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private getLeScanCallback()Landroid/bluetooth/BluetoothAdapter$LeScanCallback;
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$4;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$4;-><init>(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 13
    .line 14
    return-object p0
.end method

.method private postStartLeScan()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->getBluetoothAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->getLeScanCallback()Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget-object v2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mScanHandler:Landroid/os/Handler;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-virtual {v2, v3}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object v2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mScanHandler:Landroid/os/Handler;

    .line 19
    .line 20
    new-instance v3, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$2;

    .line 21
    .line 22
    invoke-direct {v3, p0, v0, v1}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$2;-><init>(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;Landroid/bluetooth/BluetoothAdapter;Landroid/bluetooth/BluetoothAdapter$LeScanCallback;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method private postStopLeScan()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->getBluetoothAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->getLeScanCallback()Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget-object v2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mScanHandler:Landroid/os/Handler;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-virtual {v2, v3}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object v2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mScanHandler:Landroid/os/Handler;

    .line 19
    .line 20
    new-instance v3, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;

    .line 21
    .line 22
    invoke-direct {v3, p0, v0, v1}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;-><init>(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;Landroid/bluetooth/BluetoothAdapter;Landroid/bluetooth/BluetoothAdapter$LeScanCallback;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public deferScanIfNeeded()Z
    .locals 6

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mNextScanCycleStartTime:J

    .line 2
    .line 3
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    sub-long/2addr v0, v2

    .line 8
    const-wide/16 v2, 0x0

    .line 9
    .line 10
    cmp-long v2, v0, v2

    .line 11
    .line 12
    if-lez v2, :cond_2

    .line 13
    .line 14
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const-string v3, "CycledLeScannerForJellyBeanMr2"

    .line 23
    .line 24
    const-string v4, "Waiting to start next Bluetooth scan for another %s milliseconds"

    .line 25
    .line 26
    invoke-static {v3, v4, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-boolean v2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mBackgroundFlag:Z

    .line 30
    .line 31
    if-eqz v2, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->setWakeUpAlarm()V

    .line 34
    .line 35
    .line 36
    :cond_0
    iget-object v2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mHandler:Landroid/os/Handler;

    .line 37
    .line 38
    new-instance v3, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$1;

    .line 39
    .line 40
    invoke-direct {v3, p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$1;-><init>(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;)V

    .line 41
    .line 42
    .line 43
    const-wide/16 v4, 0x3e8

    .line 44
    .line 45
    cmp-long p0, v0, v4

    .line 46
    .line 47
    if-lez p0, :cond_1

    .line 48
    .line 49
    move-wide v0, v4

    .line 50
    :cond_1
    invoke-virtual {v2, v3, v0, v1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 51
    .line 52
    .line 53
    const/4 p0, 0x1

    .line 54
    return p0

    .line 55
    :cond_2
    const/4 p0, 0x0

    .line 56
    return p0
.end method

.method public finishScan()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->postStopLeScan()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mScanningPaused:Z

    .line 6
    .line 7
    return-void
.end method

.method public startScan()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->postStartLeScan()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public stopScan()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->postStopLeScan()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
