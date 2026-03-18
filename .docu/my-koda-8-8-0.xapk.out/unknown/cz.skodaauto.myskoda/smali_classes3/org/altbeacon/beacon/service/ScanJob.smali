.class public Lorg/altbeacon/beacon/service/ScanJob;
.super Landroid/app/job/JobService;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/TargetApi;
    value = 0x15
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String; = "ScanJob"

.field private static sOverrideImmediateScanJobId:I = -0x1

.field private static sOverridePeriodicScanJobId:I = -0x1


# instance fields
.field private mInitialized:Z

.field private mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

.field private mScanState:Lorg/altbeacon/beacon/service/ScanState;

.field private mStopCalled:Z

.field private mStopHandler:Landroid/os/Handler;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/app/job/JobService;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 6
    .line 7
    new-instance v0, Landroid/os/Handler;

    .line 8
    .line 9
    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopHandler:Landroid/os/Handler;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mInitialized:Z

    .line 16
    .line 17
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopCalled:Z

    .line 18
    .line 19
    return-void
.end method

.method public static bridge synthetic a(Lorg/altbeacon/beacon/service/ScanJob;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mInitialized:Z

    .line 2
    .line 3
    return p0
.end method

.method public static bridge synthetic b(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanHelper;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic c(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanState;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic d(Lorg/altbeacon/beacon/service/ScanJob;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopCalled:Z

    .line 2
    .line 3
    return p0
.end method

.method public static bridge synthetic e(Lorg/altbeacon/beacon/service/ScanJob;)Landroid/os/Handler;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopHandler:Landroid/os/Handler;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic f(Lorg/altbeacon/beacon/service/ScanJob;)Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->initialzeScanHelper()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic g(Lorg/altbeacon/beacon/service/ScanJob;)Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->restartScanning()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static getImmediateScanJobId(Landroid/content/Context;)I
    .locals 2

    .line 1
    sget v0, Lorg/altbeacon/beacon/service/ScanJob;->sOverrideImmediateScanJobId:I

    .line 2
    .line 3
    if-ltz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "Using ImmediateScanJobId from static override: "

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    sget v1, Lorg/altbeacon/beacon/service/ScanJob;->sOverrideImmediateScanJobId:I

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const/4 v1, 0x0

    .line 24
    new-array v1, v1, [Ljava/lang/Object;

    .line 25
    .line 26
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    sget p0, Lorg/altbeacon/beacon/service/ScanJob;->sOverrideImmediateScanJobId:I

    .line 30
    .line 31
    return p0

    .line 32
    :cond_0
    const-string v0, "immediateScanJobId"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lorg/altbeacon/beacon/service/ScanJob;->getJobIdFromManifest(Landroid/content/Context;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    return p0
.end method

.method private static getJobIdFromManifest(Landroid/content/Context;Ljava/lang/String;)I
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Landroid/content/ComponentName;

    .line 6
    .line 7
    const-class v2, Lorg/altbeacon/beacon/service/ScanJob;

    .line 8
    .line 9
    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 10
    .line 11
    .line 12
    const/16 p0, 0x80

    .line 13
    .line 14
    invoke-virtual {v0, v1, p0}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 15
    .line 16
    .line 17
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    goto :goto_0

    .line 19
    :catch_0
    const/4 p0, 0x0

    .line 20
    :goto_0
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-object v0, p0, Landroid/content/pm/PackageItemInfo;->metaData:Landroid/os/Bundle;

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    iget-object p0, p0, Landroid/content/pm/PackageItemInfo;->metaData:Landroid/os/Bundle;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 39
    .line 40
    new-instance v1, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    const-string v2, "Using "

    .line 43
    .line 44
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p1, " from manifest: "

    .line 51
    .line 52
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    const/4 v1, 0x0

    .line 63
    new-array v1, v1, [Ljava/lang/Object;

    .line 64
    .line 65
    invoke-static {v0, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    return p0

    .line 69
    :cond_0
    new-instance p0, Ljava/lang/RuntimeException;

    .line 70
    .line 71
    const-string v0, "Cannot get job id from manifest.  Make sure that the "

    .line 72
    .line 73
    const-string v1, " is configured in the manifest for the ScanJob."

    .line 74
    .line 75
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0
.end method

.method public static getPeriodicScanJobId(Landroid/content/Context;)I
    .locals 2

    .line 1
    sget v0, Lorg/altbeacon/beacon/service/ScanJob;->sOverrideImmediateScanJobId:I

    .line 2
    .line 3
    if-ltz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 6
    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "Using PeriodicScanJobId from static override: "

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    sget v1, Lorg/altbeacon/beacon/service/ScanJob;->sOverridePeriodicScanJobId:I

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const/4 v1, 0x0

    .line 24
    new-array v1, v1, [Ljava/lang/Object;

    .line 25
    .line 26
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    sget p0, Lorg/altbeacon/beacon/service/ScanJob;->sOverridePeriodicScanJobId:I

    .line 30
    .line 31
    return p0

    .line 32
    :cond_0
    const-string v0, "periodicScanJobId"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lorg/altbeacon/beacon/service/ScanJob;->getJobIdFromManifest(Landroid/content/Context;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    return p0
.end method

.method public static bridge synthetic h(Lorg/altbeacon/beacon/service/ScanJob;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->scheduleNextScan()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(Lorg/altbeacon/beacon/service/ScanJob;)Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->startScanning()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private initialzeScanHelper()Z
    .locals 5

    .line 1
    invoke-static {p0}, Lorg/altbeacon/beacon/service/ScanState;->restore(Landroid/content/Context;)Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    new-instance v0, Lorg/altbeacon/beacon/service/ScanHelper;

    .line 11
    .line 12
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/service/ScanHelper;-><init>(Landroid/content/Context;)V

    .line 13
    .line 14
    .line 15
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 16
    .line 17
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v3

    .line 21
    invoke-virtual {v2, v3, v4}, Lorg/altbeacon/beacon/service/ScanState;->setLastScanStartTimeMillis(J)V

    .line 22
    .line 23
    .line 24
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 25
    .line 26
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanState;->getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/ScanHelper;->setMonitoringStatus(Lorg/altbeacon/beacon/service/MonitoringStatus;)V

    .line 31
    .line 32
    .line 33
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 34
    .line 35
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanState;->getRangedRegionState()Ljava/util/Map;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/ScanHelper;->setRangedRegionState(Ljava/util/Map;)V

    .line 40
    .line 41
    .line 42
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 43
    .line 44
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanState;->getBeaconParsers()Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/ScanHelper;->setBeaconParsers(Ljava/util/Set;)V

    .line 49
    .line 50
    .line 51
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 52
    .line 53
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanState;->getExtraBeaconDataTracker()Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/ScanHelper;->setExtraDataBeaconTracker(Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    if-nez v2, :cond_0

    .line 65
    .line 66
    :try_start_0
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 67
    .line 68
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-virtual {v0, v2, v3}, Lorg/altbeacon/beacon/service/ScanHelper;->createCycledLeScanner(ZLorg/altbeacon/bluetooth/BluetoothCrashResolver;)V
    :try_end_0
    .catch Ljava/lang/OutOfMemoryError; {:try_start_0 .. :try_end_0} :catch_0

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :catch_0
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 82
    .line 83
    const-string v0, "Failed to create CycledLeScanner thread."

    .line 84
    .line 85
    new-array v2, v1, [Ljava/lang/Object;

    .line 86
    .line 87
    invoke-static {p0, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    return v1

    .line 91
    :cond_0
    :goto_0
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 92
    .line 93
    const/4 p0, 0x1

    .line 94
    return p0

    .line 95
    :cond_1
    return v1
.end method

.method public static bridge synthetic j(Lorg/altbeacon/beacon/service/ScanJob;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->stopScanning()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method private restartScanning()Z
    .locals 8

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_9

    .line 5
    .line 6
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 7
    .line 8
    if-eqz v0, :cond_9

    .line 9
    .line 10
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->stopAndroidOBackgroundScan()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 14
    .line 15
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 26
    .line 27
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundScanPeriod()Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 33
    .line 34
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getForegroundScanPeriod()Ljava/lang/Long;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 39
    .line 40
    .line 41
    move-result-wide v3

    .line 42
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 43
    .line 44
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_1

    .line 53
    .line 54
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 55
    .line 56
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundBetweenScanPeriod()Ljava/lang/Long;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 62
    .line 63
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getForegroundBetweenScanPeriod()Ljava/lang/Long;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    :goto_1
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 68
    .line 69
    .line 70
    move-result-wide v5

    .line 71
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 72
    .line 73
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-eqz v0, :cond_2

    .line 78
    .line 79
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 80
    .line 81
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 86
    .line 87
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 92
    .line 93
    .line 94
    move-result v7

    .line 95
    invoke-virtual/range {v2 .. v7}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->setScanPeriods(JJZ)V

    .line 96
    .line 97
    .line 98
    :cond_2
    const/4 v0, 0x1

    .line 99
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mInitialized:Z

    .line 100
    .line 101
    const-wide/16 v5, 0x0

    .line 102
    .line 103
    cmp-long v2, v3, v5

    .line 104
    .line 105
    if-gtz v2, :cond_4

    .line 106
    .line 107
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 108
    .line 109
    const-string v2, "Starting scan with scan period of zero.  Exiting ScanJob."

    .line 110
    .line 111
    new-array v3, v1, [Ljava/lang/Object;

    .line 112
    .line 113
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 117
    .line 118
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    if-eqz v0, :cond_3

    .line 123
    .line 124
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 125
    .line 126
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->stop()V

    .line 131
    .line 132
    .line 133
    :cond_3
    return v1

    .line 134
    :cond_4
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 135
    .line 136
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanHelper;->getRangedRegionState()Ljava/util/Map;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    invoke-interface {v2}, Ljava/util/Map;->size()I

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    if-gtz v2, :cond_7

    .line 145
    .line 146
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 147
    .line 148
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanHelper;->getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    invoke-interface {v2}, Ljava/util/Set;->size()I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    if-lez v2, :cond_5

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_5
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 164
    .line 165
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    if-eqz v0, :cond_6

    .line 170
    .line 171
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 172
    .line 173
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->stop()V

    .line 178
    .line 179
    .line 180
    :cond_6
    return v1

    .line 181
    :cond_7
    :goto_2
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 182
    .line 183
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    if-eqz v1, :cond_8

    .line 188
    .line 189
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 190
    .line 191
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->start()V

    .line 196
    .line 197
    .line 198
    :cond_8
    return v0

    .line 199
    :cond_9
    return v1
.end method

.method private scheduleNextScan()V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    new-array v1, v1, [Ljava/lang/Object;

    .line 19
    .line 20
    const-string v2, "In foreground mode, schedule next scan"

    .line 21
    .line 22
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->forceScheduleNextScan(Landroid/content/Context;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->startPassiveScanIfNeeded()V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method

.method public static setOverrideImmediateScanJobId(I)V
    .locals 0

    .line 1
    sput p0, Lorg/altbeacon/beacon/service/ScanJob;->sOverrideImmediateScanJobId:I

    .line 2
    .line 3
    return-void
.end method

.method public static setOverridePeriodicScanJobId(I)V
    .locals 0

    .line 1
    sput p0, Lorg/altbeacon/beacon/service/ScanJob;->sOverridePeriodicScanJobId:I

    .line 2
    .line 3
    return-void
.end method

.method private startPassiveScanIfNeeded()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "Checking to see if we need to start a passive scan"

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v3, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 16
    .line 17
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/ScanState;->getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->insideAnyRegion()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    const-string p0, "We are inside a beacon region.  We will not scan between cycles."

    .line 28
    .line 29
    new-array v1, v2, [Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {v0, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanState:Lorg/altbeacon/beacon/service/ScanState;

    .line 40
    .line 41
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBeaconParsers()Ljava/util/Set;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/service/ScanHelper;->startAndroidOBackgroundScan(Ljava/util/Set;)V

    .line 46
    .line 47
    .line 48
    :cond_1
    return-void
.end method

.method private startScanning()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-virtual {v0, v1}, Lorg/altbeacon/beacon/BeaconManager;->setScannerInSameProcess(Z)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isMainProcess()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const-string v1, "2.21.1"

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 22
    .line 23
    const-string v2, "scanJob version %s is starting up on the main process"

    .line 24
    .line 25
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 34
    .line 35
    const-string v2, "beaconScanJob library version %s is starting up on a separate process"

    .line 36
    .line 37
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    new-instance v1, Lorg/altbeacon/beacon/utils/ProcessUtils;

    .line 45
    .line 46
    invoke-direct {v1, p0}, Lorg/altbeacon/beacon/utils/ProcessUtils;-><init>(Landroid/content/Context;)V

    .line 47
    .line 48
    .line 49
    new-instance v2, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v3, "beaconScanJob PID is "

    .line 52
    .line 53
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v1}, Lorg/altbeacon/beacon/utils/ProcessUtils;->getPid()I

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v3, " with process name "

    .line 64
    .line 65
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1}, Lorg/altbeacon/beacon/utils/ProcessUtils;->getProcessName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    const/4 v2, 0x0

    .line 80
    new-array v2, v2, [Ljava/lang/Object;

    .line 81
    .line 82
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :goto_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->restartScanning()Z

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    return p0
.end method

.method private stopScanning()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mInitialized:Z

    .line 3
    .line 4
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/ScanHelper;->stopAndroidOBackgroundScan()V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 12
    .line 13
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 20
    .line 21
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->stop()V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 29
    .line 30
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanHelper;->getCycledScanner()Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->destroy()V

    .line 35
    .line 36
    .line 37
    :cond_0
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 38
    .line 39
    const-string v1, "Scanning stopped"

    .line 40
    .line 41
    new-array v0, v0, [Ljava/lang/Object;

    .line 42
    .line 43
    invoke-static {p0, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public onStartJob(Landroid/app/job/JobParameters;)Z
    .locals 4

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "ScanJob Lifecycle START: "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x0

    .line 18
    new-array v3, v2, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iput-boolean v2, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopCalled:Z

    .line 24
    .line 25
    new-instance v0, Ljava/lang/Thread;

    .line 26
    .line 27
    new-instance v1, Lorg/altbeacon/beacon/service/ScanJob$1;

    .line 28
    .line 29
    invoke-direct {v1, p0, p1}, Lorg/altbeacon/beacon/service/ScanJob$1;-><init>(Lorg/altbeacon/beacon/service/ScanJob;Landroid/app/job/JobParameters;)V

    .line 30
    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    return p0
.end method

.method public onStopJob(Landroid/app/job/JobParameters;)Z
    .locals 7

    .line 1
    const-string v0, "ScanJob Lifecycle STOP: "

    .line 2
    .line 3
    const-string v1, "onStopJob called for immediate scan "

    .line 4
    .line 5
    const-string v2, "onStopJob called for periodic scan "

    .line 6
    .line 7
    sget-object v3, Lorg/altbeacon/beacon/service/ScanJob;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    const-string v4, "onStopJob called"

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    new-array v6, v5, [Ljava/lang/Object;

    .line 13
    .line 14
    invoke-static {v3, v4, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    monitor-enter p0

    .line 18
    const/4 v4, 0x1

    .line 19
    :try_start_0
    iput-boolean v4, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopCalled:Z

    .line 20
    .line 21
    invoke-virtual {p1}, Landroid/app/job/JobParameters;->getJobId()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-static {p0}, Lorg/altbeacon/beacon/service/ScanJob;->getPeriodicScanJobId(Landroid/content/Context;)I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    if-ne p1, v4, :cond_0

    .line 30
    .line 31
    new-instance p1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    new-array v1, v5, [Ljava/lang/Object;

    .line 44
    .line 45
    invoke-static {v3, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p1

    .line 50
    goto :goto_1

    .line 51
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    new-array v1, v5, [Ljava/lang/Object;

    .line 64
    .line 65
    invoke-static {v3, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    :goto_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    new-array v0, v5, [Ljava/lang/Object;

    .line 81
    .line 82
    invoke-static {v3, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mStopHandler:Landroid/os/Handler;

    .line 86
    .line 87
    const/4 v0, 0x0

    .line 88
    invoke-virtual {p1, v0}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    if-eqz p1, :cond_1

    .line 100
    .line 101
    const-string p1, "ScanJob completed for intent scan strategy."

    .line 102
    .line 103
    new-array v0, v5, [Ljava/lang/Object;

    .line 104
    .line 105
    invoke-static {v3, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    monitor-exit p0

    .line 109
    return v5

    .line 110
    :cond_1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->stopScanning()V

    .line 111
    .line 112
    .line 113
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/ScanJob;->startPassiveScanIfNeeded()V

    .line 114
    .line 115
    .line 116
    iget-object p1, p0, Lorg/altbeacon/beacon/service/ScanJob;->mScanHelper:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 117
    .line 118
    if-eqz p1, :cond_2

    .line 119
    .line 120
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/ScanHelper;->terminateThreads()V

    .line 121
    .line 122
    .line 123
    :cond_2
    monitor-exit p0

    .line 124
    return v5

    .line 125
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 126
    throw p1
.end method
