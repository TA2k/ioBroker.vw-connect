.class public Lorg/altbeacon/bluetooth/BluetoothMedic;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final MIN_MILLIS_BETWEEN_BLUETOOTH_POWER_CYCLES:J = 0xea60L

.field public static final NO_TEST:I = 0x0

.field public static final SCAN_TEST:I = 0x1

.field private static final TAG:Ljava/lang/String; = "BluetoothMedic"

.field public static final TRANSMIT_TEST:I = 0x2

.field private static sInstance:Lorg/altbeacon/bluetooth/BluetoothMedic;


# instance fields
.field private mAdapter:Landroid/bluetooth/BluetoothAdapter;

.field private mContext:Landroid/content/Context;

.field private mHandler:Landroid/os/Handler;

.field private mLastBluetoothPowerCycleTime:J

.field private mNotificationChannelCreated:Z

.field private mNotificationIcon:I

.field private mNotificationsEnabled:Z

.field private mScanTestResult:Ljava/lang/Boolean;

.field private mTestType:I

.field private mTransmitterTestResult:Ljava/lang/Boolean;

.field private powerCycleOnFailureEnabled:Z


# direct methods
.method private constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/os/Handler;

    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mHandler:Landroid/os/Handler;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    iput v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTestType:I

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    iput-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTransmitterTestResult:Ljava/lang/Boolean;

    .line 20
    .line 21
    iput-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mScanTestResult:Ljava/lang/Boolean;

    .line 22
    .line 23
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationsEnabled:Z

    .line 24
    .line 25
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationChannelCreated:Z

    .line 26
    .line 27
    iput v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationIcon:I

    .line 28
    .line 29
    const-wide/16 v2, 0x0

    .line 30
    .line 31
    iput-wide v2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mLastBluetoothPowerCycleTime:J

    .line 32
    .line 33
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->powerCycleOnFailureEnabled:Z

    .line 34
    .line 35
    iput-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mContext:Landroid/content/Context;

    .line 36
    .line 37
    return-void
.end method

.method public static bridge synthetic a(Lorg/altbeacon/bluetooth/BluetoothMedic;)Landroid/bluetooth/BluetoothAdapter;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic b(Lorg/altbeacon/bluetooth/BluetoothMedic;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mScanTestResult:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method public static bridge synthetic c(Lorg/altbeacon/bluetooth/BluetoothMedic;Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTransmitterTestResult:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-void
.end method

.method private createNotificationChannel(Landroid/content/Context;Ljava/lang/String;)V
    .locals 3

    .line 1
    new-instance v0, Landroid/app/NotificationChannel;

    .line 2
    .line 3
    const-string v1, "Errors"

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    invoke-direct {v0, p2, v1, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    .line 7
    .line 8
    .line 9
    const-string p2, "Scan errors"

    .line 10
    .line 11
    invoke-virtual {v0, p2}, Landroid/app/NotificationChannel;->setDescription(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-class p2, Landroid/app/NotificationManager;

    .line 15
    .line 16
    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Landroid/app/NotificationManager;

    .line 21
    .line 22
    invoke-virtual {p1, v0}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 23
    .line 24
    .line 25
    const/4 p1, 0x1

    .line 26
    iput-boolean p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationChannelCreated:Z

    .line 27
    .line 28
    return-void
.end method

.method private cycleBluetooth()V
    .locals 4
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v3, "Power cycling bluetooth"

    .line 7
    .line 8
    invoke-static {v0, v3, v2}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->isBleConnectPermissionDenied()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    const-string p0, "Can\'t power cycle bleutooth.  Connect permisison is denied."

    .line 18
    .line 19
    new-array v1, v1, [Ljava/lang/Object;

    .line 20
    .line 21
    invoke-static {v0, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    const-string v2, "Turning Bluetooth off."

    .line 26
    .line 27
    new-array v3, v1, [Ljava/lang/Object;

    .line 28
    .line 29
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 33
    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothAdapter;->disable()Z

    .line 37
    .line 38
    .line 39
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mHandler:Landroid/os/Handler;

    .line 40
    .line 41
    new-instance v1, Lorg/altbeacon/bluetooth/BluetoothMedic$3;

    .line 42
    .line 43
    invoke-direct {v1, p0}, Lorg/altbeacon/bluetooth/BluetoothMedic$3;-><init>(Lorg/altbeacon/bluetooth/BluetoothMedic;)V

    .line 44
    .line 45
    .line 46
    const-wide/16 v2, 0x3e8

    .line 47
    .line 48
    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_1
    const-string p0, "Cannot cycle bluetooth.  Manager is null."

    .line 53
    .line 54
    new-array v1, v1, [Ljava/lang/Object;

    .line 55
    .line 56
    invoke-static {v0, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-void
.end method

.method private cycleBluetoothIfNotTooSoon()Z
    .locals 5

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mLastBluetoothPowerCycleTime:J

    .line 6
    .line 7
    sub-long/2addr v0, v2

    .line 8
    const-wide/32 v2, 0xea60

    .line 9
    .line 10
    .line 11
    cmp-long v2, v0, v2

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    if-gez v2, :cond_0

    .line 15
    .line 16
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 17
    .line 18
    const-string v2, "Not cycling bluetooth because we just did so "

    .line 19
    .line 20
    const-string v4, " milliseconds ago."

    .line 21
    .line 22
    invoke-static {v0, v1, v2, v4}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    new-array v1, v3, [Ljava/lang/Object;

    .line 27
    .line 28
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return v3

    .line 32
    :cond_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    iput-wide v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mLastBluetoothPowerCycleTime:J

    .line 37
    .line 38
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 39
    .line 40
    const-string v1, "Power cycling bluetooth"

    .line 41
    .line 42
    new-array v2, v3, [Ljava/lang/Object;

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->cycleBluetooth()V

    .line 48
    .line 49
    .line 50
    const/4 p0, 0x1

    .line 51
    return p0
.end method

.method public static bridge synthetic d(Lorg/altbeacon/bluetooth/BluetoothMedic;)V
    .locals 2

    .line 1
    const-string v0, "scan failed"

    .line 2
    .line 3
    const-string v1, "bluetooth not ok"

    .line 4
    .line 5
    invoke-direct {p0, v0, v1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->sendScreenNotification(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static bridge synthetic e()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method private getAdvertiserSafely(Landroid/bluetooth/BluetoothAdapter;)Landroid/bluetooth/le/BluetoothLeAdvertiser;
    .locals 1

    .line 1
    :try_start_0
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothAdapter;->getBluetoothLeAdvertiser()Landroid/bluetooth/le/BluetoothLeAdvertiser;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    move-exception p0

    .line 7
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    const-string v0, "Cannot get bluetoothLeAdvertiser"

    .line 10
    .line 11
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p1, v0, p0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method

.method public static getInstance()Lorg/altbeacon/bluetooth/BluetoothMedic;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->sInstance:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 6
    .line 7
    invoke-direct {v0}, Lorg/altbeacon/bluetooth/BluetoothMedic;-><init>()V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->sInstance:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 11
    .line 12
    :cond_0
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->sInstance:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 13
    .line 14
    return-object v0
.end method

.method private initializeWithContext(Landroid/content/Context;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const-string v0, "bluetooth"

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, Landroid/bluetooth/BluetoothManager;

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothManager;->getAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 23
    .line 24
    const-string p1, "Cannot get BluetoothManager"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    return-void
.end method

.method private isAndroidSPermissionDenied(Ljava/lang/String;)Z
    .locals 3

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x1f

    .line 5
    .line 6
    if-lt v0, v2, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mContext:Landroid/content/Context;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget v0, v0, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I

    .line 17
    .line 18
    if-lt v0, v2, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mContext:Landroid/content/Context;

    .line 21
    .line 22
    invoke-static {p0, p1}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    return p0

    .line 30
    :cond_0
    return v1
.end method

.method private isBleAdvertisePermissionDenied()Z
    .locals 1

    .line 1
    const-string v0, "android.permission.BLUETOOTH_ADVERTISE"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->isAndroidSPermissionDenied(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method private isBleConnectPermissionDenied()Z
    .locals 1

    .line 1
    const-string v0, "android.permission.BLUETOOTH_CONNECT"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->isAndroidSPermissionDenied(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method private isBleScanPermissionDenied()Z
    .locals 1

    .line 1
    const-string v0, "android.permission.BLUETOOTH_SCAN"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->isAndroidSPermissionDenied(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method private scheduleRegularTests(Landroid/content/Context;)V
    .locals 4

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->initializeWithContext(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/content/ComponentName;

    .line 5
    .line 6
    const-class v1, Lorg/altbeacon/bluetooth/BluetoothTestJob;

    .line 7
    .line 8
    invoke-direct {v0, p1, v1}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Landroid/app/job/JobInfo$Builder;

    .line 12
    .line 13
    invoke-static {p1}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->getJobId(Landroid/content/Context;)I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    invoke-direct {v1, v2, v0}, Landroid/app/job/JobInfo$Builder;-><init>(ILandroid/content/ComponentName;)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-virtual {v1, v0}, Landroid/app/job/JobInfo$Builder;->setRequiresCharging(Z)Landroid/app/job/JobInfo$Builder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, v0}, Landroid/app/job/JobInfo$Builder;->setRequiresDeviceIdle(Z)Landroid/app/job/JobInfo$Builder;

    .line 25
    .line 26
    .line 27
    const-wide/32 v2, 0xdbba0

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1, v2, v3}, Landroid/app/job/JobInfo$Builder;->setPeriodic(J)Landroid/app/job/JobInfo$Builder;

    .line 31
    .line 32
    .line 33
    const/4 v0, 0x1

    .line 34
    invoke-virtual {v1, v0}, Landroid/app/job/JobInfo$Builder;->setPersisted(Z)Landroid/app/job/JobInfo$Builder;

    .line 35
    .line 36
    .line 37
    new-instance v0, Landroid/os/PersistableBundle;

    .line 38
    .line 39
    invoke-direct {v0}, Landroid/os/PersistableBundle;-><init>()V

    .line 40
    .line 41
    .line 42
    const-string v2, "test_type"

    .line 43
    .line 44
    iget p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTestType:I

    .line 45
    .line 46
    invoke-virtual {v0, v2, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1, v0}, Landroid/app/job/JobInfo$Builder;->setExtras(Landroid/os/PersistableBundle;)Landroid/app/job/JobInfo$Builder;

    .line 50
    .line 51
    .line 52
    const-string p0, "jobscheduler"

    .line 53
    .line 54
    invoke-virtual {p1, p0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p0, Landroid/app/job/JobScheduler;

    .line 59
    .line 60
    if-eqz p0, :cond_0

    .line 61
    .line 62
    invoke-virtual {v1}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-virtual {p0, p1}, Landroid/app/job/JobScheduler;->schedule(Landroid/app/job/JobInfo;)I

    .line 67
    .line 68
    .line 69
    :cond_0
    return-void
.end method

.method private sendScreenNotification(Ljava/lang/String;Ljava/lang/String;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 7
    .line 8
    const-string p1, "congtext is unexpectedly null"

    .line 9
    .line 10
    new-array p2, v1, [Ljava/lang/Object;

    .line 11
    .line 12
    invoke-static {p0, p1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    invoke-direct {p0, v0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->initializeWithContext(Landroid/content/Context;)V

    .line 17
    .line 18
    .line 19
    iget-boolean v2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationsEnabled:Z

    .line 20
    .line 21
    if-eqz v2, :cond_2

    .line 22
    .line 23
    iget-boolean v2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationChannelCreated:Z

    .line 24
    .line 25
    const-string v3, "err"

    .line 26
    .line 27
    if-nez v2, :cond_1

    .line 28
    .line 29
    invoke-direct {p0, v0, v3}, Lorg/altbeacon/bluetooth/BluetoothMedic;->createNotificationChannel(Landroid/content/Context;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    new-instance v2, Landroidx/core/app/x;

    .line 33
    .line 34
    invoke-direct {v2, v0, v3}, Landroidx/core/app/x;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    new-instance v3, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v4, "BluetoothMedic: "

    .line 40
    .line 41
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-static {p1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    iput-object p1, v2, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 56
    .line 57
    iget p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationIcon:I

    .line 58
    .line 59
    iget-object p1, v2, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 60
    .line 61
    iput p0, p1, Landroid/app/Notification;->icon:I

    .line 62
    .line 63
    const/4 p0, 0x3

    .line 64
    new-array p0, p0, [J

    .line 65
    .line 66
    fill-array-data p0, :array_0

    .line 67
    .line 68
    .line 69
    iput-object p0, p1, Landroid/app/Notification;->vibrate:[J

    .line 70
    .line 71
    invoke-static {p2}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    iput-object p0, v2, Landroidx/core/app/x;->f:Ljava/lang/CharSequence;

    .line 76
    .line 77
    invoke-static {v0}, Landroid/app/TaskStackBuilder;->create(Landroid/content/Context;)Landroid/app/TaskStackBuilder;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    new-instance p1, Landroid/content/Intent;

    .line 82
    .line 83
    const-string p2, "NoOperation"

    .line 84
    .line 85
    invoke-direct {p1, p2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p0, p1}, Landroid/app/TaskStackBuilder;->addNextIntent(Landroid/content/Intent;)Landroid/app/TaskStackBuilder;

    .line 89
    .line 90
    .line 91
    const/high16 p1, 0xc000000

    .line 92
    .line 93
    invoke-virtual {p0, v1, p1}, Landroid/app/TaskStackBuilder;->getPendingIntent(II)Landroid/app/PendingIntent;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    iput-object p0, v2, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 98
    .line 99
    const-string p0, "notification"

    .line 100
    .line 101
    invoke-virtual {v0, p0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Landroid/app/NotificationManager;

    .line 106
    .line 107
    if-eqz p0, :cond_2

    .line 108
    .line 109
    const/4 p1, 0x1

    .line 110
    invoke-virtual {v2}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    invoke-virtual {p0, p1, p2}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 115
    .line 116
    .line 117
    :cond_2
    return-void

    .line 118
    nop

    .line 119
    :array_0
    .array-data 8
        0xc8
        0x64
        0xc8
    .end array-data
.end method


# virtual methods
.method public enablePeriodicTests(Landroid/content/Context;I)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->initializeWithContext(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    iput p2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTestType:I

    .line 5
    .line 6
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 7
    .line 8
    const-string v1, "Medic scheduling periodic tests of types "

    .line 9
    .line 10
    invoke-static {p2, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    const/4 v1, 0x0

    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {v0, p2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->scheduleRegularTests(Landroid/content/Context;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public enablePowerCycleOnFailures(Landroid/content/Context;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->legacyEnablePowerCycleOnFailures(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public legacyEnablePowerCycleOnFailures(Landroid/content/Context;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mContext:Landroid/content/Context;

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->powerCycleOnFailureEnabled:Z

    .line 9
    .line 10
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->initializeWithContext(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    new-array p1, p1, [Ljava/lang/Object;

    .line 17
    .line 18
    const-string v0, "Medic monitoring for transmission and scan failure notifications"

    .line 19
    .line 20
    invoke-static {p0, v0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public processMedicAction(Ljava/lang/String;I)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->powerCycleOnFailureEnabled:Z

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    const-string v0, "onScanFailed"

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const-string v1, "Cannot power cycle bluetooth again"

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 p1, 0x2

    .line 17
    if-ne p2, p1, :cond_2

    .line 18
    .line 19
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 20
    .line 21
    const-string p2, "Detected a SCAN_FAILED_APPLICATION_REGISTRATION_FAILED.  We need to cycle bluetooth to recover"

    .line 22
    .line 23
    new-array v0, v2, [Ljava/lang/Object;

    .line 24
    .line 25
    invoke-static {p1, p2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    const-string p1, "Power cycling bluetooth"

    .line 29
    .line 30
    const-string p2, "scan failed"

    .line 31
    .line 32
    invoke-direct {p0, p2, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->sendScreenNotification(Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->cycleBluetoothIfNotTooSoon()Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_2

    .line 40
    .line 41
    invoke-direct {p0, p2, v1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->sendScreenNotification(Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    const-string v0, "onStartFailed"

    .line 46
    .line 47
    invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_1

    .line 52
    .line 53
    const/4 p1, 0x4

    .line 54
    if-ne p2, p1, :cond_2

    .line 55
    .line 56
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 57
    .line 58
    const-string p2, "advertising failed: Expected failure.  Power cycling."

    .line 59
    .line 60
    new-array v0, v2, [Ljava/lang/Object;

    .line 61
    .line 62
    invoke-static {p1, p2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    const-string p1, "Expected failure.  Power cycling."

    .line 66
    .line 67
    const-string p2, "advertising failed"

    .line 68
    .line 69
    invoke-direct {p0, p2, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->sendScreenNotification(Ljava/lang/String;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->cycleBluetoothIfNotTooSoon()Z

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-nez p1, :cond_2

    .line 77
    .line 78
    invoke-direct {p0, p2, v1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->sendScreenNotification(Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :cond_1
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 83
    .line 84
    const-string p1, "Unknown event."

    .line 85
    .line 86
    new-array p2, v2, [Ljava/lang/Object;

    .line 87
    .line 88
    invoke-static {p0, p1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_2
    return-void
.end method

.method public runScanTest(Landroid/content/Context;)Z
    .locals 10
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->initializeWithContext(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->isBleScanPermissionDenied()Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    const/4 v0, 0x1

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const-string p1, "Cant run scan test -- required scan permission is denied"

    .line 15
    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    invoke-static {p0, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return v0

    .line 22
    :cond_0
    const/4 p1, 0x0

    .line 23
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mScanTestResult:Ljava/lang/Boolean;

    .line 24
    .line 25
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 26
    .line 27
    const-string v2, "Starting scan test"

    .line 28
    .line 29
    new-array v3, v1, [Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    iget-object v4, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 39
    .line 40
    if-eqz v4, :cond_4

    .line 41
    .line 42
    invoke-virtual {v4}, Landroid/bluetooth/BluetoothAdapter;->getBluetoothLeScanner()Landroid/bluetooth/le/BluetoothLeScanner;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    new-instance v5, Lorg/altbeacon/bluetooth/BluetoothMedic$1;

    .line 47
    .line 48
    invoke-direct {v5, p0, v4}, Lorg/altbeacon/bluetooth/BluetoothMedic$1;-><init>(Lorg/altbeacon/bluetooth/BluetoothMedic;Landroid/bluetooth/le/BluetoothLeScanner;)V

    .line 49
    .line 50
    .line 51
    if-eqz v4, :cond_3

    .line 52
    .line 53
    :try_start_0
    invoke-virtual {v4, v5}, Landroid/bluetooth/le/BluetoothLeScanner;->startScan(Landroid/bluetooth/le/ScanCallback;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mScanTestResult:Ljava/lang/Boolean;

    .line 57
    .line 58
    if-nez p1, :cond_2

    .line 59
    .line 60
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 61
    .line 62
    const-string v6, "Waiting for scan test to complete..."

    .line 63
    .line 64
    new-array v7, v1, [Ljava/lang/Object;

    .line 65
    .line 66
    invoke-static {p1, v6, v7}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 67
    .line 68
    .line 69
    const-wide/16 v6, 0x3e8

    .line 70
    .line 71
    :try_start_1
    invoke-static {v6, v7}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :catch_0
    move-exception p1

    .line 76
    goto :goto_1

    .line 77
    :catch_1
    :goto_0
    :try_start_2
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 78
    .line 79
    .line 80
    move-result-wide v6

    .line 81
    sub-long/2addr v6, v2

    .line 82
    const-wide/16 v8, 0x1388

    .line 83
    .line 84
    cmp-long p1, v6, v8

    .line 85
    .line 86
    if-lez p1, :cond_1

    .line 87
    .line 88
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 89
    .line 90
    const-string v2, "Timeout running scan test"

    .line 91
    .line 92
    new-array v3, v1, [Ljava/lang/Object;

    .line 93
    .line 94
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_2
    invoke-virtual {v4, v5}, Landroid/bluetooth/le/BluetoothLeScanner;->stopScan(Landroid/bluetooth/le/ScanCallback;)V
    :try_end_2
    .catch Ljava/lang/IllegalStateException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/NullPointerException; {:try_start_2 .. :try_end_2} :catch_0

    .line 98
    .line 99
    .line 100
    goto :goto_2

    .line 101
    :goto_1
    sget-object v2, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 102
    .line 103
    const-string v3, "NullPointerException. Cannot run scan test."

    .line 104
    .line 105
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-static {v2, v3, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    goto :goto_2

    .line 113
    :catch_2
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 114
    .line 115
    const-string v2, "Bluetooth is off.  Cannot run scan test."

    .line 116
    .line 117
    new-array v3, v1, [Ljava/lang/Object;

    .line 118
    .line 119
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_3
    const-string v2, "Cannot get scanner"

    .line 124
    .line 125
    new-array v3, v1, [Ljava/lang/Object;

    .line 126
    .line 127
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :cond_4
    :goto_2
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 131
    .line 132
    const-string v2, "scan test complete"

    .line 133
    .line 134
    new-array v3, v1, [Ljava/lang/Object;

    .line 135
    .line 136
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mScanTestResult:Ljava/lang/Boolean;

    .line 140
    .line 141
    if-eqz p0, :cond_6

    .line 142
    .line 143
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 144
    .line 145
    .line 146
    move-result p0

    .line 147
    if-eqz p0, :cond_5

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_5
    move v0, v1

    .line 151
    :cond_6
    :goto_3
    return v0
.end method

.method public runTransmitterTest(Landroid/content/Context;)Z
    .locals 9
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->initializeWithContext(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->isBleAdvertisePermissionDenied()Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    const/4 v0, 0x1

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const-string p1, "Cannot run transmitter test -- advertise permission not granted"

    .line 15
    .line 16
    new-array v1, v1, [Ljava/lang/Object;

    .line 17
    .line 18
    invoke-static {p0, p1, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return v0

    .line 22
    :cond_0
    const/4 p1, 0x0

    .line 23
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTransmitterTestResult:Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 26
    .line 27
    .line 28
    move-result-wide v2

    .line 29
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 30
    .line 31
    if-eqz p1, :cond_3

    .line 32
    .line 33
    invoke-direct {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->getAdvertiserSafely(Landroid/bluetooth/BluetoothAdapter;)Landroid/bluetooth/le/BluetoothLeAdvertiser;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    new-instance v4, Landroid/bluetooth/le/AdvertiseSettings$Builder;

    .line 40
    .line 41
    invoke-direct {v4}, Landroid/bluetooth/le/AdvertiseSettings$Builder;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v4, v1}, Landroid/bluetooth/le/AdvertiseSettings$Builder;->setAdvertiseMode(I)Landroid/bluetooth/le/AdvertiseSettings$Builder;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    invoke-virtual {v4}, Landroid/bluetooth/le/AdvertiseSettings$Builder;->build()Landroid/bluetooth/le/AdvertiseSettings;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    new-instance v5, Landroid/bluetooth/le/AdvertiseData$Builder;

    .line 53
    .line 54
    invoke-direct {v5}, Landroid/bluetooth/le/AdvertiseData$Builder;-><init>()V

    .line 55
    .line 56
    .line 57
    new-array v6, v0, [B

    .line 58
    .line 59
    aput-byte v1, v6, v1

    .line 60
    .line 61
    invoke-virtual {v5, v1, v6}, Landroid/bluetooth/le/AdvertiseData$Builder;->addManufacturerData(I[B)Landroid/bluetooth/le/AdvertiseData$Builder;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    invoke-virtual {v5}, Landroid/bluetooth/le/AdvertiseData$Builder;->build()Landroid/bluetooth/le/AdvertiseData;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    sget-object v6, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 70
    .line 71
    const-string v7, "Starting transmitter test"

    .line 72
    .line 73
    new-array v8, v1, [Ljava/lang/Object;

    .line 74
    .line 75
    invoke-static {v6, v7, v8}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    new-instance v6, Lorg/altbeacon/bluetooth/BluetoothMedic$2;

    .line 79
    .line 80
    invoke-direct {v6, p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic$2;-><init>(Lorg/altbeacon/bluetooth/BluetoothMedic;Landroid/bluetooth/le/BluetoothLeAdvertiser;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, v4, v5, v6}, Landroid/bluetooth/le/BluetoothLeAdvertiser;->startAdvertising(Landroid/bluetooth/le/AdvertiseSettings;Landroid/bluetooth/le/AdvertiseData;Landroid/bluetooth/le/AdvertiseCallback;)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_1
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 88
    .line 89
    const-string v4, "Cannot get advertiser"

    .line 90
    .line 91
    new-array v5, v1, [Ljava/lang/Object;

    .line 92
    .line 93
    invoke-static {p1, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_2
    :goto_0
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTransmitterTestResult:Ljava/lang/Boolean;

    .line 97
    .line 98
    if-nez p1, :cond_3

    .line 99
    .line 100
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 101
    .line 102
    const-string v4, "Waiting for transmitter test to complete..."

    .line 103
    .line 104
    new-array v5, v1, [Ljava/lang/Object;

    .line 105
    .line 106
    invoke-static {p1, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    const-wide/16 v4, 0x3e8

    .line 110
    .line 111
    :try_start_0
    invoke-static {v4, v5}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 112
    .line 113
    .line 114
    :catch_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 115
    .line 116
    .line 117
    move-result-wide v4

    .line 118
    sub-long/2addr v4, v2

    .line 119
    const-wide/16 v6, 0x1388

    .line 120
    .line 121
    cmp-long p1, v4, v6

    .line 122
    .line 123
    if-lez p1, :cond_2

    .line 124
    .line 125
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 126
    .line 127
    const-string v2, "Timeout running transmitter test"

    .line 128
    .line 129
    new-array v3, v1, [Ljava/lang/Object;

    .line 130
    .line 131
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    :cond_3
    sget-object p1, Lorg/altbeacon/bluetooth/BluetoothMedic;->TAG:Ljava/lang/String;

    .line 135
    .line 136
    const-string v2, "transmitter test complete"

    .line 137
    .line 138
    new-array v3, v1, [Ljava/lang/Object;

    .line 139
    .line 140
    invoke-static {p1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mTransmitterTestResult:Ljava/lang/Boolean;

    .line 144
    .line 145
    if-eqz p0, :cond_4

    .line 146
    .line 147
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 148
    .line 149
    .line 150
    move-result p0

    .line 151
    if-eqz p0, :cond_4

    .line 152
    .line 153
    goto :goto_1

    .line 154
    :cond_4
    move v0, v1

    .line 155
    :goto_1
    return v0
.end method

.method public setNotificationsEnabled(ZI)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationsEnabled:Z

    .line 2
    .line 3
    iput p2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic;->mNotificationIcon:I

    .line 4
    .line 5
    return-void
.end method
