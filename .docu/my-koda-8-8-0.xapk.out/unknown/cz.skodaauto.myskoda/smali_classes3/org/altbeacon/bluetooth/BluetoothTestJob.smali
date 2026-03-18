.class public Lorg/altbeacon/bluetooth/BluetoothTestJob;
.super Landroid/app/job/JobService;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "BluetoothTestJob"

.field private static sOverrideJobId:I = -0x1


# instance fields
.field private mHandler:Landroid/os/Handler;

.field private mHandlerThread:Landroid/os/HandlerThread;


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
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandler:Landroid/os/Handler;

    .line 6
    .line 7
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandlerThread:Landroid/os/HandlerThread;

    .line 8
    .line 9
    return-void
.end method

.method public static bridge synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static getJobId(Landroid/content/Context;)I
    .locals 4

    .line 1
    sget v0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->sOverrideJobId:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-ltz v0, :cond_0

    .line 5
    .line 6
    sget-object p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->TAG:Ljava/lang/String;

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "Using BluetoothTestJob JobId from static override: "

    .line 11
    .line 12
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget v2, Lorg/altbeacon/bluetooth/BluetoothTestJob;->sOverrideJobId:I

    .line 16
    .line 17
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-array v1, v1, [Ljava/lang/Object;

    .line 25
    .line 26
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    sget p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->sOverrideJobId:I

    .line 30
    .line 31
    return p0

    .line 32
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v2, Landroid/content/ComponentName;

    .line 37
    .line 38
    const-class v3, Lorg/altbeacon/bluetooth/BluetoothTestJob;

    .line 39
    .line 40
    invoke-direct {v2, p0, v3}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 41
    .line 42
    .line 43
    const/16 p0, 0x80

    .line 44
    .line 45
    invoke-virtual {v0, v2, p0}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 46
    .line 47
    .line 48
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 49
    goto :goto_0

    .line 50
    :catch_0
    const/4 p0, 0x0

    .line 51
    :goto_0
    if-eqz p0, :cond_1

    .line 52
    .line 53
    iget-object v0, p0, Landroid/content/pm/PackageItemInfo;->metaData:Landroid/os/Bundle;

    .line 54
    .line 55
    if-eqz v0, :cond_1

    .line 56
    .line 57
    const-string v2, "jobId"

    .line 58
    .line 59
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-eqz v0, :cond_1

    .line 64
    .line 65
    iget-object p0, p0, Landroid/content/pm/PackageItemInfo;->metaData:Landroid/os/Bundle;

    .line 66
    .line 67
    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    sget-object v0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->TAG:Ljava/lang/String;

    .line 72
    .line 73
    const-string v2, "Using BluetoothTestJob JobId from manifest: "

    .line 74
    .line 75
    invoke-static {p0, v2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    new-array v1, v1, [Ljava/lang/Object;

    .line 80
    .line 81
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    return p0

    .line 85
    :cond_1
    new-instance p0, Ljava/lang/RuntimeException;

    .line 86
    .line 87
    const-string v0, "Cannot get job id from manifest.  Make sure that the BluetoothTestJob is configured in the manifest."

    .line 88
    .line 89
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0
.end method

.method public static setOverrideJobId(I)V
    .locals 0

    .line 1
    sput p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->sOverrideJobId:I

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public onStartJob(Landroid/app/job/JobParameters;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandlerThread:Landroid/os/HandlerThread;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroid/os/HandlerThread;

    .line 6
    .line 7
    const-string v1, "BluetoothTestThread"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandlerThread:Landroid/os/HandlerThread;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandler:Landroid/os/Handler;

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    new-instance v0, Landroid/os/Handler;

    .line 22
    .line 23
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandlerThread:Landroid/os/HandlerThread;

    .line 24
    .line 25
    invoke-virtual {v1}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandler:Landroid/os/Handler;

    .line 33
    .line 34
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob;->mHandler:Landroid/os/Handler;

    .line 35
    .line 36
    new-instance v1, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;

    .line 37
    .line 38
    invoke-direct {v1, p0, p1}, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;-><init>(Lorg/altbeacon/bluetooth/BluetoothTestJob;Landroid/app/job/JobParameters;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    return p0
.end method

.method public onStopJob(Landroid/app/job/JobParameters;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
