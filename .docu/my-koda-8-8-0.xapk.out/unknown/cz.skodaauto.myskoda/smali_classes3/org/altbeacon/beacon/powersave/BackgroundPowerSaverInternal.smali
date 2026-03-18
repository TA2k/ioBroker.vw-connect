.class public Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/f;


# annotations
.annotation build Landroid/annotation/TargetApi;
    value = 0x12
.end annotation


# static fields
.field private static final TAG:Ljava/lang/String; = "BackgroundPowerSaver"


# instance fields
.field private final applicationContext:Landroid/content/Context;

.field private final beaconManager:Lorg/altbeacon/beacon/BeaconManager;

.field private final screenOffReceiver:Landroid/content/BroadcastReceiver;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal$1;-><init>(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->screenOffReceiver:Landroid/content/BroadcastReceiver;

    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->applicationContext:Landroid/content/Context;

    .line 16
    .line 17
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 22
    .line 23
    new-instance p1, Landroid/os/Handler;

    .line 24
    .line 25
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-direct {p1, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Lm8/o;

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    invoke-direct {v0, p0, v1}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static synthetic a(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->lambda$new$0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->applicationContext:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic c(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)Landroid/content/BroadcastReceiver;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->screenOffReceiver:Landroid/content/BroadcastReceiver;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic d(Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;)V
    .locals 1

    .line 1
    const-string v0, "the screen going off"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->inferBackground(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private inferBackground(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-string v0, "We have inferred by "

    .line 10
    .line 11
    const-string v1, " that we are in the background."

    .line 12
    .line 13
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const/4 v0, 0x0

    .line 18
    new-array v0, v0, [Ljava/lang/Object;

    .line 19
    .line 20
    const-string v1, "BackgroundPowerSaver"

    .line 21
    .line 22
    invoke-static {v1, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 26
    .line 27
    const/4 p1, 0x1

    .line 28
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundModeInternal(Z)V

    .line 29
    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method private lambda$new$0()V
    .locals 1

    .line 1
    sget-object v0, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 2
    .line 3
    iget-object v0, v0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Landroidx/lifecycle/z;->a(Landroidx/lifecycle/w;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private methodCalledByApplicationOnCreate()Z
    .locals 7

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Thread;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-class v0, Landroid/app/Application;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    array-length v1, p0

    .line 16
    const/4 v2, 0x0

    .line 17
    move v3, v2

    .line 18
    :goto_0
    if-ge v3, v1, :cond_3

    .line 19
    .line 20
    aget-object v4, p0, v3

    .line 21
    .line 22
    invoke-virtual {v4}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    const-string v6, "onCreate"

    .line 27
    .line 28
    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_2

    .line 33
    .line 34
    invoke-virtual {v4}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    const/4 v6, 0x1

    .line 43
    if-eqz v5, :cond_0

    .line 44
    .line 45
    return v6

    .line 46
    :cond_0
    invoke-virtual {v4}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    if-eqz v5, :cond_2

    .line 51
    .line 52
    :try_start_0
    invoke-virtual {v4}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-static {v4}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    :cond_1
    invoke-virtual {v4}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    if-eqz v4, :cond_2

    .line 65
    .line 66
    invoke-virtual {v4}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v5
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 74
    if-eqz v5, :cond_1

    .line 75
    .line 76
    return v6

    .line 77
    :catch_0
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    return v2
.end method


# virtual methods
.method public enableDefaultBackgroundStateInference()V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    invoke-direct {p0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->methodCalledByApplicationOnCreate()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const-string v0, "application.onCreate in the call stack"

    .line 16
    .line 17
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->inferBackground(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->applicationContext:Landroid/content/Context;

    .line 22
    .line 23
    const-string v1, "power"

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Landroid/os/PowerManager;

    .line 30
    .line 31
    invoke-virtual {v0}, Landroid/os/PowerManager;->isInteractive()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    const-string v0, "the screen being off"

    .line 38
    .line 39
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->inferBackground(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    new-instance v0, Landroid/content/IntentFilter;

    .line 44
    .line 45
    const-string v1, "android.intent.action.SCREEN_OFF"

    .line 46
    .line 47
    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-object v1, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->applicationContext:Landroid/content/Context;

    .line 51
    .line 52
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    iget-object v2, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->screenOffReceiver:Landroid/content/BroadcastReceiver;

    .line 57
    .line 58
    invoke-virtual {v1, v2, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 59
    .line 60
    .line 61
    :cond_2
    :goto_0
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 62
    .line 63
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    if-eqz p0, :cond_3

    .line 68
    .line 69
    const/4 p0, 0x0

    .line 70
    new-array p0, p0, [Ljava/lang/Object;

    .line 71
    .line 72
    const-string v0, "BackgroundPowerSaver"

    .line 73
    .line 74
    const-string v1, "Background mode not set.  We assume we are in the foreground."

    .line 75
    .line 76
    invoke-static {v0, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_3
    return-void
.end method

.method public bridge synthetic onCreate(Landroidx/lifecycle/x;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroidx/lifecycle/f;->onCreate(Landroidx/lifecycle/x;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onDestroy(Landroidx/lifecycle/x;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroidx/lifecycle/f;->onDestroy(Landroidx/lifecycle/x;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onPause(Landroidx/lifecycle/x;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroidx/lifecycle/f;->onPause(Landroidx/lifecycle/x;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic onResume(Landroidx/lifecycle/x;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroidx/lifecycle/f;->onResume(Landroidx/lifecycle/x;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public onStart(Landroidx/lifecycle/x;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Landroidx/lifecycle/f;->onStart(Landroidx/lifecycle/x;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    new-array v0, p1, [Ljava/lang/Object;

    .line 6
    .line 7
    const-string v1, "BackgroundPowerSaver"

    .line 8
    .line 9
    const-string v2, "setting foreground mode"

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundMode(Z)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->applicationContext:Landroid/content/Context;

    .line 20
    .line 21
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->retryForegroundServiceScanning()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public onStop(Landroidx/lifecycle/x;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroidx/lifecycle/f;->onStop(Landroidx/lifecycle/x;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    new-array p1, p1, [Ljava/lang/Object;

    .line 6
    .line 7
    const-string v0, "BackgroundPowerSaver"

    .line 8
    .line 9
    const-string v1, "setting background mode"

    .line 10
    .line 11
    invoke-static {v0, v1, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaverInternal;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundMode(Z)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
