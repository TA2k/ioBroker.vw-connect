.class public Lorg/altbeacon/beacon/startup/RegionBootstrap;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;
    }
.end annotation

.annotation runtime Ljava/lang/Deprecated;
.end annotation


# static fields
.field protected static final TAG:Ljava/lang/String; = "AppStarter"


# instance fields
.field private beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

.field private beaconManager:Lorg/altbeacon/beacon/BeaconManager;

.field private context:Landroid/content/Context;

.field private disabled:Z

.field private monitorNotifier:Lorg/altbeacon/beacon/MonitorNotifier;

.field private regions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation
.end field

.field private serviceConnected:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Lorg/altbeacon/beacon/MonitorNotifier;Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Lorg/altbeacon/beacon/MonitorNotifier;",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Region;",
            ">;)V"
        }
    .end annotation

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 16
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->disabled:Z

    .line 17
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    if-eqz p1, :cond_1

    .line 18
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    iput-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->context:Landroid/content/Context;

    .line 19
    iput-object p2, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->monitorNotifier:Lorg/altbeacon/beacon/MonitorNotifier;

    .line 20
    iput-object p3, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 21
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    move-result-object p1

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 22
    new-instance p1, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;

    invoke-direct {p1, p0, v0}, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;-><init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;I)V

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 23
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 24
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundMode(Z)V

    .line 25
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->bind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 26
    const-string p0, "Waiting for BeaconService connection"

    new-array p1, v0, [Ljava/lang/Object;

    const-string p2, "AppStarter"

    invoke-static {p2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "Application Context should not be null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Landroid/content/Context;Lorg/altbeacon/beacon/MonitorNotifier;Lorg/altbeacon/beacon/Region;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->disabled:Z

    .line 3
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    if-eqz p1, :cond_1

    .line 4
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    iput-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->context:Landroid/content/Context;

    .line 5
    iput-object p2, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->monitorNotifier:Lorg/altbeacon/beacon/MonitorNotifier;

    .line 6
    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 7
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    move-result-object p1

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 9
    new-instance p1, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;

    invoke-direct {p1, p0, v0}, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;-><init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;I)V

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 10
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 11
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundMode(Z)V

    .line 12
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->bind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 13
    const-string p0, "Waiting for BeaconService connection"

    new-array p1, v0, [Ljava/lang/Object;

    const-string p2, "AppStarter"

    invoke-static {p2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 14
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "Application Context should not be null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Lorg/altbeacon/beacon/startup/BootstrapNotifier;Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/altbeacon/beacon/startup/BootstrapNotifier;",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Region;",
            ">;)V"
        }
    .end annotation

    .line 43
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 44
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->disabled:Z

    .line 45
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    .line 46
    invoke-interface {p1}, Lorg/altbeacon/beacon/startup/BootstrapNotifier;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    if-eqz v1, :cond_1

    .line 47
    invoke-interface {p1}, Lorg/altbeacon/beacon/startup/BootstrapNotifier;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    iput-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->context:Landroid/content/Context;

    .line 48
    iput-object p2, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 49
    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->monitorNotifier:Lorg/altbeacon/beacon/MonitorNotifier;

    .line 50
    invoke-static {v1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    move-result-object p1

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 51
    new-instance p1, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;

    invoke-direct {p1, p0, v0}, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;-><init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;I)V

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 52
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 53
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundMode(Z)V

    .line 54
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->bind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 55
    const-string p0, "Waiting for BeaconService connection"

    new-array p1, v0, [Ljava/lang/Object;

    const-string p2, "AppStarter"

    invoke-static {p2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 56
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "The BootstrapNotifier instance is returning null from its getApplicationContext() method.  Have you implemented this method?"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Lorg/altbeacon/beacon/startup/BootstrapNotifier;Lorg/altbeacon/beacon/Region;)V
    .locals 2

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 29
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->disabled:Z

    .line 30
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    .line 31
    invoke-interface {p1}, Lorg/altbeacon/beacon/startup/BootstrapNotifier;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    if-eqz v1, :cond_1

    .line 32
    invoke-interface {p1}, Lorg/altbeacon/beacon/startup/BootstrapNotifier;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    iput-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->context:Landroid/content/Context;

    .line 33
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 34
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->monitorNotifier:Lorg/altbeacon/beacon/MonitorNotifier;

    .line 36
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->context:Landroid/content/Context;

    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    move-result-object p1

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 37
    new-instance p1, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;

    invoke-direct {p1, p0, v0}, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;-><init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;I)V

    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 38
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->isBackgroundModeUninitialized()Z

    move-result p1

    if-eqz p1, :cond_0

    .line 39
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundMode(Z)V

    .line 40
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->bind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 41
    const-string p0, "Waiting for BeaconService connection"

    new-array p1, v0, [Ljava/lang/Object;

    const-string p2, "AppStarter"

    invoke-static {p2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "The BootstrapNotifier instance is returning null from its getApplicationContext() method.  Have you implemented this method?"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static bridge synthetic a(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Lorg/altbeacon/beacon/BeaconManager;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic b(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic c(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Lorg/altbeacon/beacon/MonitorNotifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->monitorNotifier:Lorg/altbeacon/beacon/MonitorNotifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic d(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic e(Lorg/altbeacon/beacon/startup/RegionBootstrap;Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public addRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const-string v2, "AppStarter"

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->startMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catch_0
    move-exception v0

    .line 23
    const-string v3, "Can\'t add bootstrap region"

    .line 24
    .line 25
    new-array v1, v1, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {v0, v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const-string v0, "Adding a region: service not yet Connected"

    .line 32
    .line 33
    new-array v1, v1, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :goto_0
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 39
    .line 40
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    :cond_1
    return-void
.end method

.method public disable()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->disabled:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->disabled:Z

    .line 8
    .line 9
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Lorg/altbeacon/beacon/Region;

    .line 26
    .line 27
    iget-object v2, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 28
    .line 29
    invoke-virtual {v2, v1}, Lorg/altbeacon/beacon/BeaconManager;->stopMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catch_0
    move-exception v0

    .line 34
    const/4 v1, 0x0

    .line 35
    new-array v1, v1, [Ljava/lang/Object;

    .line 36
    .line 37
    const-string v2, "AppStarter"

    .line 38
    .line 39
    const-string v3, "Can\'t stop bootstrap regions"

    .line 40
    .line 41
    invoke-static {v0, v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 45
    .line 46
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconConsumer:Lorg/altbeacon/beacon/BeaconConsumer;

    .line 47
    .line 48
    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/BeaconManager;->unbind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method

.method public removeRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->serviceConnected:Z

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const-string v2, "AppStarter"

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->beaconManager:Lorg/altbeacon/beacon/BeaconManager;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lorg/altbeacon/beacon/BeaconManager;->stopMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catch_0
    move-exception v0

    .line 23
    const-string v3, "Can\'t stop bootstrap region"

    .line 24
    .line 25
    new-array v1, v1, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {v0, v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const-string v0, "Removing a region: service not yet Connected"

    .line 32
    .line 33
    new-array v1, v1, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :goto_0
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap;->regions:Ljava/util/List;

    .line 39
    .line 40
    invoke-interface {p0, p1}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    :cond_1
    return-void
.end method
