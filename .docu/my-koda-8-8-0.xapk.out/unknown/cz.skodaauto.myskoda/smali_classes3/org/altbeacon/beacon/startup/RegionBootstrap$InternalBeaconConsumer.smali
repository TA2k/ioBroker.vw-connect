.class Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/BeaconConsumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/startup/RegionBootstrap;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "InternalBeaconConsumer"
.end annotation


# instance fields
.field private serviceIntent:Landroid/content/Intent;

.field final synthetic this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;


# direct methods
.method private constructor <init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;)V
    .locals 0

    .line 2
    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;-><init>(Lorg/altbeacon/beacon/startup/RegionBootstrap;)V

    return-void
.end method


# virtual methods
.method public bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z
    .locals 1

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->serviceIntent:Landroid/content/Intent;

    .line 2
    .line 3
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 4
    .line 5
    invoke-static {v0}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->b(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Landroid/content/Context;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0, p1}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 13
    .line 14
    invoke-static {p0}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->b(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Landroid/content/Context;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0, p1, p2, p3}, Landroid/content/Context;->bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0
.end method

.method public getApplicationContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->b(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public onBeaconServiceConnect()V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v2, "AppStarter"

    .line 5
    .line 6
    const-string v3, "Activating background region monitoring"

    .line 7
    .line 8
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 12
    .line 13
    invoke-static {v1}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->a(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Lorg/altbeacon/beacon/BeaconManager;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-object v3, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 18
    .line 19
    invoke-static {v3}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->c(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Lorg/altbeacon/beacon/MonitorNotifier;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v1, v3}, Lorg/altbeacon/beacon/BeaconManager;->addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    invoke-static {v1, v3}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->e(Lorg/altbeacon/beacon/startup/RegionBootstrap;Z)V

    .line 30
    .line 31
    .line 32
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 33
    .line 34
    invoke-static {v1}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->d(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_0

    .line 47
    .line 48
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    check-cast v3, Lorg/altbeacon/beacon/Region;

    .line 53
    .line 54
    const-string v4, "Background region monitoring activated for region %s"

    .line 55
    .line 56
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    invoke-static {v2, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object v4, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 64
    .line 65
    invoke-static {v4}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->a(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Lorg/altbeacon/beacon/BeaconManager;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    invoke-virtual {v4, v3}, Lorg/altbeacon/beacon/BeaconManager;->startMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :catch_0
    move-exception p0

    .line 74
    goto :goto_1

    .line 75
    :cond_0
    return-void

    .line 76
    :goto_1
    const-string v1, "Can\'t set up bootstrap regions"

    .line 77
    .line 78
    new-array v0, v0, [Ljava/lang/Object;

    .line 79
    .line 80
    invoke-static {p0, v2, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-void
.end method

.method public unbindService(Landroid/content/ServiceConnection;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 2
    .line 3
    invoke-static {v0}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->b(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p1}, Landroid/content/Context;->unbindService(Landroid/content/ServiceConnection;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 11
    .line 12
    invoke-static {p1}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->b(Lorg/altbeacon/beacon/startup/RegionBootstrap;)Landroid/content/Context;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iget-object v0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->serviceIntent:Landroid/content/Intent;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Landroid/content/Context;->stopService(Landroid/content/Intent;)Z

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lorg/altbeacon/beacon/startup/RegionBootstrap$InternalBeaconConsumer;->this$0:Lorg/altbeacon/beacon/startup/RegionBootstrap;

    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    invoke-static {p0, p1}, Lorg/altbeacon/beacon/startup/RegionBootstrap;->e(Lorg/altbeacon/beacon/startup/RegionBootstrap;Z)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
