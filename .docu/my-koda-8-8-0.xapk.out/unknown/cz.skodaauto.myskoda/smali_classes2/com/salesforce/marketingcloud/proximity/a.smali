.class Lcom/salesforce/marketingcloud/proximity/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/BeaconConsumer;
.implements Lorg/altbeacon/beacon/MonitorNotifier;


# static fields
.field static final j:Ljava/lang/String; = "m:0-3=4c000215,i:4-19,i:20-21,i:22-23,p:24-24"

.field static final k:I = 0x79

.field static final l:Ljava/lang/String; = "0ahUKEwj"


# instance fields
.field final a:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation
.end field

.field private final b:Lorg/altbeacon/beacon/BeaconManager;

.field private final c:Landroid/content/Context;

.field private final d:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;"
        }
    .end annotation
.end field

.field private final e:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

.field private f:Z

.field private g:Z

.field private h:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaver;

.field private i:Landroid/content/Intent;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/proximity/a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Landroidx/collection/f;

    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 5
    iput-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    .line 6
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 7
    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 8
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    .line 9
    iput-object p2, p0, Lcom/salesforce/marketingcloud/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 10
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    move-result-object p2

    new-instance v0, Lorg/altbeacon/beacon/BeaconParser;

    const-string v1, "iBeacon"

    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/BeaconParser;-><init>(Ljava/lang/String;)V

    const-string v1, "m:0-3=4c000215,i:4-19,i:20-21,i:22-23,p:24-24"

    invoke-virtual {v0, v1}, Lorg/altbeacon/beacon/BeaconParser;->setBeaconLayout(Ljava/lang/String;)Lorg/altbeacon/beacon/BeaconParser;

    move-result-object v0

    invoke-interface {p2, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    const-wide/16 v0, 0x1388

    .line 11
    invoke-virtual {p1, v0, v1}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundScanPeriod(J)V

    const-wide/16 v0, 0x2710

    .line 12
    invoke-virtual {p1, v0, v1}, Lorg/altbeacon/beacon/BeaconManager;->setBackgroundBetweenScanPeriod(J)V

    .line 13
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/BeaconManager;->addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V

    return-void
.end method

.method private static a(Lorg/altbeacon/beacon/Region;)Lcom/salesforce/marketingcloud/proximity/c;
    .locals 4

    .line 4
    :try_start_0
    new-instance v0, Lcom/salesforce/marketingcloud/proximity/c;

    invoke-virtual {p0}, Lorg/altbeacon/beacon/Region;->getUniqueId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0}, Lorg/altbeacon/beacon/Region;->getId1()Lorg/altbeacon/beacon/Identifier;

    move-result-object v2

    invoke-virtual {v2}, Lorg/altbeacon/beacon/Identifier;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0}, Lorg/altbeacon/beacon/Region;->getId2()Lorg/altbeacon/beacon/Identifier;

    move-result-object v3

    invoke-virtual {v3}, Lorg/altbeacon/beacon/Identifier;->toInt()I

    move-result v3

    .line 5
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Region;->getId3()Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    invoke-virtual {p0}, Lorg/altbeacon/beacon/Identifier;->toInt()I

    move-result p0

    invoke-direct {v0, v1, v2, v3, p0}, Lcom/salesforce/marketingcloud/proximity/c;-><init>(Ljava/lang/String;Ljava/lang/String;II)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 6
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Unable to convert Region to BeaconRegion"

    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/proximity/c;)Lorg/altbeacon/beacon/Region;
    .locals 4

    .line 2
    new-instance v0, Lorg/altbeacon/beacon/Region;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/c;->m()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    move-result-object v2

    invoke-static {v2}, Lorg/altbeacon/beacon/Identifier;->fromUuid(Ljava/util/UUID;)Lorg/altbeacon/beacon/Identifier;

    move-result-object v2

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/c;->o()I

    move-result v3

    invoke-static {v3}, Lorg/altbeacon/beacon/Identifier;->fromInt(I)Lorg/altbeacon/beacon/Identifier;

    move-result-object v3

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/proximity/c;->p()I

    move-result p0

    invoke-static {p0}, Lorg/altbeacon/beacon/Identifier;->fromInt(I)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    invoke-direct {v0, v1, v2, v3, p0}, Lorg/altbeacon/beacon/Region;-><init>(Ljava/lang/String;Lorg/altbeacon/beacon/Identifier;Lorg/altbeacon/beacon/Identifier;Lorg/altbeacon/beacon/Identifier;)V

    return-object v0
.end method

.method private a()V
    .locals 3

    .line 32
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "clearAllMonitoredRegions"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_2

    .line 34
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Stop monitoring %d BeaconRegions"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 35
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lorg/altbeacon/beacon/Region;

    if-eqz v1, :cond_0

    .line 36
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/proximity/a;->b(Lorg/altbeacon/beacon/Region;)V

    goto :goto_0

    .line 37
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    invoke-interface {p0}, Ljava/util/Map;->clear()V

    :cond_2
    return-void
.end method

.method private synthetic a(Landroid/content/Intent;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 0

    .line 38
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V
    .locals 3

    if-eqz p1, :cond_0

    .line 7
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/c;

    .line 8
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->getSmallIconResId()I

    move-result v1

    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;->getChannelIdProvider()Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;

    move-result-object p1

    invoke-direct {v0, v1, p1}, Lcom/salesforce/marketingcloud/notifications/c;-><init>(ILcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationChannelIdProvider;)V

    .line 10
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 11
    const-string v1, "alert"

    const-string v2, "Searching for available beacons ..."

    invoke-virtual {p1, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    const-string v1, "_m"

    const-string v2, "0ahUKEwj"

    invoke-virtual {p1, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/j;->a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object p1

    .line 14
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    invoke-virtual {v0, v1, p1}, Lcom/salesforce/marketingcloud/notifications/c;->setupNotificationBuilder(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroidx/core/app/x;

    move-result-object p1

    .line 15
    invoke-virtual {p1}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    move-result-object p1

    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    move-result v0

    if-nez v0, :cond_0

    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    const/16 v0, 0x79

    invoke-virtual {p0, p1, v0}, Lorg/altbeacon/beacon/BeaconManager;->enableForegroundServiceScanning(Landroid/app/Notification;I)V

    :cond_0
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/proximity/a;Landroid/content/Intent;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/proximity/a;->a(Landroid/content/Intent;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V

    return-void
.end method

.method private b()V
    .locals 2

    const/4 v0, 0x1

    .line 1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->g:Z

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {v0, p0}, Lorg/altbeacon/beacon/BeaconManager;->bind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Waiting for BeaconService connection"

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method private b(Lorg/altbeacon/beacon/Region;)V
    .locals 2

    .line 9
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->stopMonitoring(Lorg/altbeacon/beacon/Region;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 10
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v1, "Failed to stop monitoring %s"

    invoke-static {v0, p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method private c()V
    .locals 5

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v1, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v2, "monitorNewRegions"

    .line 7
    .line 8
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_2

    .line 18
    .line 19
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lcom/salesforce/marketingcloud/proximity/c;

    .line 36
    .line 37
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    .line 38
    .line 39
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-interface {v2, v3}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-nez v2, :cond_0

    .line 48
    .line 49
    invoke-static {v1}, Lcom/salesforce/marketingcloud/proximity/a;->a(Lcom/salesforce/marketingcloud/proximity/c;)Lorg/altbeacon/beacon/Region;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    iget-object v3, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    .line 54
    .line 55
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    invoke-interface {v3, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    sget-object v3, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/proximity/c;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    const-string v4, "Now monitoring [%s]"

    .line 73
    .line 74
    invoke-static {v3, v4, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    .line 78
    .line 79
    invoke-virtual {v1, v2}, Lorg/altbeacon/beacon/BeaconManager;->startMonitoring(Lorg/altbeacon/beacon/Region;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_0
    sget-object v2, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 84
    .line 85
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    const-string v3, "Region [%s] already monitored by SDK"

    .line 90
    .line 91
    invoke-static {v2, v3, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 98
    .line 99
    .line 100
    :cond_2
    return-void
.end method


# virtual methods
.method public a(Ljava/util/List;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation

    .line 18
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "monitorBeaconRegions() - [%d regions]"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->e:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/proximity/a;->a(Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;)V

    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    invoke-virtual {v1, p0}, Lorg/altbeacon/beacon/BeaconManager;->addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V

    .line 21
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    return-void

    .line 22
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    monitor-enter v1

    .line 23
    :try_start_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->clear()V

    .line 24
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    invoke-interface {v2, p1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 25
    iget-boolean p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->f:Z

    if-eqz p1, :cond_1

    .line 26
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/a;->c()V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 27
    :cond_1
    const-string p1, "Not yet connected.  Will register Beacons once complete."

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    invoke-static {v0, p1, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    iget-boolean p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->g:Z

    if-nez p1, :cond_2

    .line 29
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/a;->b()V

    .line 30
    :cond_2
    :goto_0
    monitor-exit v1

    return-void

    .line 31
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public b(Ljava/util/List;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/proximity/c;",
            ">;)V"
        }
    .end annotation

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "unmonitorBeaconRegions() - [%d regions]"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 5
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_1

    .line 6
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/proximity/c;

    .line 7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->a:Ljava/util/Map;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/proximity/c;->n()Ljava/lang/String;

    move-result-object v2

    invoke-interface {v1, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    invoke-static {v0}, Lcom/salesforce/marketingcloud/proximity/a;->a(Lcom/salesforce/marketingcloud/proximity/c;)Lorg/altbeacon/beacon/Region;

    move-result-object v0

    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/proximity/a;->b(Lorg/altbeacon/beacon/Region;)V

    goto :goto_0

    :cond_1
    :goto_1
    return-void
.end method

.method public bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z
    .locals 1

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->i:Landroid/content/Intent;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2, p3}, Landroid/content/Context;->bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public d()V
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v3, "stopMonitoring()"

    .line 7
    .line 8
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->f:Z

    .line 15
    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/a;->a()V

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    .line 22
    .line 23
    invoke-virtual {v2, p0}, Lorg/altbeacon/beacon/BeaconManager;->unbind(Lorg/altbeacon/beacon/BeaconConsumer;)V

    .line 24
    .line 25
    .line 26
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    .line 27
    .line 28
    invoke-virtual {v2, p0}, Lorg/altbeacon/beacon/BeaconManager;->removeMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)Z

    .line 29
    .line 30
    .line 31
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->h:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaver;

    .line 32
    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 36
    .line 37
    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v2, Landroid/app/Application;

    .line 42
    .line 43
    iget-object v3, p0, Lcom/salesforce/marketingcloud/proximity/a;->h:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaver;

    .line 44
    .line 45
    invoke-virtual {v2, v3}, Landroid/app/Application;->unregisterActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    goto :goto_2

    .line 51
    :cond_0
    :goto_0
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->f:Z

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 55
    .line 56
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 57
    .line 58
    .line 59
    :goto_1
    monitor-exit v0

    .line 60
    return-void

    .line 61
    :goto_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    throw p0
.end method

.method public didDetermineStateForRegion(ILorg/altbeacon/beacon/Region;)V
    .locals 3

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    filled-new-array {v1, p2}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const-string v2, "didDetermineStateForRegion(%d, %s)"

    .line 12
    .line 13
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isReady()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_0

    .line 21
    .line 22
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isInitializing()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    new-array p0, p0, [Ljava/lang/Object;

    .line 30
    .line 31
    const-string p1, "MarketingCloudSdk#init must be called in your application\'s onCreate"

    .line 32
    .line 33
    invoke-static {v0, p1, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    new-instance v0, Landroid/content/Intent;

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    if-ne p1, v1, :cond_1

    .line 41
    .line 42
    const-string p1, "com.salesforce.marketingcloud.proximity.BEACON_REGION_ENTERED"

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    const-string p1, "com.salesforce.marketingcloud.proximity.BEACON_REGION_EXITED"

    .line 46
    .line 47
    :goto_0
    invoke-direct {v0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-static {p2}, Lcom/salesforce/marketingcloud/proximity/a;->a(Lorg/altbeacon/beacon/Region;)Lcom/salesforce/marketingcloud/proximity/c;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    const-string p2, "beaconRegion"

    .line 55
    .line 56
    invoke-virtual {v0, p2, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isReady()Z

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-eqz p2, :cond_2

    .line 65
    .line 66
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 67
    .line 68
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    invoke-virtual {p1, p2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-virtual {p0, p1}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_2
    new-instance p2, Lcom/salesforce/marketingcloud/proximity/f;

    .line 81
    .line 82
    invoke-direct {p2, p0, p1}, Lcom/salesforce/marketingcloud/proximity/f;-><init>(Lcom/salesforce/marketingcloud/proximity/a;Landroid/content/Intent;)V

    .line 83
    .line 84
    .line 85
    invoke-static {p2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 86
    .line 87
    .line 88
    return-void
.end method

.method public didEnterRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 1

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "didEnterRegion(%s)"

    .line 8
    .line 9
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public didExitRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 1

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "didExitRegion(%s)"

    .line 8
    .line 9
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public getApplicationContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public onBeaconServiceConnect()V
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/proximity/e;->h:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v3, "onBeaconServiceConnect"

    .line 7
    .line 8
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->d:Ljava/util/List;

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    new-instance v2, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaver;

    .line 15
    .line 16
    iget-object v3, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 17
    .line 18
    invoke-direct {v2, v3}, Lorg/altbeacon/beacon/powersave/BackgroundPowerSaver;-><init>(Landroid/content/Context;)V

    .line 19
    .line 20
    .line 21
    iput-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->h:Lorg/altbeacon/beacon/powersave/BackgroundPowerSaver;

    .line 22
    .line 23
    iget-object v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->b:Lorg/altbeacon/beacon/BeaconManager;

    .line 24
    .line 25
    invoke-virtual {v2, p0}, Lorg/altbeacon/beacon/BeaconManager;->addMonitorNotifier(Lorg/altbeacon/beacon/MonitorNotifier;)V

    .line 26
    .line 27
    .line 28
    const/4 v2, 0x1

    .line 29
    iput-boolean v2, p0, Lcom/salesforce/marketingcloud/proximity/a;->f:Z

    .line 30
    .line 31
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/proximity/a;->g:Z

    .line 32
    .line 33
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/proximity/a;->c()V

    .line 34
    .line 35
    .line 36
    monitor-exit v0

    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0
.end method

.method public unbindService(Landroid/content/ServiceConnection;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroid/content/Context;->unbindService(Landroid/content/ServiceConnection;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->c:Landroid/content/Context;

    .line 7
    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/proximity/a;->i:Landroid/content/Intent;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Landroid/content/Context;->stopService(Landroid/content/Intent;)Z

    .line 11
    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->f:Z

    .line 15
    .line 16
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/proximity/a;->g:Z

    .line 17
    .line 18
    return-void
.end method
