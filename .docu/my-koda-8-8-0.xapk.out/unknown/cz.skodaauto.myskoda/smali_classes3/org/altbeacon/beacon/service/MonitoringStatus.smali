.class public Lorg/altbeacon/beacon/service/MonitoringStatus;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final MAX_REGIONS_FOR_STATUS_PRESERVATION:I = 0x32

.field private static final MAX_STATUS_PRESERVATION_FILE_AGE_TO_RESTORE_SECS:I = 0x384

.field private static final SINGLETON_LOCK:Ljava/lang/Object;

.field public static final STATUS_PRESERVATION_FILE_NAME:Ljava/lang/String; = "org.altbeacon.beacon.service.monitoring_status_state"

.field private static final TAG:Ljava/lang/String; = "MonitoringStatus"

.field private static volatile sInstance:Lorg/altbeacon/beacon/service/MonitoringStatus;


# instance fields
.field private inactiveRegionsExist:Z

.field private mContext:Landroid/content/Context;

.field private mRegionsStatesMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lorg/altbeacon/beacon/Region;",
            "Lorg/altbeacon/beacon/service/RegionMonitoringState;",
            ">;"
        }
    .end annotation
.end field

.field private mStatePreservationIsOn:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->SINGLETON_LOCK:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->inactiveRegionsExist:Z

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z

    .line 9
    .line 10
    iput-object p1, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 11
    .line 12
    return-void
.end method

.method private addLocalRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)Lorg/altbeacon/beacon/service/RegionMonitoringState;
    .locals 5

    .line 3
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    move-result-object v0

    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_3

    .line 4
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lorg/altbeacon/beacon/Region;

    .line 5
    invoke-virtual {v2, p1}, Lorg/altbeacon/beacon/Region;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    .line 6
    invoke-virtual {v2, p1}, Lorg/altbeacon/beacon/Region;->hasSameIdentifiers(Lorg/altbeacon/beacon/Region;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 7
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->inactiveRegionsExist:Z

    if-eqz v0, :cond_1

    goto :goto_0

    .line 8
    :cond_1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    move-result-object p0

    invoke-interface {p0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    return-object p0

    .line 9
    :cond_2
    sget-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Replacing region with unique identifier "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Lorg/altbeacon/beacon/Region;->getUniqueId()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    new-array v4, v1, [Ljava/lang/Object;

    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Old definition: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    new-array v3, v1, [Ljava/lang/Object;

    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "New definition: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    new-array v3, v1, [Ljava/lang/Object;

    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    const-string v2, "clearing state"

    new-array v3, v1, [Ljava/lang/Object;

    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 13
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    move-result-object v0

    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    :cond_3
    :goto_0
    new-instance v0, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    invoke-direct {v0, p2}, Lorg/altbeacon/beacon/service/RegionMonitoringState;-><init>(Lorg/altbeacon/beacon/service/Callback;)V

    .line 15
    sget-object p2, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Region marked as active: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    new-array v1, v1, [Ljava/lang/Object;

    invoke-static {p2, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p2, 0x1

    .line 16
    invoke-virtual {v0, p2}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->setActiveSinceAppLaunch(Z)V

    .line 17
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    move-result-object p0

    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0
.end method

.method public static getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;
    .locals 2

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->sInstance:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object v1, Lorg/altbeacon/beacon/service/MonitoringStatus;->SINGLETON_LOCK:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    sget-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->sInstance:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-direct {v0, p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;-><init>(Landroid/content/Context;)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->sInstance:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    :goto_0
    monitor-exit v1

    .line 27
    return-object v0

    .line 28
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    throw p0

    .line 30
    :cond_1
    return-object v0
.end method

.method private getRegionsStateMap()Ljava/util/Map;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lorg/altbeacon/beacon/Region;",
            "Lorg/altbeacon/beacon/service/RegionMonitoringState;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mRegionsStatesMap:Ljava/util/Map;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->restoreOrInitializeMonitoringStatus()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mRegionsStatesMap:Ljava/util/Map;

    .line 9
    .line 10
    return-object p0
.end method

.method private regionsMatchingTo(Lorg/altbeacon/beacon/Beacon;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/altbeacon/beacon/Beacon;",
            ")",
            "Ljava/util/List<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Lorg/altbeacon/beacon/Region;

    .line 25
    .line 26
    invoke-virtual {v1, p1}, Lorg/altbeacon/beacon/Region;->matchesBeacon(Lorg/altbeacon/beacon/Beacon;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_0

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    sget-object v2, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 37
    .line 38
    const-string v3, "This region (%s) does not match beacon: %s"

    .line 39
    .line 40
    filled-new-array {v1, p1}, [Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    return-object v0
.end method

.method private restoreOrInitializeMonitoringStatus()V
    .locals 6

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getLastMonitoringStatusUpdateTime()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    sub-long/2addr v0, v2

    .line 10
    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mRegionsStatesMap:Ljava/util/Map;

    .line 16
    .line 17
    iget-boolean v2, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    sget-object p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 23
    .line 24
    const-string v0, "Not restoring monitoring state because persistence is disabled"

    .line 25
    .line 26
    new-array v1, v3, [Ljava/lang/Object;

    .line 27
    .line 28
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    const-wide/32 v4, 0xdbba0

    .line 33
    .line 34
    .line 35
    cmp-long v2, v0, v4

    .line 36
    .line 37
    if-lez v2, :cond_1

    .line 38
    .line 39
    sget-object p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 40
    .line 41
    const-string v2, "Not restoring monitoring state because it was recorded too many milliseconds ago: "

    .line 42
    .line 43
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    new-array v1, v3, [Ljava/lang/Object;

    .line 48
    .line 49
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->restoreMonitoringStatus()V

    .line 54
    .line 55
    .line 56
    sget-object p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 57
    .line 58
    const-string v0, "Done restoring monitoring status"

    .line 59
    .line 60
    new-array v1, v3, [Ljava/lang/Object;

    .line 61
    .line 62
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public addLocalRegion(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;
    .locals 2

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/service/Callback;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/service/Callback;-><init>(Ljava/lang/String;)V

    .line 2
    invoke-direct {p0, p1, v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->addLocalRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    move-result-object p0

    return-object p0
.end method

.method public declared-synchronized addRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)V
    .locals 0

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0, p1, p2}, Lorg/altbeacon/beacon/service/MonitoringStatus;->addLocalRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    .line 7
    .line 8
    monitor-exit p0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p1

    .line 11
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 12
    throw p1
.end method

.method public declared-synchronized clear()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 3
    .line 4
    const-string v1, "org.altbeacon.beacon.service.monitoring_status_state"

    .line 5
    .line 6
    invoke-virtual {v0, v1}, Landroid/content/Context;->deleteFile(Ljava/lang/String;)Z

    .line 7
    .line 8
    .line 9
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {v0}, Ljava/util/Map;->clear()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    .line 16
    monitor-exit p0

    .line 17
    return-void

    .line 18
    :catchall_0
    move-exception v0

    .line 19
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    throw v0
.end method

.method public declared-synchronized getActiveRegions()Ljava/util/Set;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Ljava/util/HashSet;

    .line 3
    .line 4
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lorg/altbeacon/beacon/Region;

    .line 30
    .line 31
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 40
    .line 41
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getActiveSinceAppLaunch()Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_0

    .line 46
    .line 47
    invoke-virtual {v0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :catchall_0
    move-exception v0

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    monitor-exit p0

    .line 54
    return-object v0

    .line 55
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 56
    throw v0
.end method

.method public getLastMonitoringStatusUpdateTime()J
    .locals 2

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    const-string v0, "org.altbeacon.beacon.service.monitoring_status_state"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/content/Context;->getFileStreamPath(Ljava/lang/String;)Ljava/io/File;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/io/File;->lastModified()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public declared-synchronized insideAnyRegion()Z
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lorg/altbeacon/beacon/Region;

    .line 21
    .line 22
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->stateOf(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getInside()Z

    .line 29
    .line 30
    .line 31
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    const/4 v2, 0x1

    .line 33
    if-ne v1, v2, :cond_0

    .line 34
    .line 35
    monitor-exit p0

    .line 36
    return v2

    .line 37
    :catchall_0
    move-exception v0

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    monitor-exit p0

    .line 40
    const/4 p0, 0x0

    .line 41
    return p0

    .line 42
    :goto_0
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 43
    throw v0
.end method

.method public isStatePreservationOn()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z

    .line 2
    .line 3
    return p0
.end method

.method public declared-synchronized purgeInactiveRegions()V
    .locals 7

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->inactiveRegionsExist:Z

    .line 3
    .line 4
    if-eqz v0, :cond_3

    .line 5
    .line 6
    sget-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 7
    .line 8
    const-string v1, "Time to purge inactive regions."

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    new-array v3, v2, [Ljava/lang/Object;

    .line 12
    .line 13
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    move v3, v2

    .line 34
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    check-cast v4, Lorg/altbeacon/beacon/Region;

    .line 45
    .line 46
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    invoke-interface {v5, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    check-cast v5, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 55
    .line 56
    invoke-virtual {v5}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getActiveSinceAppLaunch()Z

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    if-eqz v6, :cond_0

    .line 61
    .line 62
    invoke-virtual {v0, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception v0

    .line 67
    goto :goto_1

    .line 68
    :cond_0
    sget-object v3, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 69
    .line 70
    new-instance v5, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 73
    .line 74
    .line 75
    const-string v6, "We will purge this inactive region: "

    .line 76
    .line 77
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    new-array v5, v2, [Ljava/lang/Object;

    .line 88
    .line 89
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    const/4 v3, 0x1

    .line 93
    goto :goto_0

    .line 94
    :cond_1
    if-eqz v3, :cond_2

    .line 95
    .line 96
    iput-object v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mRegionsStatesMap:Ljava/util/Map;

    .line 97
    .line 98
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V

    .line 99
    .line 100
    .line 101
    :cond_2
    iput-boolean v2, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->inactiveRegionsExist:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 102
    .line 103
    :cond_3
    monitor-exit p0

    .line 104
    return-void

    .line 105
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 106
    throw v0
.end method

.method public declared-synchronized regions()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/Region;",
            ">;"
        }
    .end annotation

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    monitor-exit p0

    .line 11
    return-object v0

    .line 12
    :catchall_0
    move-exception v0

    .line 13
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 14
    throw v0
.end method

.method public declared-synchronized regionsCount()I
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    monitor-exit p0

    .line 11
    return v0

    .line 12
    :catchall_0
    move-exception v0

    .line 13
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 14
    throw v0
.end method

.method public removeLocalRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public declared-synchronized removeRegion(Lorg/altbeacon/beacon/Region;)V
    .locals 0

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->removeLocalRegion(Lorg/altbeacon/beacon/Region;)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    .line 7
    .line 8
    monitor-exit p0

    .line 9
    return-void

    .line 10
    :catchall_0
    move-exception p1

    .line 11
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 12
    throw p1
.end method

.method public restoreMonitoringStatus()V
    .locals 9

    .line 1
    const-string v0, "Restored region monitoring state for "

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    :try_start_0
    iget-object v3, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 6
    .line 7
    const-string v4, "org.altbeacon.beacon.service.monitoring_status_state"

    .line 8
    .line 9
    invoke-virtual {v3, v4}, Landroid/content/Context;->openFileInput(Ljava/lang/String;)Ljava/io/FileInputStream;

    .line 10
    .line 11
    .line 12
    move-result-object v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_3
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 13
    :try_start_1
    new-instance v4, Ljava/io/ObjectInputStream;

    .line 14
    .line 15
    invoke-direct {v4, v3}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/ClassCastException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 16
    .line 17
    .line 18
    :try_start_2
    invoke-virtual {v4}, Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Ljava/util/Map;

    .line 23
    .line 24
    sget-object v5, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 25
    .line 26
    new-instance v6, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    invoke-direct {v6, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {v2}, Ljava/util/Map;->size()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string v0, " regions."

    .line 39
    .line 40
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    new-array v6, v1, [Ljava/lang/Object;

    .line 48
    .line 49
    invoke-static {v5, v0, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v2}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_0

    .line 65
    .line 66
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    check-cast v5, Lorg/altbeacon/beacon/Region;

    .line 71
    .line 72
    sget-object v6, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 73
    .line 74
    new-instance v7, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 77
    .line 78
    .line 79
    const-string v8, "Region  "

    .line 80
    .line 81
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v8, " uniqueId: "

    .line 88
    .line 89
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v5}, Lorg/altbeacon/beacon/Region;->getUniqueId()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v8, " state: "

    .line 100
    .line 101
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-interface {v2, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    new-array v7, v1, [Ljava/lang/Object;

    .line 116
    .line 117
    invoke-static {v6, v5, v7}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_0

    .line 121
    :catchall_0
    move-exception p0

    .line 122
    :goto_1
    move-object v2, v3

    .line 123
    goto/16 :goto_8

    .line 124
    .line 125
    :catch_0
    move-exception p0

    .line 126
    :goto_2
    move-object v2, v3

    .line 127
    goto :goto_5

    .line 128
    :cond_0
    invoke-interface {v2}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    :cond_1
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    if-eqz v5, :cond_2

    .line 141
    .line 142
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v5

    .line 146
    check-cast v5, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 147
    .line 148
    const/4 v6, 0x1

    .line 149
    iput-boolean v6, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->inactiveRegionsExist:Z

    .line 150
    .line 151
    invoke-virtual {v5}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getInside()Z

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    if-eqz v6, :cond_1

    .line 156
    .line 157
    invoke-virtual {v5}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->markInside()Z

    .line 158
    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_2
    iget-object p0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mRegionsStatesMap:Ljava/util/Map;

    .line 162
    .line 163
    invoke-interface {p0, v2}, Ljava/util/Map;->putAll(Ljava/util/Map;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/ClassCastException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 164
    .line 165
    .line 166
    if-eqz v3, :cond_3

    .line 167
    .line 168
    :try_start_3
    invoke-virtual {v3}, Ljava/io/FileInputStream;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 169
    .line 170
    .line 171
    :catch_1
    :cond_3
    :goto_4
    :try_start_4
    invoke-virtual {v4}, Ljava/io/ObjectInputStream;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_5

    .line 172
    .line 173
    .line 174
    goto :goto_7

    .line 175
    :catchall_1
    move-exception p0

    .line 176
    move-object v4, v2

    .line 177
    goto :goto_1

    .line 178
    :catch_2
    move-exception p0

    .line 179
    move-object v4, v2

    .line 180
    goto :goto_2

    .line 181
    :catchall_2
    move-exception p0

    .line 182
    move-object v4, v2

    .line 183
    goto :goto_8

    .line 184
    :catch_3
    move-exception p0

    .line 185
    move-object v4, v2

    .line 186
    :goto_5
    :try_start_5
    instance-of v0, p0, Ljava/io/InvalidClassException;

    .line 187
    .line 188
    if-eqz v0, :cond_4

    .line 189
    .line 190
    sget-object p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 191
    .line 192
    const-string v0, "Serialized Monitoring State has wrong class. Just ignoring saved state..."

    .line 193
    .line 194
    new-array v1, v1, [Ljava/lang/Object;

    .line 195
    .line 196
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_6

    .line 200
    :catchall_3
    move-exception p0

    .line 201
    goto :goto_8

    .line 202
    :cond_4
    sget-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 203
    .line 204
    const-string v1, "Deserialization exception, message: %s"

    .line 205
    .line 206
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    invoke-static {v0, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 215
    .line 216
    .line 217
    :goto_6
    if-eqz v2, :cond_5

    .line 218
    .line 219
    :try_start_6
    invoke-virtual {v2}, Ljava/io/FileInputStream;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_4

    .line 220
    .line 221
    .line 222
    :catch_4
    :cond_5
    if-eqz v4, :cond_6

    .line 223
    .line 224
    goto :goto_4

    .line 225
    :catch_5
    :cond_6
    :goto_7
    return-void

    .line 226
    :goto_8
    if-eqz v2, :cond_7

    .line 227
    .line 228
    :try_start_7
    invoke-virtual {v2}, Ljava/io/FileInputStream;->close()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_6

    .line 229
    .line 230
    .line 231
    :catch_6
    :cond_7
    if-eqz v4, :cond_8

    .line 232
    .line 233
    :try_start_8
    invoke-virtual {v4}, Ljava/io/ObjectInputStream;->close()V
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_7

    .line 234
    .line 235
    .line 236
    :catch_7
    :cond_8
    throw p0
.end method

.method public saveMonitoringStatusIfOn()V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_5

    .line 6
    .line 7
    :cond_0
    sget-object v0, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 8
    .line 9
    const-string v1, "saveMonitoringStatusIfOn()"

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    new-array v3, v2, [Ljava/lang/Object;

    .line 13
    .line 14
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/16 v3, 0x32

    .line 26
    .line 27
    const-string v4, "org.altbeacon.beacon.service.monitoring_status_state"

    .line 28
    .line 29
    if-le v1, v3, :cond_1

    .line 30
    .line 31
    const-string v1, "Too many regions being monitored.  Will not persist region state"

    .line 32
    .line 33
    new-array v2, v2, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 39
    .line 40
    invoke-virtual {p0, v4}, Landroid/content/Context;->deleteFile(Ljava/lang/String;)Z

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    const/4 v0, 0x0

    .line 45
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 46
    .line 47
    invoke-virtual {v1, v4, v2}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;

    .line 48
    .line 49
    .line 50
    move-result-object v1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_3
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 51
    :try_start_1
    new-instance v2, Ljava/io/ObjectOutputStream;

    .line 52
    .line 53
    invoke-direct {v2, v1}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 54
    .line 55
    .line 56
    :try_start_2
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    new-instance v0, Ljava/util/HashMap;

    .line 61
    .line 62
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 63
    .line 64
    .line 65
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_2

    .line 78
    .line 79
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    check-cast v4, Lorg/altbeacon/beacon/Region;

    .line 84
    .line 85
    invoke-interface {p0, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    check-cast v5, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 90
    .line 91
    invoke-virtual {v0, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :catchall_0
    move-exception p0

    .line 96
    :goto_1
    move-object v0, v1

    .line 97
    goto :goto_6

    .line 98
    :catch_0
    move-exception p0

    .line 99
    :goto_2
    move-object v0, v1

    .line 100
    goto :goto_4

    .line 101
    :cond_2
    invoke-virtual {v2, v0}, Ljava/io/ObjectOutputStream;->writeObject(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 102
    .line 103
    .line 104
    if-eqz v1, :cond_3

    .line 105
    .line 106
    :try_start_3
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 107
    .line 108
    .line 109
    :catch_1
    :cond_3
    :goto_3
    :try_start_4
    invoke-virtual {v2}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_5

    .line 110
    .line 111
    .line 112
    goto :goto_5

    .line 113
    :catchall_1
    move-exception p0

    .line 114
    move-object v2, v0

    .line 115
    goto :goto_1

    .line 116
    :catch_2
    move-exception p0

    .line 117
    move-object v2, v0

    .line 118
    goto :goto_2

    .line 119
    :catchall_2
    move-exception p0

    .line 120
    move-object v2, v0

    .line 121
    goto :goto_6

    .line 122
    :catch_3
    move-exception p0

    .line 123
    move-object v2, v0

    .line 124
    :goto_4
    :try_start_5
    sget-object v1, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 125
    .line 126
    const-string v3, "Error while saving monitored region states to file "

    .line 127
    .line 128
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    invoke-static {v1, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    sget-object v1, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 136
    .line 137
    invoke-virtual {p0, v1}, Ljava/lang/Throwable;->printStackTrace(Ljava/io/PrintStream;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 138
    .line 139
    .line 140
    if-eqz v0, :cond_4

    .line 141
    .line 142
    :try_start_6
    invoke-virtual {v0}, Ljava/io/FileOutputStream;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_4

    .line 143
    .line 144
    .line 145
    :catch_4
    :cond_4
    if-eqz v2, :cond_5

    .line 146
    .line 147
    goto :goto_3

    .line 148
    :catch_5
    :cond_5
    :goto_5
    return-void

    .line 149
    :catchall_3
    move-exception p0

    .line 150
    :goto_6
    if-eqz v0, :cond_6

    .line 151
    .line 152
    :try_start_7
    invoke-virtual {v0}, Ljava/io/FileOutputStream;->close()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_6

    .line 153
    .line 154
    .line 155
    :catch_6
    :cond_6
    if-eqz v2, :cond_7

    .line 156
    .line 157
    :try_start_8
    invoke-virtual {v2}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_7

    .line 158
    .line 159
    .line 160
    :catch_7
    :cond_7
    throw p0
.end method

.method public declared-synchronized startStatusPreservation()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z

    .line 8
    .line 9
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception v0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    :goto_0
    monitor-exit p0

    .line 16
    return-void

    .line 17
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 18
    throw v0
.end method

.method public declared-synchronized stateOf(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Lorg/altbeacon/beacon/service/RegionMonitoringState;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    monitor-exit p0

    .line 13
    return-object p1

    .line 14
    :catchall_0
    move-exception p1

    .line 15
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 16
    throw p1
.end method

.method public declared-synchronized stopStatusPreservation()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 3
    .line 4
    const-string v1, "org.altbeacon.beacon.service.monitoring_status_state"

    .line 5
    .line 6
    invoke-virtual {v0, v1}, Landroid/content/Context;->deleteFile(Ljava/lang/String;)Z

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mStatePreservationIsOn:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    monitor-exit p0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception v0

    .line 15
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 16
    throw v0
.end method

.method public updateLocalState(Lorg/altbeacon/beacon/Region;Ljava/lang/Integer;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->addLocalRegion(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    :cond_0
    if-eqz p2, :cond_2

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-nez p0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->markOutside()V

    .line 26
    .line 27
    .line 28
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    const/4 p1, 0x1

    .line 33
    if-ne p0, p1, :cond_2

    .line 34
    .line 35
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->markInside()Z

    .line 36
    .line 37
    .line 38
    :cond_2
    return-void
.end method

.method public updateMonitoringStatusTime(J)V
    .locals 1

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 2
    .line 3
    const-string v0, "org.altbeacon.beacon.service.monitoring_status_state"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/content/Context;->getFileStreamPath(Ljava/lang/String;)Ljava/io/File;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0, p1, p2}, Ljava/io/File;->setLastModified(J)Z

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public declared-synchronized updateNewlyInsideInRegionsContaining(Lorg/altbeacon/beacon/Beacon;)V
    .locals 7

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regionsMatchingTo(Lorg/altbeacon/beacon/Beacon;)Ljava/util/List;

    .line 3
    .line 4
    .line 5
    move-result-object p1

    .line 6
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    const/4 v0, 0x0

    .line 11
    move v1, v0

    .line 12
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_2

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Lorg/altbeacon/beacon/Region;

    .line 23
    .line 24
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getRegionsStateMap()Ljava/util/Map;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 33
    .line 34
    if-eqz v3, :cond_0

    .line 35
    .line 36
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->markInside()Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getActiveSinceAppLaunch()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getCallback()Lorg/altbeacon/beacon/service/Callback;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iget-object v4, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 53
    .line 54
    const-string v5, "monitoringData"

    .line 55
    .line 56
    new-instance v6, Lorg/altbeacon/beacon/service/MonitoringData;

    .line 57
    .line 58
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getInside()Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    invoke-direct {v6, v3, v2}, Lorg/altbeacon/beacon/service/MonitoringData;-><init>(ZLorg/altbeacon/beacon/Region;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v6}, Lorg/altbeacon/beacon/service/MonitoringData;->toBundle()Landroid/os/Bundle;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v1, v4, v5, v2}, Lorg/altbeacon/beacon/service/Callback;->call(Landroid/content/Context;Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :catchall_0
    move-exception p1

    .line 74
    goto :goto_3

    .line 75
    :cond_1
    sget-object v1, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 76
    .line 77
    const-string v2, "Not sending region update for region not active since last launch."

    .line 78
    .line 79
    new-array v3, v0, [Ljava/lang/Object;

    .line 80
    .line 81
    invoke-static {v1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :goto_1
    const/4 v1, 0x1

    .line 85
    goto :goto_0

    .line 86
    :cond_2
    if-eqz v1, :cond_3

    .line 87
    .line 88
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 93
    .line 94
    .line 95
    move-result-wide v0

    .line 96
    invoke-virtual {p0, v0, v1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->updateMonitoringStatusTime(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 97
    .line 98
    .line 99
    :goto_2
    monitor-exit p0

    .line 100
    return-void

    .line 101
    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 102
    throw p1
.end method

.method public declared-synchronized updateNewlyOutside()V
    .locals 7

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->inactiveRegionsExist:Z

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->purgeInactiveRegions()V

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catchall_0
    move-exception v0

    .line 11
    goto :goto_3

    .line 12
    :cond_0
    :goto_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v1, 0x0

    .line 21
    :cond_1
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_2

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Lorg/altbeacon/beacon/Region;

    .line 32
    .line 33
    invoke-virtual {p0, v2}, Lorg/altbeacon/beacon/service/MonitoringStatus;->stateOf(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/service/RegionMonitoringState;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->markOutsideIfExpired()Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    sget-object v1, Lorg/altbeacon/beacon/service/MonitoringStatus;->TAG:Ljava/lang/String;

    .line 44
    .line 45
    const-string v4, "found a monitor that expired: %s"

    .line 46
    .line 47
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-static {v1, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getCallback()Lorg/altbeacon/beacon/service/Callback;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    iget-object v4, p0, Lorg/altbeacon/beacon/service/MonitoringStatus;->mContext:Landroid/content/Context;

    .line 59
    .line 60
    const-string v5, "monitoringData"

    .line 61
    .line 62
    new-instance v6, Lorg/altbeacon/beacon/service/MonitoringData;

    .line 63
    .line 64
    invoke-virtual {v3}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->getInside()Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    invoke-direct {v6, v3, v2}, Lorg/altbeacon/beacon/service/MonitoringData;-><init>(ZLorg/altbeacon/beacon/Region;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v6}, Lorg/altbeacon/beacon/service/MonitoringData;->toBundle()Landroid/os/Bundle;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-virtual {v1, v4, v5, v2}, Lorg/altbeacon/beacon/service/Callback;->call(Landroid/content/Context;Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 76
    .line 77
    .line 78
    const/4 v1, 0x1

    .line 79
    goto :goto_1

    .line 80
    :cond_2
    if-eqz v1, :cond_3

    .line 81
    .line 82
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 87
    .line 88
    .line 89
    move-result-wide v0

    .line 90
    invoke-virtual {p0, v0, v1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->updateMonitoringStatusTime(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    .line 92
    .line 93
    :goto_2
    monitor-exit p0

    .line 94
    return-void

    .line 95
    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 96
    throw v0
.end method
