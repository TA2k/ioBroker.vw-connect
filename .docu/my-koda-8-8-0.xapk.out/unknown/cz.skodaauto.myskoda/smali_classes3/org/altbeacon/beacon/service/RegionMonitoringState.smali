.class public Lorg/altbeacon/beacon/service/RegionMonitoringState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final TAG:Ljava/lang/String; = "RegionMonitoringState"


# instance fields
.field private transient activeSinceAppLaunch:Z

.field private final callback:Lorg/altbeacon/beacon/service/Callback;

.field private inside:Z

.field private lastSeenTime:J


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/Callback;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->inside:Z

    .line 6
    .line 7
    const-wide/16 v1, 0x0

    .line 8
    .line 9
    iput-wide v1, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 10
    .line 11
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->activeSinceAppLaunch:Z

    .line 12
    .line 13
    iput-object p1, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->callback:Lorg/altbeacon/beacon/service/Callback;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public getActiveSinceAppLaunch()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->activeSinceAppLaunch:Z

    .line 2
    .line 3
    return p0
.end method

.method public getCallback()Lorg/altbeacon/beacon/service/Callback;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->callback:Lorg/altbeacon/beacon/service/Callback;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInside()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->inside:Z

    .line 2
    .line 3
    return p0
.end method

.method public markInside()Z
    .locals 2

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 6
    .line 7
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->inside:Z

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->inside:Z

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public markOutside()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->inside:Z

    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 7
    .line 8
    return-void
.end method

.method public markOutsideIfExpired()Z
    .locals 6

    .line 1
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->inside:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 6
    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    cmp-long v0, v0, v2

    .line 10
    .line 11
    if-lez v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 18
    .line 19
    sub-long/2addr v0, v2

    .line 20
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getRegionExitPeriod()J

    .line 21
    .line 22
    .line 23
    move-result-wide v2

    .line 24
    cmp-long v0, v0, v2

    .line 25
    .line 26
    if-lez v0, :cond_0

    .line 27
    .line 28
    sget-object v0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->TAG:Ljava/lang/String;

    .line 29
    .line 30
    iget-wide v1, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 31
    .line 32
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    iget-wide v4, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->lastSeenTime:J

    .line 41
    .line 42
    sub-long/2addr v2, v4

    .line 43
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getRegionExitPeriod()J

    .line 48
    .line 49
    .line 50
    move-result-wide v3

    .line 51
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    filled-new-array {v1, v2, v3}, [Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    const-string v2, "We are newly outside the region because the lastSeenTime of %s was %s seconds ago, and that is over the expiration duration of %s"

    .line 60
    .line 61
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RegionMonitoringState;->markOutside()V

    .line 65
    .line 66
    .line 67
    const/4 p0, 0x1

    .line 68
    return p0

    .line 69
    :cond_0
    const/4 p0, 0x0

    .line 70
    return p0
.end method

.method public setActiveSinceAppLaunch(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/RegionMonitoringState;->activeSinceAppLaunch:Z

    .line 2
    .line 3
    return-void
.end method
