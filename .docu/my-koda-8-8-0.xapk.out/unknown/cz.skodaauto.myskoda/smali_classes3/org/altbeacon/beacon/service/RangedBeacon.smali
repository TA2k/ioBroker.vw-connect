.class public Lorg/altbeacon/beacon/service/RangedBeacon;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final DEFAULT_MAX_TRACKING_AGE:J = 0x1388L

.field public static final DEFAULT_SAMPLE_EXPIRATION_MILLISECONDS:J = 0x4e20L

.field private static final TAG:Ljava/lang/String; = "RangedBeacon"

.field public static maxTrackingAge:J = 0x1388L

.field private static sampleExpirationMilliseconds:J = 0x4e20L


# instance fields
.field private firstCycleDetectionTimestamp:J

.field private lastCycleDetectionTimestamp:J

.field protected lastTrackedTimeMillis:J

.field mBeacon:Lorg/altbeacon/beacon/Beacon;

.field protected transient mFilter:Lorg/altbeacon/beacon/service/RssiFilter;

.field private mTracked:Z

.field private packetCount:I


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/Beacon;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mTracked:Z

    .line 6
    .line 7
    const-wide/16 v0, 0x0

    .line 8
    .line 9
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastTrackedTimeMillis:J

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    iput-object v2, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mFilter:Lorg/altbeacon/beacon/service/RssiFilter;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    iput v2, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->packetCount:I

    .line 16
    .line 17
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->firstCycleDetectionTimestamp:J

    .line 18
    .line 19
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastCycleDetectionTimestamp:J

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/RangedBeacon;->updateBeacon(Lorg/altbeacon/beacon/Beacon;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method private getFilter()Lorg/altbeacon/beacon/service/RssiFilter;
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mFilter:Lorg/altbeacon/beacon/service/RssiFilter;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    :try_start_0
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lorg/altbeacon/beacon/service/RssiFilter;

    .line 20
    .line 21
    iput-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mFilter:Lorg/altbeacon/beacon/service/RssiFilter;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catch_0
    move-exception v0

    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const-string v1, "RangedBeacon"

    .line 34
    .line 35
    const-string v2, "Failed with exception %s"

    .line 36
    .line 37
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    const-string v2, "Could not construct class %s"

    .line 53
    .line 54
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    const/4 v0, 0x0

    .line 58
    new-array v0, v0, [Ljava/lang/Object;

    .line 59
    .line 60
    const-string v2, "Will default to RunningAverageRssiFilter"

    .line 61
    .line 62
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_0
    :goto_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mFilter:Lorg/altbeacon/beacon/service/RssiFilter;

    .line 66
    .line 67
    if-nez v0, :cond_1

    .line 68
    .line 69
    new-instance v0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;

    .line 70
    .line 71
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;-><init>()V

    .line 72
    .line 73
    .line 74
    iput-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mFilter:Lorg/altbeacon/beacon/service/RssiFilter;

    .line 75
    .line 76
    :cond_1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mFilter:Lorg/altbeacon/beacon/service/RssiFilter;

    .line 77
    .line 78
    return-object p0
.end method

.method public static setMaxTrackinAge(I)V
    .locals 2

    .line 1
    int-to-long v0, p0

    .line 2
    sput-wide v0, Lorg/altbeacon/beacon/service/RangedBeacon;->maxTrackingAge:J

    .line 3
    .line 4
    return-void
.end method

.method public static setSampleExpirationMilliseconds(J)V
    .locals 0

    .line 1
    sput-wide p0, Lorg/altbeacon/beacon/service/RangedBeacon;->sampleExpirationMilliseconds:J

    .line 2
    .line 3
    invoke-static {p0, p1}, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->setSampleExpirationMilliseconds(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public addMeasurement(Ljava/lang/Integer;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x7f

    .line 6
    .line 7
    if-eq v0, v1, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mTracked:Z

    .line 11
    .line 12
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastTrackedTimeMillis:J

    .line 17
    .line 18
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/RangedBeacon;->getFilter()Lorg/altbeacon/beacon/service/RssiFilter;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-interface {p0, p1}, Lorg/altbeacon/beacon/service/RssiFilter;->addMeasurement(Ljava/lang/Integer;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public commitMeasurements()V
    .locals 6

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/RangedBeacon;->getFilter()Lorg/altbeacon/beacon/service/RssiFilter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lorg/altbeacon/beacon/service/RssiFilter;->noMeasurementsAvailable()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    const-string v2, "RangedBeacon"

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/RangedBeacon;->getFilter()Lorg/altbeacon/beacon/service/RssiFilter;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {v0}, Lorg/altbeacon/beacon/service/RssiFilter;->calculateRssi()D

    .line 19
    .line 20
    .line 21
    move-result-wide v3

    .line 22
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 23
    .line 24
    invoke-virtual {v0, v3, v4}, Lorg/altbeacon/beacon/Beacon;->setRunningAverageRssi(D)V

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 28
    .line 29
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/RangedBeacon;->getFilter()Lorg/altbeacon/beacon/service/RssiFilter;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-interface {v5}, Lorg/altbeacon/beacon/service/RssiFilter;->getMeasurementCount()I

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    invoke-virtual {v0, v5}, Lorg/altbeacon/beacon/Beacon;->setRssiMeasurementCount(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    const-string v3, "calculated new runningAverageRssi: %s"

    .line 49
    .line 50
    invoke-static {v2, v3, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const-string v0, "No measurements available to calculate running average"

    .line 55
    .line 56
    new-array v3, v1, [Ljava/lang/Object;

    .line 57
    .line 58
    invoke-static {v2, v0, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :goto_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 62
    .line 63
    iget v2, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->packetCount:I

    .line 64
    .line 65
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/Beacon;->setPacketCount(I)V

    .line 66
    .line 67
    .line 68
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 69
    .line 70
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->firstCycleDetectionTimestamp:J

    .line 71
    .line 72
    invoke-virtual {v0, v2, v3}, Lorg/altbeacon/beacon/Beacon;->setFirstCycleDetectionTimestamp(J)V

    .line 73
    .line 74
    .line 75
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 76
    .line 77
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastCycleDetectionTimestamp:J

    .line 78
    .line 79
    invoke-virtual {v0, v2, v3}, Lorg/altbeacon/beacon/Beacon;->setLastCycleDetectionTimestamp(J)V

    .line 80
    .line 81
    .line 82
    iput v1, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->packetCount:I

    .line 83
    .line 84
    const-wide/16 v0, 0x0

    .line 85
    .line 86
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->firstCycleDetectionTimestamp:J

    .line 87
    .line 88
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastCycleDetectionTimestamp:J

    .line 89
    .line 90
    return-void
.end method

.method public getBeacon()Lorg/altbeacon/beacon/Beacon;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTrackingAge()J
    .locals 4

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastTrackedTimeMillis:J

    .line 6
    .line 7
    sub-long/2addr v0, v2

    .line 8
    return-wide v0
.end method

.method public isExpired()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangedBeacon;->getTrackingAge()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    sget-wide v2, Lorg/altbeacon/beacon/service/RangedBeacon;->maxTrackingAge:J

    .line 6
    .line 7
    cmp-long p0, v0, v2

    .line 8
    .line 9
    if-lez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public isTracked()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mTracked:Z

    .line 2
    .line 3
    return p0
.end method

.method public noMeasurementsAvailable()Z
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/RangedBeacon;->getFilter()Lorg/altbeacon/beacon/service/RssiFilter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lorg/altbeacon/beacon/service/RssiFilter;->noMeasurementsAvailable()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public setTracked(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mTracked:Z

    .line 2
    .line 3
    return-void
.end method

.method public updateBeacon(Lorg/altbeacon/beacon/Beacon;)V
    .locals 4

    .line 1
    iget v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->packetCount:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->packetCount:I

    .line 6
    .line 7
    iput-object p1, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 8
    .line 9
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->firstCycleDetectionTimestamp:J

    .line 10
    .line 11
    const-wide/16 v2, 0x0

    .line 12
    .line 13
    cmp-long v0, v0, v2

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getFirstCycleDetectionTimestamp()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->firstCycleDetectionTimestamp:J

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getLastCycleDetectionTimestamp()J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->lastCycleDetectionTimestamp:J

    .line 28
    .line 29
    iget-object p1, p0, Lorg/altbeacon/beacon/service/RangedBeacon;->mBeacon:Lorg/altbeacon/beacon/Beacon;

    .line 30
    .line 31
    invoke-virtual {p1}, Lorg/altbeacon/beacon/Beacon;->getRssi()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/RangedBeacon;->addMeasurement(Ljava/lang/Integer;)V

    .line 40
    .line 41
    .line 42
    return-void
.end method
