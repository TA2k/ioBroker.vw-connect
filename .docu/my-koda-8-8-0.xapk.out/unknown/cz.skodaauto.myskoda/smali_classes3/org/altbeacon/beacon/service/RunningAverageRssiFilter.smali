.class public Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/service/RssiFilter;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;
    }
.end annotation


# static fields
.field public static final DEFAULT_SAMPLE_EXPIRATION_MILLISECONDS:J = 0x4e20L

.field private static final TAG:Ljava/lang/String; = "RunningAverageRssiFilter"

.field private static sampleExpirationMilliseconds:J = 0x4e20L


# instance fields
.field private mMeasurements:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 10
    .line 11
    return-void
.end method

.method public static getSampleExpirationMilliseconds()J
    .locals 2

    .line 1
    sget-wide v0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->sampleExpirationMilliseconds:J

    .line 2
    .line 3
    return-wide v0
.end method

.method private declared-synchronized refreshMeasurements()V
    .locals 7

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Ljava/util/ArrayList;

    .line 3
    .line 4
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;

    .line 24
    .line 25
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 26
    .line 27
    .line 28
    move-result-wide v3

    .line 29
    iget-wide v5, v2, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->timestamp:J

    .line 30
    .line 31
    sub-long/2addr v3, v5

    .line 32
    sget-wide v5, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->sampleExpirationMilliseconds:J

    .line 33
    .line 34
    cmp-long v3, v3, v5

    .line 35
    .line 36
    if-gez v3, :cond_0

    .line 37
    .line 38
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception v0

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    iput-object v0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    monitor-exit p0

    .line 50
    return-void

    .line 51
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 52
    throw v0
.end method

.method public static setSampleExpirationMilliseconds(J)V
    .locals 0

    .line 1
    sput-wide p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->sampleExpirationMilliseconds:J

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public addMeasurement(Ljava/lang/Integer;)V
    .locals 3

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;-><init>(Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, v0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->rssi:Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    iput-wide v1, v0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->timestamp:J

    .line 14
    .line 15
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public calculateRssi()D
    .locals 8

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->refreshMeasurements()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    add-int/lit8 v1, v0, -0x1

    .line 11
    .line 12
    const/4 v2, 0x2

    .line 13
    if-le v0, v2, :cond_0

    .line 14
    .line 15
    div-int/lit8 v1, v0, 0xa

    .line 16
    .line 17
    add-int/lit8 v3, v1, 0x1

    .line 18
    .line 19
    sub-int v1, v0, v1

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v3, 0x0

    .line 24
    :goto_0
    const-wide/16 v4, 0x0

    .line 25
    .line 26
    move v2, v3

    .line 27
    :goto_1
    if-gt v2, v1, :cond_1

    .line 28
    .line 29
    iget-object v6, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    check-cast v6, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;

    .line 36
    .line 37
    iget-object v6, v6, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->rssi:Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    int-to-double v6, v6

    .line 44
    add-double/2addr v4, v6

    .line 45
    add-int/lit8 v2, v2, 0x1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    sub-int/2addr v1, v3

    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    int-to-double v1, v1

    .line 52
    div-double/2addr v4, v1

    .line 53
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    filled-new-array {p0, v0}, [Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    const-string v0, "RunningAverageRssiFilter"

    .line 66
    .line 67
    const-string v1, "Running average mRssi based on %s measurements: %s"

    .line 68
    .line 69
    invoke-static {v0, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    return-wide v4
.end method

.method public getMeasurementCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public noMeasurementsAvailable()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;->mMeasurements:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method
