.class public Lorg/altbeacon/beacon/service/Stats;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/service/Stats$Sample;
    }
.end annotation


# static fields
.field private static final INSTANCE:Lorg/altbeacon/beacon/service/Stats;

.field private static final SIMPLE_DATE_FORMAT:Ljava/text/SimpleDateFormat;

.field private static final TAG:Ljava/lang/String; = "Stats"


# instance fields
.field private mEnableHistoricalLogging:Z

.field private mEnableLogging:Z

.field private mEnabled:Z

.field private mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

.field private mSampleIntervalMillis:J

.field private mSamples:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/altbeacon/beacon/service/Stats$Sample;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/service/Stats;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/Stats;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/service/Stats;->INSTANCE:Lorg/altbeacon/beacon/service/Stats;

    .line 7
    .line 8
    new-instance v0, Ljava/text/SimpleDateFormat;

    .line 9
    .line 10
    const-string v1, "HH:mm:ss.SSS"

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lorg/altbeacon/beacon/service/Stats;->SIMPLE_DATE_FORMAT:Ljava/text/SimpleDateFormat;

    .line 16
    .line 17
    return-void
.end method

.method private constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSampleIntervalMillis:J

    .line 7
    .line 8
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/Stats;->clearSamples()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method private formattedDate(Ljava/util/Date;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string p0, ""

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    sget-object v0, Lorg/altbeacon/beacon/service/Stats;->SIMPLE_DATE_FORMAT:Ljava/text/SimpleDateFormat;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    invoke-virtual {v0, p1}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0

    .line 17
    :cond_0
    return-object p0
.end method

.method public static getInstance()Lorg/altbeacon/beacon/service/Stats;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/Stats;->INSTANCE:Lorg/altbeacon/beacon/service/Stats;

    .line 2
    .line 3
    return-object v0
.end method

.method private logSample(Lorg/altbeacon/beacon/service/Stats$Sample;Z)V
    .locals 7

    .line 1
    const-string v0, "Stats"

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    new-array p2, p2, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string v1, "sample start time, sample stop time, first detection time, last detection time, max millis between detections, detection count"

    .line 9
    .line 10
    invoke-static {v0, v1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p2, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->sampleStartTime:Ljava/util/Date;

    .line 14
    .line 15
    invoke-direct {p0, p2}, Lorg/altbeacon/beacon/service/Stats;->formattedDate(Ljava/util/Date;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    iget-object p2, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->sampleStopTime:Ljava/util/Date;

    .line 20
    .line 21
    invoke-direct {p0, p2}, Lorg/altbeacon/beacon/service/Stats;->formattedDate(Ljava/util/Date;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    iget-object p2, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->firstDetectionTime:Ljava/util/Date;

    .line 26
    .line 27
    invoke-direct {p0, p2}, Lorg/altbeacon/beacon/service/Stats;->formattedDate(Ljava/util/Date;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iget-object p2, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->lastDetectionTime:Ljava/util/Date;

    .line 32
    .line 33
    invoke-direct {p0, p2}, Lorg/altbeacon/beacon/service/Stats;->formattedDate(Ljava/util/Date;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iget-wide v5, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->maxMillisBetweenDetections:J

    .line 38
    .line 39
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    iget-wide p0, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->detectionCount:J

    .line 44
    .line 45
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    filled-new-array/range {v1 .. v6}, [Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    const-string p1, "%s, %s, %s, %s, %s, %s"

    .line 54
    .line 55
    invoke-static {v0, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method private logSamples()V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSamples:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "Stats"

    .line 16
    .line 17
    const-string v2, "--- Stats for %s samples"

    .line 18
    .line 19
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSamples:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    const/4 v1, 0x1

    .line 29
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 40
    .line 41
    invoke-direct {p0, v2, v1}, Lorg/altbeacon/beacon/service/Stats;->logSample(Lorg/altbeacon/beacon/service/Stats$Sample;Z)V

    .line 42
    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    return-void
.end method

.method private rollSampleIfNeeded()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSampleIntervalMillis:J

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
    new-instance v0, Ljava/util/Date;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/util/Date;->getTime()J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    iget-object v2, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 23
    .line 24
    iget-object v2, v2, Lorg/altbeacon/beacon/service/Stats$Sample;->sampleStartTime:Ljava/util/Date;

    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/util/Date;->getTime()J

    .line 27
    .line 28
    .line 29
    move-result-wide v2

    .line 30
    sub-long/2addr v0, v2

    .line 31
    iget-wide v2, p0, Lorg/altbeacon/beacon/service/Stats;->mSampleIntervalMillis:J

    .line 32
    .line 33
    cmp-long v0, v0, v2

    .line 34
    .line 35
    if-ltz v0, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    return-void

    .line 39
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/Stats;->newSampleInterval()V

    .line 40
    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public clearSample()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 3
    .line 4
    return-void
.end method

.method public clearSamples()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSamples:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/Stats;->newSampleInterval()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public getSamples()Ljava/util/ArrayList;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Lorg/altbeacon/beacon/service/Stats$Sample;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/Stats;->rollSampleIfNeeded()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/altbeacon/beacon/service/Stats;->mSamples:Ljava/util/ArrayList;

    .line 5
    .line 6
    return-object p0
.end method

.method public isEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/Stats;->mEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public log(Lorg/altbeacon/beacon/Beacon;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/Stats;->rollSampleIfNeeded()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 5
    .line 6
    iget-wide v0, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->detectionCount:J

    .line 7
    .line 8
    const-wide/16 v2, 0x1

    .line 9
    .line 10
    add-long/2addr v0, v2

    .line 11
    iput-wide v0, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->detectionCount:J

    .line 12
    .line 13
    iget-object v0, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->firstDetectionTime:Ljava/util/Date;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Ljava/util/Date;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v0, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->firstDetectionTime:Ljava/util/Date;

    .line 23
    .line 24
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 25
    .line 26
    iget-object p1, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->lastDetectionTime:Ljava/util/Date;

    .line 27
    .line 28
    if-eqz p1, :cond_1

    .line 29
    .line 30
    new-instance p1, Ljava/util/Date;

    .line 31
    .line 32
    invoke-direct {p1}, Ljava/util/Date;-><init>()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 36
    .line 37
    .line 38
    move-result-wide v0

    .line 39
    iget-object p1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 40
    .line 41
    iget-object p1, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->lastDetectionTime:Ljava/util/Date;

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 44
    .line 45
    .line 46
    move-result-wide v2

    .line 47
    sub-long/2addr v0, v2

    .line 48
    iget-object p1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 49
    .line 50
    iget-wide v2, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->maxMillisBetweenDetections:J

    .line 51
    .line 52
    cmp-long v2, v0, v2

    .line 53
    .line 54
    if-lez v2, :cond_1

    .line 55
    .line 56
    iput-wide v0, p1, Lorg/altbeacon/beacon/service/Stats$Sample;->maxMillisBetweenDetections:J

    .line 57
    .line 58
    :cond_1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 59
    .line 60
    new-instance p1, Ljava/util/Date;

    .line 61
    .line 62
    invoke-direct {p1}, Ljava/util/Date;-><init>()V

    .line 63
    .line 64
    .line 65
    iput-object p1, p0, Lorg/altbeacon/beacon/service/Stats$Sample;->lastDetectionTime:Ljava/util/Date;

    .line 66
    .line 67
    return-void
.end method

.method public newSampleInterval()V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/Date;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/util/Date;

    .line 11
    .line 12
    iget-object v1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 13
    .line 14
    iget-object v1, v1, Lorg/altbeacon/beacon/service/Stats$Sample;->sampleStartTime:Ljava/util/Date;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    .line 17
    .line 18
    .line 19
    move-result-wide v1

    .line 20
    iget-wide v3, p0, Lorg/altbeacon/beacon/service/Stats;->mSampleIntervalMillis:J

    .line 21
    .line 22
    add-long/2addr v1, v3

    .line 23
    invoke-direct {v0, v1, v2}, Ljava/util/Date;-><init>(J)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 27
    .line 28
    iput-object v0, v1, Lorg/altbeacon/beacon/service/Stats$Sample;->sampleStopTime:Ljava/util/Date;

    .line 29
    .line 30
    iget-boolean v2, p0, Lorg/altbeacon/beacon/service/Stats;->mEnableHistoricalLogging:Z

    .line 31
    .line 32
    if-nez v2, :cond_0

    .line 33
    .line 34
    iget-boolean v2, p0, Lorg/altbeacon/beacon/service/Stats;->mEnableLogging:Z

    .line 35
    .line 36
    if-eqz v2, :cond_0

    .line 37
    .line 38
    const/4 v2, 0x1

    .line 39
    invoke-direct {p0, v1, v2}, Lorg/altbeacon/beacon/service/Stats;->logSample(Lorg/altbeacon/beacon/service/Stats$Sample;Z)V

    .line 40
    .line 41
    .line 42
    :cond_0
    new-instance v1, Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 43
    .line 44
    invoke-direct {v1}, Lorg/altbeacon/beacon/service/Stats$Sample;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object v1, p0, Lorg/altbeacon/beacon/service/Stats;->mSample:Lorg/altbeacon/beacon/service/Stats$Sample;

    .line 48
    .line 49
    iput-object v0, v1, Lorg/altbeacon/beacon/service/Stats$Sample;->sampleStartTime:Ljava/util/Date;

    .line 50
    .line 51
    iget-object v0, p0, Lorg/altbeacon/beacon/service/Stats;->mSamples:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/Stats;->mEnableHistoricalLogging:Z

    .line 57
    .line 58
    if-eqz v0, :cond_1

    .line 59
    .line 60
    invoke-direct {p0}, Lorg/altbeacon/beacon/service/Stats;->logSamples()V

    .line 61
    .line 62
    .line 63
    :cond_1
    return-void
.end method

.method public setEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/Stats;->mEnabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public setHistoricalLoggingEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/Stats;->mEnableHistoricalLogging:Z

    .line 2
    .line 3
    return-void
.end method

.method public setLoggingEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/Stats;->mEnableLogging:Z

    .line 2
    .line 3
    return-void
.end method

.method public setSampleIntervalMillis(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lorg/altbeacon/beacon/service/Stats;->mSampleIntervalMillis:J

    .line 2
    .line 3
    return-void
.end method
