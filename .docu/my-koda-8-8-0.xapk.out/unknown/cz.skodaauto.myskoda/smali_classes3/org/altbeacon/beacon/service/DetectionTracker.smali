.class public Lorg/altbeacon/beacon/service/DetectionTracker;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final INSTANCE:Lorg/altbeacon/beacon/service/DetectionTracker;


# instance fields
.field private mLastDetectionTime:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/service/DetectionTracker;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/DetectionTracker;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/service/DetectionTracker;->INSTANCE:Lorg/altbeacon/beacon/service/DetectionTracker;

    .line 7
    .line 8
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
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/DetectionTracker;->mLastDetectionTime:J

    .line 7
    .line 8
    return-void
.end method

.method public static getInstance()Lorg/altbeacon/beacon/service/DetectionTracker;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/DetectionTracker;->INSTANCE:Lorg/altbeacon/beacon/service/DetectionTracker;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public getLastDetectionTime()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/DetectionTracker;->mLastDetectionTime:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public recordDetection()V
    .locals 2

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/DetectionTracker;->mLastDetectionTime:J

    .line 6
    .line 7
    return-void
.end method
