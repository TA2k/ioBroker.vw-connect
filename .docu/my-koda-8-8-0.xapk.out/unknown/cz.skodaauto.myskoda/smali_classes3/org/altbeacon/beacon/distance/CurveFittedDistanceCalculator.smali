.class public Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/distance/DistanceCalculator;


# static fields
.field public static final TAG:Ljava/lang/String; = "CurveFittedDistanceCalculator"


# instance fields
.field private mCoefficient1:D

.field private mCoefficient2:D

.field private mCoefficient3:D


# direct methods
.method public constructor <init>(DDD)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;->mCoefficient1:D

    .line 5
    .line 6
    iput-wide p3, p0, Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;->mCoefficient2:D

    .line 7
    .line 8
    iput-wide p5, p0, Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;->mCoefficient3:D

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public calculateDistance(ID)D
    .locals 8

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmpl-double v0, p2, v0

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-wide/high16 p0, -0x4010000000000000L    # -1.0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :cond_0
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    filled-new-array {v0, v1}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "CurveFittedDistanceCalculator"

    .line 23
    .line 24
    const-string v2, "calculating distance based on mRssi of %s and txPower of %s"

    .line 25
    .line 26
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 30
    .line 31
    mul-double v4, p2, v2

    .line 32
    .line 33
    int-to-double v6, p1

    .line 34
    div-double/2addr v4, v6

    .line 35
    cmpg-double p1, v4, v2

    .line 36
    .line 37
    if-gez p1, :cond_1

    .line 38
    .line 39
    const-wide/high16 p0, 0x4024000000000000L    # 10.0

    .line 40
    .line 41
    invoke-static {v4, v5, p0, p1}, Ljava/lang/Math;->pow(DD)D

    .line 42
    .line 43
    .line 44
    move-result-wide p0

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    iget-wide v2, p0, Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;->mCoefficient1:D

    .line 47
    .line 48
    iget-wide v6, p0, Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;->mCoefficient2:D

    .line 49
    .line 50
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 51
    .line 52
    .line 53
    move-result-wide v4

    .line 54
    mul-double/2addr v4, v2

    .line 55
    iget-wide p0, p0, Lorg/altbeacon/beacon/distance/CurveFittedDistanceCalculator;->mCoefficient3:D

    .line 56
    .line 57
    add-double/2addr p0, v4

    .line 58
    :goto_0
    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 63
    .line 64
    .line 65
    move-result-object p3

    .line 66
    filled-new-array {p2, p3}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    const-string p3, "avg mRssi: %s distance: %s"

    .line 71
    .line 72
    invoke-static {v1, p3, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    return-wide p0
.end method
