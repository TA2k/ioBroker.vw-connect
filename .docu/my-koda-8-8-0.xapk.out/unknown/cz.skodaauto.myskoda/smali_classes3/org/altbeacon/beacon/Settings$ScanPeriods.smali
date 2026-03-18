.class public final Lorg/altbeacon/beacon/Settings$ScanPeriods;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Settings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ScanPeriods"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u000f\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B-\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0007J\t\u0010\r\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0010\u001a\u00020\u0003H\u00c6\u0003J1\u0010\u0011\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u0012\u001a\u00020\u00132\u0008\u0010\u0014\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0015\u001a\u00020\u0016H\u00d6\u0001J\t\u0010\u0017\u001a\u00020\u0018H\u00d6\u0001R\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\tR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\tR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\tR\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\t\u00a8\u0006\u0019"
    }
    d2 = {
        "Lorg/altbeacon/beacon/Settings$ScanPeriods;",
        "",
        "foregroundScanPeriodMillis",
        "",
        "foregroundBetweenScanPeriodMillis",
        "backgroundScanPeriodMillis",
        "backgroundBetweenScanPeriodMillis",
        "(JJJJ)V",
        "getBackgroundBetweenScanPeriodMillis",
        "()J",
        "getBackgroundScanPeriodMillis",
        "getForegroundBetweenScanPeriodMillis",
        "getForegroundScanPeriodMillis",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final backgroundBetweenScanPeriodMillis:J

.field private final backgroundScanPeriodMillis:J

.field private final foregroundBetweenScanPeriodMillis:J

.field private final foregroundScanPeriodMillis:J


# direct methods
.method public constructor <init>()V
    .locals 11

    .line 1
    const/16 v9, 0xf

    const/4 v10, 0x0

    const-wide/16 v1, 0x0

    const-wide/16 v3, 0x0

    const-wide/16 v5, 0x0

    const-wide/16 v7, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v10}, Lorg/altbeacon/beacon/Settings$ScanPeriods;-><init>(JJJJILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(JJJJ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 4
    iput-wide p3, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 5
    iput-wide p5, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 6
    iput-wide p7, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    return-void
.end method

.method public synthetic constructor <init>(JJJJILkotlin/jvm/internal/g;)V
    .locals 8

    and-int/lit8 v0, p9, 0x1

    if-eqz v0, :cond_0

    const-wide/16 v0, 0x44c

    goto :goto_0

    :cond_0
    move-wide v0, p1

    :goto_0
    and-int/lit8 v2, p9, 0x2

    if-eqz v2, :cond_1

    const-wide/16 v2, 0x0

    goto :goto_1

    :cond_1
    move-wide v2, p3

    :goto_1
    and-int/lit8 v4, p9, 0x4

    if-eqz v4, :cond_2

    const-wide/16 v4, 0x7530

    goto :goto_2

    :cond_2
    move-wide v4, p5

    :goto_2
    and-int/lit8 v6, p9, 0x8

    if-eqz v6, :cond_3

    const-wide/32 v6, 0x493e0

    move-wide/from16 p8, v6

    :goto_3
    move-object p1, p0

    move-wide p2, v0

    move-wide p4, v2

    move-wide p6, v4

    goto :goto_4

    :cond_3
    move-wide/from16 p8, p7

    goto :goto_3

    .line 7
    :goto_4
    invoke-direct/range {p1 .. p9}, Lorg/altbeacon/beacon/Settings$ScanPeriods;-><init>(JJJJ)V

    return-void
.end method

.method public static synthetic copy$default(Lorg/altbeacon/beacon/Settings$ScanPeriods;JJJJILjava/lang/Object;)Lorg/altbeacon/beacon/Settings$ScanPeriods;
    .locals 9

    .line 1
    and-int/lit8 v0, p9, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 6
    .line 7
    :cond_0
    move-wide v1, p1

    .line 8
    and-int/lit8 p1, p9, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-wide p3, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 13
    .line 14
    :cond_1
    move-wide v3, p3

    .line 15
    and-int/lit8 p1, p9, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-wide p5, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 20
    .line 21
    :cond_2
    move-wide v5, p5

    .line 22
    and-int/lit8 p1, p9, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-wide p1, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 27
    .line 28
    move-wide v7, p1

    .line 29
    :goto_0
    move-object v0, p0

    .line 30
    goto :goto_1

    .line 31
    :cond_3
    move-wide/from16 v7, p7

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :goto_1
    invoke-virtual/range {v0 .. v8}, Lorg/altbeacon/beacon/Settings$ScanPeriods;->copy(JJJJ)Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method


# virtual methods
.method public final component1()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component3()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component4()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final copy(JJJJ)Lorg/altbeacon/beacon/Settings$ScanPeriods;
    .locals 0

    .line 1
    new-instance p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 2
    .line 3
    invoke-direct/range {p0 .. p8}, Lorg/altbeacon/beacon/Settings$ScanPeriods;-><init>(JJJJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 12
    .line 13
    iget-wide v3, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 14
    .line 15
    iget-wide v5, p1, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 16
    .line 17
    cmp-long v1, v3, v5

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    return v2

    .line 22
    :cond_2
    iget-wide v3, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 23
    .line 24
    iget-wide v5, p1, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 25
    .line 26
    cmp-long v1, v3, v5

    .line 27
    .line 28
    if-eqz v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-wide v3, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 32
    .line 33
    iget-wide v5, p1, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 34
    .line 35
    cmp-long v1, v3, v5

    .line 36
    .line 37
    if-eqz v1, :cond_4

    .line 38
    .line 39
    return v2

    .line 40
    :cond_4
    iget-wide v3, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 41
    .line 42
    iget-wide p0, p1, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 43
    .line 44
    cmp-long p0, v3, p0

    .line 45
    .line 46
    if-eqz p0, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    return v0
.end method

.method public final getBackgroundBetweenScanPeriodMillis()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getBackgroundScanPeriodMillis()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getForegroundBetweenScanPeriodMillis()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getForegroundScanPeriodMillis()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-wide v2, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 11
    .line 12
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-wide v2, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-wide v1, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 23
    .line 24
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 9

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundScanPeriodMillis:J

    .line 2
    .line 3
    iget-wide v2, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->foregroundBetweenScanPeriodMillis:J

    .line 4
    .line 5
    iget-wide v4, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundScanPeriodMillis:J

    .line 6
    .line 7
    iget-wide v6, p0, Lorg/altbeacon/beacon/Settings$ScanPeriods;->backgroundBetweenScanPeriodMillis:J

    .line 8
    .line 9
    const-string p0, "ScanPeriods(foregroundScanPeriodMillis="

    .line 10
    .line 11
    const-string v8, ", foregroundBetweenScanPeriodMillis="

    .line 12
    .line 13
    invoke-static {v0, v1, p0, v8}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v0, ", backgroundScanPeriodMillis="

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v0, ", backgroundBetweenScanPeriodMillis="

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v0, ")"

    .line 34
    .line 35
    invoke-static {v6, v7, v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
