.class public final Lv71/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lv71/e;


# instance fields
.field public final a:D

.field public final b:D


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lv71/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lv71/e;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lv71/e;->c:Lv71/e;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide v0, 0x4013af1a9fbe76c8L    # 4.920999999999999

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    iput-wide v0, p0, Lv71/e;->a:D

    .line 10
    .line 11
    const/4 v0, 0x2

    .line 12
    int-to-double v0, v0

    .line 13
    const-wide v2, 0x3fcae147ae147ae1L    # 0.21

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    mul-double/2addr v2, v0

    .line 19
    const-wide v0, 0x3fffba5e353f7ceeL    # 1.983

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    add-double/2addr v2, v0

    .line 25
    iput-wide v2, p0, Lv71/e;->b:D

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of p0, p1, Lv71/e;

    .line 5
    .line 6
    if-nez p0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    const-wide p0, 0x3ff174bc6a7ef9dbL    # 1.091

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    invoke-static {p0, p1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_2

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_2
    const-wide p0, 0x3fee147ae147ae14L    # 0.94

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    invoke-static {p0, p1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    const-wide p0, 0x40071eb851eb851fL    # 2.89

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    invoke-static {p0, p1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_4

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_4
    const-wide p0, 0x3fffba5e353f7ceeL    # 1.983

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    invoke-static {p0, p1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-eqz p0, :cond_5

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_5
    const-wide p0, 0x3fcae147ae147ae1L    # 0.21

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    invoke-static {p0, p1, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-eqz p0, :cond_6

    .line 67
    .line 68
    :goto_0
    const/4 p0, 0x0

    .line 69
    return p0

    .line 70
    :cond_6
    :goto_1
    const/4 p0, 0x1

    .line 71
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    const-wide v0, 0x3ff174bc6a7ef9dbL    # 1.091

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/16 v0, 0x1f

    .line 11
    .line 12
    mul-int/2addr p0, v0

    .line 13
    const-wide v1, 0x3fee147ae147ae14L    # 0.94

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    invoke-static {v1, v2, p0, v0}, Lf2/m0;->a(DII)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    const-wide v1, 0x40071eb851eb851fL    # 2.89

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    invoke-static {v1, v2, p0, v0}, Lf2/m0;->a(DII)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    const-wide v1, 0x3fffba5e353f7ceeL    # 1.983

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    invoke-static {v1, v2, p0, v0}, Lf2/m0;->a(DII)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    const-wide v0, 0x3fcae147ae147ae1L    # 0.21

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    add-int/2addr v0, p0

    .line 50
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "VehicleDimensions(frontOverhangInMeter=1.091, rearOverhangInMeter=0.94, wheelbaseInMeter=2.89, widthInMeter=1.983, mirrorWidthInMeter=0.21)"

    .line 2
    .line 3
    return-object p0
.end method
