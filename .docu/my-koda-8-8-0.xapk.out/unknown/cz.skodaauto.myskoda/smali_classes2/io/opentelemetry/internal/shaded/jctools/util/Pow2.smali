.class public final Lio/opentelemetry/internal/shaded/jctools/util/Pow2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final MAX_POW2:I = 0x40000000


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static align(JI)J
    .locals 2

    .line 1
    invoke-static {p2}, Lio/opentelemetry/internal/shaded/jctools/util/Pow2;->isPowerOfTwo(I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    add-int/lit8 p2, p2, -0x1

    .line 8
    .line 9
    int-to-long v0, p2

    .line 10
    add-long/2addr p0, v0

    .line 11
    not-int p2, p2

    .line 12
    int-to-long v0, p2

    .line 13
    and-long/2addr p0, v0

    .line 14
    return-wide p0

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 16
    .line 17
    const-string p1, "alignment must be a power of 2:"

    .line 18
    .line 19
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public static isPowerOfTwo(I)Z
    .locals 1

    .line 1
    add-int/lit8 v0, p0, -0x1

    .line 2
    .line 3
    and-int/2addr p0, v0

    .line 4
    if-nez p0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public static roundToPowerOfTwo(I)I
    .locals 3

    .line 1
    const/high16 v0, 0x40000000    # 2.0f

    .line 2
    .line 3
    if-gt p0, v0, :cond_1

    .line 4
    .line 5
    if-ltz p0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    sub-int/2addr p0, v0

    .line 9
    invoke-static {p0}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    rsub-int/lit8 p0, p0, 0x20

    .line 14
    .line 15
    shl-int p0, v0, p0

    .line 16
    .line 17
    return p0

    .line 18
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    const-string v1, "Given value:"

    .line 21
    .line 22
    const-string v2, ". Expecting value >= 0."

    .line 23
    .line 24
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw v0

    .line 32
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string v1, "There is no larger power of 2 int for value:"

    .line 35
    .line 36
    const-string v2, " since it exceeds 2^31."

    .line 37
    .line 38
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v0
.end method
