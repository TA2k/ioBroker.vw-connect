.class public final Lzl/p;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Lyl/j;


# direct methods
.method public constructor <init>(Lyl/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzl/p;->i:Lyl/j;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final g()J
    .locals 6

    .line 1
    iget-object p0, p0, Lzl/p;->i:Lyl/j;

    .line 2
    .line 3
    invoke-interface {p0}, Lyl/j;->o()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 8
    .line 9
    if-lez v0, :cond_0

    .line 10
    .line 11
    int-to-float v0, v0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, v1

    .line 14
    :goto_0
    invoke-interface {p0}, Lyl/j;->m()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-lez p0, :cond_1

    .line 19
    .line 20
    int-to-float v1, p0

    .line 21
    :cond_1
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    int-to-long v2, p0

    .line 26
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    int-to-long v0, p0

    .line 31
    const/16 p0, 0x20

    .line 32
    .line 33
    shl-long/2addr v2, p0

    .line 34
    const-wide v4, 0xffffffffL

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v0, v4

    .line 40
    or-long/2addr v0, v2

    .line 41
    return-wide v0
.end method

.method public final i(Lg3/d;)V
    .locals 8

    .line 1
    iget-object p0, p0, Lzl/p;->i:Lyl/j;

    .line 2
    .line 3
    invoke-interface {p0}, Lyl/j;->o()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/high16 v1, 0x3f800000    # 1.0f

    .line 8
    .line 9
    if-lez v0, :cond_0

    .line 10
    .line 11
    invoke-interface {p1}, Lg3/d;->e()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    const/16 v4, 0x20

    .line 16
    .line 17
    shr-long/2addr v2, v4

    .line 18
    long-to-int v2, v2

    .line 19
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    int-to-float v0, v0

    .line 24
    div-float/2addr v2, v0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v2, v1

    .line 27
    :goto_0
    invoke-interface {p0}, Lyl/j;->m()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-lez v0, :cond_1

    .line 32
    .line 33
    invoke-interface {p1}, Lg3/d;->e()J

    .line 34
    .line 35
    .line 36
    move-result-wide v3

    .line 37
    const-wide v5, 0xffffffffL

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    and-long/2addr v3, v5

    .line 43
    long-to-int v1, v3

    .line 44
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    int-to-float v0, v0

    .line 49
    div-float/2addr v1, v0

    .line 50
    :cond_1
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-virtual {v0}, Lgw0/c;->o()J

    .line 55
    .line 56
    .line 57
    move-result-wide v3

    .line 58
    invoke-virtual {v0}, Lgw0/c;->h()Le3/r;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    invoke-interface {v5}, Le3/r;->o()V

    .line 63
    .line 64
    .line 65
    :try_start_0
    iget-object v5, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v5, Lbu/c;

    .line 68
    .line 69
    const-wide/16 v6, 0x0

    .line 70
    .line 71
    invoke-virtual {v5, v6, v7, v2, v1}, Lbu/c;->A(JFF)V

    .line 72
    .line 73
    .line 74
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p1}, Lgw0/c;->h()Le3/r;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-static {p1}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-interface {p0, p1}, Lyl/j;->c(Landroid/graphics/Canvas;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 87
    .line 88
    .line 89
    invoke-static {v0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :catchall_0
    move-exception p0

    .line 94
    invoke-static {v0, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 95
    .line 96
    .line 97
    throw p0
.end method
