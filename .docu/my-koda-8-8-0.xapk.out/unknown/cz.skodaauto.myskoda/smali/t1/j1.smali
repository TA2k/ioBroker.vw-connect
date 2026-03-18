.class public final Lt1/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lg4/l0;

.field public b:Lt3/y;

.field public c:Lt3/y;


# direct methods
.method public constructor <init>(Lg4/l0;Lt3/y;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/j1;->a:Lg4/l0;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-object p1, p0, Lt1/j1;->b:Lt3/y;

    .line 8
    .line 9
    iput-object p2, p0, Lt1/j1;->c:Lt3/y;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(J)J
    .locals 6

    .line 1
    iget-object v0, p0, Lt1/j1;->b:Lt3/y;

    .line 2
    .line 3
    sget-object v1, Ld3/c;->e:Ld3/c;

    .line 4
    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    invoke-interface {v0}, Lt3/y;->g()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Lt1/j1;->c:Lt3/y;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-interface {p0, v0, v2}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    move-object p0, v1

    .line 26
    :goto_0
    if-nez p0, :cond_2

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_2
    move-object v1, p0

    .line 30
    :cond_3
    :goto_1
    const/16 p0, 0x20

    .line 31
    .line 32
    shr-long v2, p1, p0

    .line 33
    .line 34
    long-to-int v0, v2

    .line 35
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    iget v3, v1, Ld3/c;->a:F

    .line 40
    .line 41
    cmpg-float v2, v2, v3

    .line 42
    .line 43
    if-gez v2, :cond_4

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_4
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    iget v3, v1, Ld3/c;->c:F

    .line 51
    .line 52
    cmpl-float v2, v2, v3

    .line 53
    .line 54
    if-lez v2, :cond_5

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_5
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    :goto_2
    const-wide v4, 0xffffffffL

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr p1, v4

    .line 67
    long-to-int p1, p1

    .line 68
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    iget v0, v1, Ld3/c;->b:F

    .line 73
    .line 74
    cmpg-float p2, p2, v0

    .line 75
    .line 76
    if-gez p2, :cond_6

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_6
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    iget v0, v1, Ld3/c;->d:F

    .line 84
    .line 85
    cmpl-float p2, p2, v0

    .line 86
    .line 87
    if-lez p2, :cond_7

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_7
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    :goto_3
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    int-to-long p1, p1

    .line 99
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    int-to-long v0, v0

    .line 104
    shl-long p0, p1, p0

    .line 105
    .line 106
    and-long/2addr v0, v4

    .line 107
    or-long/2addr p0, v0

    .line 108
    return-wide p0
.end method

.method public final b(JZ)I
    .locals 0

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lt1/j1;->a(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    :cond_0
    invoke-virtual {p0, p1, p2}, Lt1/j1;->d(J)J

    .line 8
    .line 9
    .line 10
    move-result-wide p1

    .line 11
    iget-object p0, p0, Lt1/j1;->a:Lg4/l0;

    .line 12
    .line 13
    iget-object p0, p0, Lg4/l0;->b:Lg4/o;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lg4/o;->g(J)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final c(J)Z
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lt1/j1;->a(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide p1

    .line 5
    invoke-virtual {p0, p1, p2}, Lt1/j1;->d(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p1

    .line 9
    const-wide v0, 0xffffffffL

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    and-long/2addr v0, p1

    .line 15
    long-to-int v0, v0

    .line 16
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-object p0, p0, Lt1/j1;->a:Lg4/l0;

    .line 21
    .line 22
    iget-object v1, p0, Lg4/l0;->b:Lg4/o;

    .line 23
    .line 24
    invoke-virtual {v1, v0}, Lg4/o;->e(F)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/16 v1, 0x20

    .line 29
    .line 30
    shr-long/2addr p1, v1

    .line 31
    long-to-int p1, p1

    .line 32
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    invoke-virtual {p0, v0}, Lg4/l0;->e(I)F

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    cmpl-float p2, p2, v1

    .line 41
    .line 42
    if-ltz p2, :cond_0

    .line 43
    .line 44
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    invoke-virtual {p0, v0}, Lg4/l0;->f(I)F

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    cmpg-float p0, p1, p0

    .line 53
    .line 54
    if-gtz p0, :cond_0

    .line 55
    .line 56
    const/4 p0, 0x1

    .line 57
    return p0

    .line 58
    :cond_0
    const/4 p0, 0x0

    .line 59
    return p0
.end method

.method public final d(J)J
    .locals 3

    .line 1
    iget-object v0, p0, Lt1/j1;->b:Lt3/y;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    invoke-interface {v0}, Lt3/y;->g()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v0, v2

    .line 14
    :goto_0
    if-nez v0, :cond_1

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    iget-object p0, p0, Lt1/j1;->c:Lt3/y;

    .line 18
    .line 19
    if-eqz p0, :cond_4

    .line 20
    .line 21
    invoke-interface {p0}, Lt3/y;->g()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    move-object v2, p0

    .line 28
    :cond_2
    if-nez v2, :cond_3

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_3
    invoke-interface {v0, v2, p1, p2}, Lt3/y;->Z(Lt3/y;J)J

    .line 32
    .line 33
    .line 34
    move-result-wide p0

    .line 35
    return-wide p0

    .line 36
    :cond_4
    :goto_1
    return-wide p1
.end method

.method public final e(J)J
    .locals 3

    .line 1
    iget-object v0, p0, Lt1/j1;->b:Lt3/y;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    invoke-interface {v0}, Lt3/y;->g()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v0, v2

    .line 14
    :goto_0
    if-nez v0, :cond_1

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    iget-object p0, p0, Lt1/j1;->c:Lt3/y;

    .line 18
    .line 19
    if-eqz p0, :cond_4

    .line 20
    .line 21
    invoke-interface {p0}, Lt3/y;->g()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    move-object v2, p0

    .line 28
    :cond_2
    if-nez v2, :cond_3

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_3
    invoke-interface {v2, v0, p1, p2}, Lt3/y;->Z(Lt3/y;J)J

    .line 32
    .line 33
    .line 34
    move-result-wide p0

    .line 35
    return-wide p0

    .line 36
    :cond_4
    :goto_1
    return-wide p1
.end method
