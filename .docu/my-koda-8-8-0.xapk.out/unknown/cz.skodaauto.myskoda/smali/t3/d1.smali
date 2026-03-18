.class public abstract Lt3/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt4/c;


# instance fields
.field public d:Z


# direct methods
.method public static A(Lt3/d1;Lt3/e1;J)V
    .locals 3

    .line 1
    sget v0, Lt3/g1;->b:I

    .line 2
    .line 3
    sget-object v0, Lt3/f1;->g:Lt3/f1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 9
    .line 10
    .line 11
    iget-wide v1, p1, Lt3/e1;->h:J

    .line 12
    .line 13
    invoke-static {p2, p3, v1, v2}, Lt4/j;->d(JJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide p2

    .line 17
    const/4 p0, 0x0

    .line 18
    invoke-virtual {p1, p2, p3, p0, v0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static final b(Lt3/d1;Lt3/e1;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lv3/a1;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    check-cast p1, Lv3/a1;

    .line 9
    .line 10
    iget-boolean p0, p0, Lt3/d1;->d:Z

    .line 11
    .line 12
    invoke-interface {p1, p0}, Lv3/a1;->p(Z)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public static synthetic h(Lt3/d1;Lt3/e1;II)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public static i(Lt3/d1;Lt3/e1;J)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 5
    .line 6
    .line 7
    iget-wide v0, p1, Lt3/e1;->h:J

    .line 8
    .line 9
    invoke-static {p2, p3, v0, v1}, Lt4/j;->d(JJ)J

    .line 10
    .line 11
    .line 12
    move-result-wide p2

    .line 13
    const/4 p0, 0x0

    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-virtual {p1, p2, p3, p0, v0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public static l(Lt3/d1;Lt3/e1;II)V
    .locals 9

    .line 1
    int-to-long v0, p2

    .line 2
    const/16 p2, 0x20

    .line 3
    .line 4
    shl-long/2addr v0, p2

    .line 5
    int-to-long v2, p3

    .line 6
    const-wide v4, 0xffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    and-long/2addr v2, v4

    .line 12
    or-long/2addr v0, v2

    .line 13
    invoke-virtual {p0}, Lt3/d1;->d()Lt4/m;

    .line 14
    .line 15
    .line 16
    move-result-object p3

    .line 17
    sget-object v2, Lt4/m;->d:Lt4/m;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v6, 0x0

    .line 21
    if-eq p3, v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {p0}, Lt3/d1;->f()I

    .line 24
    .line 25
    .line 26
    move-result p3

    .line 27
    if-nez p3, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {p0}, Lt3/d1;->f()I

    .line 31
    .line 32
    .line 33
    move-result p3

    .line 34
    iget v2, p1, Lt3/e1;->d:I

    .line 35
    .line 36
    sub-int/2addr p3, v2

    .line 37
    shr-long v7, v0, p2

    .line 38
    .line 39
    long-to-int v2, v7

    .line 40
    sub-int/2addr p3, v2

    .line 41
    and-long/2addr v0, v4

    .line 42
    long-to-int v0, v0

    .line 43
    int-to-long v1, p3

    .line 44
    shl-long p2, v1, p2

    .line 45
    .line 46
    int-to-long v0, v0

    .line 47
    and-long/2addr v0, v4

    .line 48
    or-long/2addr p2, v0

    .line 49
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 50
    .line 51
    .line 52
    iget-wide v0, p1, Lt3/e1;->h:J

    .line 53
    .line 54
    invoke-static {p2, p3, v0, v1}, Lt4/j;->d(JJ)J

    .line 55
    .line 56
    .line 57
    move-result-wide p2

    .line 58
    invoke-virtual {p1, p2, p3, v3, v6}, Lt3/e1;->l0(JFLay0/k;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_1
    :goto_0
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 63
    .line 64
    .line 65
    iget-wide p2, p1, Lt3/e1;->h:J

    .line 66
    .line 67
    invoke-static {v0, v1, p2, p3}, Lt4/j;->d(JJ)J

    .line 68
    .line 69
    .line 70
    move-result-wide p2

    .line 71
    invoke-virtual {p1, p2, p3, v3, v6}, Lt3/e1;->l0(JFLay0/k;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public static p(Lt3/d1;Lt3/e1;II)V
    .locals 9

    .line 1
    sget v0, Lt3/g1;->b:I

    .line 2
    .line 3
    sget-object v0, Lt3/f1;->g:Lt3/f1;

    .line 4
    .line 5
    int-to-long v1, p2

    .line 6
    const/16 p2, 0x20

    .line 7
    .line 8
    shl-long/2addr v1, p2

    .line 9
    int-to-long v3, p3

    .line 10
    const-wide v5, 0xffffffffL

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    and-long/2addr v3, v5

    .line 16
    or-long/2addr v1, v3

    .line 17
    invoke-virtual {p0}, Lt3/d1;->d()Lt4/m;

    .line 18
    .line 19
    .line 20
    move-result-object p3

    .line 21
    sget-object v3, Lt4/m;->d:Lt4/m;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    if-eq p3, v3, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Lt3/d1;->f()I

    .line 27
    .line 28
    .line 29
    move-result p3

    .line 30
    if-nez p3, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p0}, Lt3/d1;->f()I

    .line 34
    .line 35
    .line 36
    move-result p3

    .line 37
    iget v3, p1, Lt3/e1;->d:I

    .line 38
    .line 39
    sub-int/2addr p3, v3

    .line 40
    shr-long v7, v1, p2

    .line 41
    .line 42
    long-to-int v3, v7

    .line 43
    sub-int/2addr p3, v3

    .line 44
    and-long/2addr v1, v5

    .line 45
    long-to-int v1, v1

    .line 46
    int-to-long v2, p3

    .line 47
    shl-long p2, v2, p2

    .line 48
    .line 49
    int-to-long v1, v1

    .line 50
    and-long/2addr v1, v5

    .line 51
    or-long/2addr p2, v1

    .line 52
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 53
    .line 54
    .line 55
    iget-wide v1, p1, Lt3/e1;->h:J

    .line 56
    .line 57
    invoke-static {p2, p3, v1, v2}, Lt4/j;->d(JJ)J

    .line 58
    .line 59
    .line 60
    move-result-wide p2

    .line 61
    invoke-virtual {p1, p2, p3, v4, v0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_1
    :goto_0
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 66
    .line 67
    .line 68
    iget-wide p2, p1, Lt3/e1;->h:J

    .line 69
    .line 70
    invoke-static {v1, v2, p2, p3}, Lt4/j;->d(JJ)J

    .line 71
    .line 72
    .line 73
    move-result-wide p2

    .line 74
    invoke-virtual {p1, p2, p3, v4, v0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public static t(Lt3/d1;Lt3/e1;J)V
    .locals 8

    .line 1
    sget v0, Lt3/g1;->b:I

    .line 2
    .line 3
    sget-object v0, Lt3/f1;->g:Lt3/f1;

    .line 4
    .line 5
    invoke-virtual {p0}, Lt3/d1;->d()Lt4/m;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Lt4/m;->d:Lt4/m;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-eq v1, v2, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Lt3/d1;->f()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p0}, Lt3/d1;->f()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    iget v2, p1, Lt3/e1;->d:I

    .line 26
    .line 27
    sub-int/2addr v1, v2

    .line 28
    const/16 v2, 0x20

    .line 29
    .line 30
    shr-long v4, p2, v2

    .line 31
    .line 32
    long-to-int v4, v4

    .line 33
    sub-int/2addr v1, v4

    .line 34
    const-wide v4, 0xffffffffL

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr p2, v4

    .line 40
    long-to-int p2, p2

    .line 41
    int-to-long v6, v1

    .line 42
    shl-long v1, v6, v2

    .line 43
    .line 44
    int-to-long p2, p2

    .line 45
    and-long/2addr p2, v4

    .line 46
    or-long/2addr p2, v1

    .line 47
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 48
    .line 49
    .line 50
    iget-wide v1, p1, Lt3/e1;->h:J

    .line 51
    .line 52
    invoke-static {p2, p3, v1, v2}, Lt4/j;->d(JJ)J

    .line 53
    .line 54
    .line 55
    move-result-wide p2

    .line 56
    invoke-virtual {p1, p2, p3, v3, v0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_1
    :goto_0
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 61
    .line 62
    .line 63
    iget-wide v1, p1, Lt3/e1;->h:J

    .line 64
    .line 65
    invoke-static {p2, p3, v1, v2}, Lt4/j;->d(JJ)J

    .line 66
    .line 67
    .line 68
    move-result-wide p2

    .line 69
    invoke-virtual {p1, p2, p3, v3, v0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public static synthetic z(Lt3/d1;Lt3/e1;IILay0/k;I)V
    .locals 6

    .line 1
    and-int/lit8 p5, p5, 0x8

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    sget p4, Lt3/g1;->b:I

    .line 6
    .line 7
    sget-object p4, Lt3/f1;->g:Lt3/f1;

    .line 8
    .line 9
    :cond_0
    move-object v5, p4

    .line 10
    const/4 v4, 0x0

    .line 11
    move-object v0, p0

    .line 12
    move-object v1, p1

    .line 13
    move v2, p2

    .line 14
    move v3, p3

    .line 15
    invoke-virtual/range {v0 .. v5}, Lt3/d1;->w(Lt3/e1;IIFLay0/k;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public c(Lt3/q;)F
    .locals 0

    .line 1
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 2
    .line 3
    return p0
.end method

.method public abstract d()Lt4/m;
.end method

.method public abstract f()I
.end method

.method public final g(Lt3/e1;IIF)V
    .locals 4

    .line 1
    int-to-long v0, p2

    .line 2
    const/16 p2, 0x20

    .line 3
    .line 4
    shl-long/2addr v0, p2

    .line 5
    int-to-long p2, p3

    .line 6
    const-wide v2, 0xffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    and-long/2addr p2, v2

    .line 12
    or-long/2addr p2, v0

    .line 13
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p1, Lt3/e1;->h:J

    .line 17
    .line 18
    invoke-static {p2, p3, v0, v1}, Lt4/j;->d(JJ)J

    .line 19
    .line 20
    .line 21
    move-result-wide p2

    .line 22
    const/4 p0, 0x0

    .line 23
    invoke-virtual {p1, p2, p3, p4, p0}, Lt3/e1;->l0(JFLay0/k;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final w(Lt3/e1;IIFLay0/k;)V
    .locals 4

    .line 1
    int-to-long v0, p2

    .line 2
    const/16 p2, 0x20

    .line 3
    .line 4
    shl-long/2addr v0, p2

    .line 5
    int-to-long p2, p3

    .line 6
    const-wide v2, 0xffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    and-long/2addr p2, v2

    .line 12
    or-long/2addr p2, v0

    .line 13
    invoke-static {p0, p1}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p1, Lt3/e1;->h:J

    .line 17
    .line 18
    invoke-static {p2, p3, v0, v1}, Lt4/j;->d(JJ)J

    .line 19
    .line 20
    .line 21
    move-result-wide p2

    .line 22
    invoke-virtual {p1, p2, p3, p4, p5}, Lt3/e1;->l0(JFLay0/k;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
