.class public abstract Lt4/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(IIII)J
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-lt p1, p0, :cond_0

    .line 4
    .line 5
    move v2, v1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v2, v0

    .line 8
    :goto_0
    if-lt p3, p2, :cond_1

    .line 9
    .line 10
    move v3, v1

    .line 11
    goto :goto_1

    .line 12
    :cond_1
    move v3, v0

    .line 13
    :goto_1
    and-int/2addr v2, v3

    .line 14
    if-ltz p0, :cond_2

    .line 15
    .line 16
    move v3, v1

    .line 17
    goto :goto_2

    .line 18
    :cond_2
    move v3, v0

    .line 19
    :goto_2
    and-int/2addr v2, v3

    .line 20
    if-ltz p2, :cond_3

    .line 21
    .line 22
    move v0, v1

    .line 23
    :cond_3
    and-int/2addr v0, v2

    .line 24
    if-nez v0, :cond_4

    .line 25
    .line 26
    const-string v0, "maxWidth must be >= than minWidth,\nmaxHeight must be >= than minHeight,\nminWidth and minHeight must be >= 0"

    .line 27
    .line 28
    invoke-static {v0}, Lt4/i;->a(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :cond_4
    invoke-static {p0, p1, p2, p3}, Lt4/b;->h(IIII)J

    .line 32
    .line 33
    .line 34
    move-result-wide p0

    .line 35
    return-wide p0
.end method

.method public static synthetic b(III)J
    .locals 2

    .line 1
    and-int/lit8 v0, p2, 0x2

    .line 2
    .line 3
    const v1, 0x7fffffff

    .line 4
    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move p0, v1

    .line 9
    :cond_0
    and-int/lit8 p2, p2, 0x8

    .line 10
    .line 11
    if-eqz p2, :cond_1

    .line 12
    .line 13
    move p1, v1

    .line 14
    :cond_1
    const/4 p2, 0x0

    .line 15
    invoke-static {p2, p0, p2, p1}, Lt4/b;->a(IIII)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0
.end method

.method public static final c(I)I
    .locals 1

    .line 1
    const/16 v0, 0x1fff

    .line 2
    .line 3
    if-ge p0, v0, :cond_0

    .line 4
    .line 5
    const/16 p0, 0xd

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    const/16 v0, 0x7fff

    .line 9
    .line 10
    if-ge p0, v0, :cond_1

    .line 11
    .line 12
    const/16 p0, 0xf

    .line 13
    .line 14
    return p0

    .line 15
    :cond_1
    const v0, 0xffff

    .line 16
    .line 17
    .line 18
    if-ge p0, v0, :cond_2

    .line 19
    .line 20
    const/16 p0, 0x10

    .line 21
    .line 22
    return p0

    .line 23
    :cond_2
    const v0, 0x3ffff

    .line 24
    .line 25
    .line 26
    if-ge p0, v0, :cond_3

    .line 27
    .line 28
    const/16 p0, 0x12

    .line 29
    .line 30
    return p0

    .line 31
    :cond_3
    const/16 p0, 0xff

    .line 32
    .line 33
    return p0
.end method

.method public static final d(JJ)J
    .locals 5

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shr-long v1, p2, v0

    .line 4
    .line 5
    long-to-int v1, v1

    .line 6
    invoke-static {p0, p1}, Lt4/a;->j(J)I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    invoke-static {p0, p1}, Lt4/a;->h(J)I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-ge v1, v2, :cond_0

    .line 15
    .line 16
    move v1, v2

    .line 17
    :cond_0
    if-le v1, v3, :cond_1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    move v3, v1

    .line 21
    :goto_0
    const-wide v1, 0xffffffffL

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    and-long/2addr p2, v1

    .line 27
    long-to-int p2, p2

    .line 28
    invoke-static {p0, p1}, Lt4/a;->i(J)I

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    invoke-static {p0, p1}, Lt4/a;->g(J)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-ge p2, p3, :cond_2

    .line 37
    .line 38
    move p2, p3

    .line 39
    :cond_2
    if-le p2, p0, :cond_3

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_3
    move p0, p2

    .line 43
    :goto_1
    int-to-long p1, v3

    .line 44
    shl-long/2addr p1, v0

    .line 45
    int-to-long v3, p0

    .line 46
    and-long v0, v3, v1

    .line 47
    .line 48
    or-long p0, p1, v0

    .line 49
    .line 50
    return-wide p0
.end method

.method public static final e(JJ)J
    .locals 4

    .line 1
    invoke-static {p0, p1}, Lt4/a;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0, p1}, Lt4/a;->h(J)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-static {p0, p1}, Lt4/a;->i(J)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-static {p0, p1}, Lt4/a;->g(J)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-static {p2, p3}, Lt4/a;->j(J)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-ge p1, v0, :cond_0

    .line 22
    .line 23
    move p1, v0

    .line 24
    :cond_0
    if-le p1, v1, :cond_1

    .line 25
    .line 26
    move p1, v1

    .line 27
    :cond_1
    invoke-static {p2, p3}, Lt4/a;->h(J)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-ge v3, v0, :cond_2

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    move v0, v3

    .line 35
    :goto_0
    if-le v0, v1, :cond_3

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_3
    move v1, v0

    .line 39
    :goto_1
    invoke-static {p2, p3}, Lt4/a;->i(J)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-ge v0, v2, :cond_4

    .line 44
    .line 45
    move v0, v2

    .line 46
    :cond_4
    if-le v0, p0, :cond_5

    .line 47
    .line 48
    move v0, p0

    .line 49
    :cond_5
    invoke-static {p2, p3}, Lt4/a;->g(J)I

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    if-ge p2, v2, :cond_6

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_6
    move v2, p2

    .line 57
    :goto_2
    if-le v2, p0, :cond_7

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_7
    move p0, v2

    .line 61
    :goto_3
    invoke-static {p1, v1, v0, p0}, Lt4/b;->a(IIII)J

    .line 62
    .line 63
    .line 64
    move-result-wide p0

    .line 65
    return-wide p0
.end method

.method public static final f(IJ)I
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lt4/a;->i(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, p2}, Lt4/a;->g(J)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-ge p0, v0, :cond_0

    .line 10
    .line 11
    move p0, v0

    .line 12
    :cond_0
    if-le p0, p1, :cond_1

    .line 13
    .line 14
    return p1

    .line 15
    :cond_1
    return p0
.end method

.method public static final g(IJ)I
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lt4/a;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-ge p0, v0, :cond_0

    .line 10
    .line 11
    move p0, v0

    .line 12
    :cond_0
    if-le p0, p1, :cond_1

    .line 13
    .line 14
    return p1

    .line 15
    :cond_1
    return p0
.end method

.method public static final h(IIII)J
    .locals 6

    .line 1
    const v0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    if-ne p3, v0, :cond_0

    .line 5
    .line 6
    move v1, p2

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v1, p3

    .line 9
    :goto_0
    invoke-static {v1}, Lt4/b;->c(I)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-ne p1, v0, :cond_1

    .line 14
    .line 15
    move v0, p0

    .line 16
    goto :goto_1

    .line 17
    :cond_1
    move v0, p1

    .line 18
    :goto_1
    invoke-static {v0}, Lt4/b;->c(I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    add-int/2addr v2, v3

    .line 23
    const/16 v4, 0x1f

    .line 24
    .line 25
    if-le v2, v4, :cond_2

    .line 26
    .line 27
    invoke-static {v0, v1}, Lt4/b;->k(II)V

    .line 28
    .line 29
    .line 30
    :cond_2
    add-int/lit8 p1, p1, 0x1

    .line 31
    .line 32
    shr-int/lit8 v0, p1, 0x1f

    .line 33
    .line 34
    not-int v0, v0

    .line 35
    and-int/2addr p1, v0

    .line 36
    add-int/lit8 p3, p3, 0x1

    .line 37
    .line 38
    shr-int/lit8 v0, p3, 0x1f

    .line 39
    .line 40
    not-int v0, v0

    .line 41
    and-int/2addr p3, v0

    .line 42
    add-int/lit8 v0, v3, -0xd

    .line 43
    .line 44
    shr-int/lit8 v1, v0, 0x1

    .line 45
    .line 46
    and-int/lit8 v0, v0, 0x1

    .line 47
    .line 48
    add-int/2addr v1, v0

    .line 49
    add-int/lit8 v0, v3, 0x2

    .line 50
    .line 51
    add-int/lit8 v3, v3, 0x21

    .line 52
    .line 53
    int-to-long v1, v1

    .line 54
    int-to-long v4, p0

    .line 55
    const/4 p0, 0x2

    .line 56
    shl-long/2addr v4, p0

    .line 57
    or-long/2addr v1, v4

    .line 58
    int-to-long p0, p1

    .line 59
    const/16 v4, 0x21

    .line 60
    .line 61
    shl-long/2addr p0, v4

    .line 62
    or-long/2addr p0, v1

    .line 63
    int-to-long v1, p2

    .line 64
    shl-long v0, v1, v0

    .line 65
    .line 66
    or-long/2addr p0, v0

    .line 67
    int-to-long p2, p3

    .line 68
    shl-long/2addr p2, v3

    .line 69
    or-long/2addr p0, p2

    .line 70
    return-wide p0
.end method

.method public static final i(JII)J
    .locals 4

    .line 1
    invoke-static {p0, p1}, Lt4/a;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/2addr v0, p2

    .line 6
    const/4 v1, 0x0

    .line 7
    if-gez v0, :cond_0

    .line 8
    .line 9
    move v0, v1

    .line 10
    :cond_0
    invoke-static {p0, p1}, Lt4/a;->h(J)I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const v3, 0x7fffffff

    .line 15
    .line 16
    .line 17
    if-ne v2, v3, :cond_1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    add-int/2addr v2, p2

    .line 21
    if-gez v2, :cond_2

    .line 22
    .line 23
    move v2, v1

    .line 24
    :cond_2
    :goto_0
    invoke-static {p0, p1}, Lt4/a;->i(J)I

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    add-int/2addr p2, p3

    .line 29
    if-gez p2, :cond_3

    .line 30
    .line 31
    move p2, v1

    .line 32
    :cond_3
    invoke-static {p0, p1}, Lt4/a;->g(J)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-ne p0, v3, :cond_5

    .line 37
    .line 38
    :cond_4
    move v1, p0

    .line 39
    goto :goto_1

    .line 40
    :cond_5
    add-int/2addr p0, p3

    .line 41
    if-gez p0, :cond_4

    .line 42
    .line 43
    :goto_1
    invoke-static {v0, v2, p2, v1}, Lt4/b;->a(IIII)J

    .line 44
    .line 45
    .line 46
    move-result-wide p0

    .line 47
    return-wide p0
.end method

.method public static synthetic j(JIII)J
    .locals 2

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p2, v1

    .line 7
    :cond_0
    and-int/lit8 p4, p4, 0x2

    .line 8
    .line 9
    if-eqz p4, :cond_1

    .line 10
    .line 11
    move p3, v1

    .line 12
    :cond_1
    invoke-static {p0, p1, p2, p3}, Lt4/b;->i(JII)J

    .line 13
    .line 14
    .line 15
    move-result-wide p0

    .line 16
    return-wide p0
.end method

.method public static final k(II)V
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2
    .line 3
    const-string v1, " and height of "

    .line 4
    .line 5
    const-string v2, " in Constraints"

    .line 6
    .line 7
    const-string v3, "Can\'t represent a width of "

    .line 8
    .line 9
    invoke-static {p0, p1, v3, v1, v2}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw v0
.end method

.method public static final l(I)Ljava/lang/Void;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2
    .line 3
    const-string v1, "Can\'t represent a size of "

    .line 4
    .line 5
    const-string v2, " in Constraints"

    .line 6
    .line 7
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    throw v0
.end method
