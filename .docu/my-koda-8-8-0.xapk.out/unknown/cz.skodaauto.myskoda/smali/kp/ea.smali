.class public abstract Lkp/ea;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lp1/v;)F
    .locals 4

    .line 1
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, Lp1/o;->e:Lg1/w1;

    .line 6
    .line 7
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lp1/v;->p()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    const/16 p0, 0x20

    .line 16
    .line 17
    shr-long/2addr v0, p0

    .line 18
    long-to-int p0, v0

    .line 19
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_0
    invoke-virtual {p0}, Lp1/v;->p()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    const-wide v2, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v0, v2

    .line 34
    long-to-int p0, v0

    .line 35
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    return p0
.end method

.method public static final b(Lp1/v;F)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v0, v0, Lp1/o;->h:Z

    .line 6
    .line 7
    invoke-virtual {p0}, Lp1/v;->q()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    neg-float p0, p1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-static {p0}, Lkp/ea;->a(Lp1/v;)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    :goto_0
    const/4 p1, 0x0

    .line 20
    cmpl-float p0, p0, p1

    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    const/4 v1, 0x1

    .line 24
    if-lez p0, :cond_1

    .line 25
    .line 26
    move p0, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move p0, p1

    .line 29
    :goto_1
    if-eqz p0, :cond_2

    .line 30
    .line 31
    if-nez v0, :cond_3

    .line 32
    .line 33
    :cond_2
    if-nez p0, :cond_4

    .line 34
    .line 35
    if-nez v0, :cond_4

    .line 36
    .line 37
    :cond_3
    return v1

    .line 38
    :cond_4
    return p1
.end method

.method public static final c(Landroid/text/style/LeadingMarginSpan;)Z
    .locals 1

    .line 1
    instance-of v0, p0, Landroid/text/style/QuoteSpan;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    instance-of v0, p0, Landroid/text/style/BulletSpan;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    instance-of v0, p0, Landroid/text/style/IconMarginSpan;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    instance-of v0, p0, Landroid/text/style/DrawableMarginSpan;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    instance-of p0, p0, Landroid/text/style/LeadingMarginSpan$Standard;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 25
    return p0
.end method
