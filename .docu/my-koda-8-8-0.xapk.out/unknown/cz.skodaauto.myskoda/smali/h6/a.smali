.class public final Lh6/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public c:F

.field public d:F

.field public e:J

.field public f:J

.field public g:J

.field public h:F

.field public i:I


# virtual methods
.method public final a(J)F
    .locals 8

    .line 1
    iget-wide v0, p0, Lh6/a;->e:J

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    if-gez v2, :cond_0

    .line 7
    .line 8
    return v3

    .line 9
    :cond_0
    iget-wide v4, p0, Lh6/a;->g:J

    .line 10
    .line 11
    const-wide/16 v6, 0x0

    .line 12
    .line 13
    cmp-long v2, v4, v6

    .line 14
    .line 15
    const/high16 v6, 0x3f800000    # 1.0f

    .line 16
    .line 17
    if-ltz v2, :cond_2

    .line 18
    .line 19
    cmp-long v2, p1, v4

    .line 20
    .line 21
    if-gez v2, :cond_1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    sub-long/2addr p1, v4

    .line 25
    iget v0, p0, Lh6/a;->h:F

    .line 26
    .line 27
    sub-float v1, v6, v0

    .line 28
    .line 29
    long-to-float p1, p1

    .line 30
    iget p0, p0, Lh6/a;->i:I

    .line 31
    .line 32
    int-to-float p0, p0

    .line 33
    div-float/2addr p1, p0

    .line 34
    invoke-static {p1, v3, v6}, Lh6/d;->b(FFF)F

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    mul-float/2addr p0, v0

    .line 39
    add-float/2addr p0, v1

    .line 40
    return p0

    .line 41
    :cond_2
    :goto_0
    sub-long/2addr p1, v0

    .line 42
    long-to-float p1, p1

    .line 43
    iget p0, p0, Lh6/a;->a:I

    .line 44
    .line 45
    int-to-float p0, p0

    .line 46
    div-float/2addr p1, p0

    .line 47
    invoke-static {p1, v3, v6}, Lh6/d;->b(FFF)F

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    const/high16 p1, 0x3f000000    # 0.5f

    .line 52
    .line 53
    mul-float/2addr p0, p1

    .line 54
    return p0
.end method
