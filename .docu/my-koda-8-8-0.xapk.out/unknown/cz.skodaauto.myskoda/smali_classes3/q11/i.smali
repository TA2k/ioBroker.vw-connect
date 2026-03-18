.class public Lq11/i;
.super Lq11/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:I

.field public final i:Ln11/g;


# direct methods
.method public constructor <init>(Ln11/b;Ln11/g;Ln11/g;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1, p2}, Lq11/f;-><init>(Ln11/b;Ln11/g;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p3}, Ln11/g;->e()Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    if-eqz p1, :cond_1

    .line 9
    .line 10
    invoke-virtual {p3}, Ln11/g;->d()J

    .line 11
    .line 12
    .line 13
    move-result-wide p1

    .line 14
    iget-wide v0, p0, Lq11/f;->f:J

    .line 15
    .line 16
    div-long/2addr p1, v0

    .line 17
    long-to-int p1, p1

    .line 18
    iput p1, p0, Lq11/i;->h:I

    .line 19
    .line 20
    const/4 p2, 0x2

    .line 21
    if-lt p1, p2, :cond_0

    .line 22
    .line 23
    iput-object p3, p0, Lq11/i;->i:Ln11/g;

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 27
    .line 28
    const-string p1, "The effective range must be at least 2"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 35
    .line 36
    const-string p1, "Range duration field must be precise"

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0
.end method


# virtual methods
.method public final b(J)I
    .locals 6

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    iget v1, p0, Lq11/i;->h:I

    .line 6
    .line 7
    iget-wide v2, p0, Lq11/f;->f:J

    .line 8
    .line 9
    if-ltz v0, :cond_0

    .line 10
    .line 11
    div-long/2addr p1, v2

    .line 12
    int-to-long v0, v1

    .line 13
    rem-long/2addr p1, v0

    .line 14
    long-to-int p0, p1

    .line 15
    return p0

    .line 16
    :cond_0
    add-int/lit8 p0, v1, -0x1

    .line 17
    .line 18
    const-wide/16 v4, 0x1

    .line 19
    .line 20
    add-long/2addr p1, v4

    .line 21
    div-long/2addr p1, v2

    .line 22
    int-to-long v0, v1

    .line 23
    rem-long/2addr p1, v0

    .line 24
    long-to-int p1, p1

    .line 25
    add-int/2addr p0, p1

    .line 26
    return p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget p0, p0, Lq11/i;->h:I

    .line 2
    .line 3
    add-int/lit8 p0, p0, -0x1

    .line 4
    .line 5
    return p0
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/i;->i:Ln11/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final v(IJ)J
    .locals 2

    .line 1
    iget v0, p0, Lq11/i;->h:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {p0, p1, v1, v0}, Ljp/je;->g(Ln11/a;III)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p2, p3}, Lq11/i;->b(J)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    sub-int/2addr p1, v0

    .line 14
    int-to-long v0, p1

    .line 15
    iget-wide p0, p0, Lq11/f;->f:J

    .line 16
    .line 17
    mul-long/2addr v0, p0

    .line 18
    add-long/2addr v0, p2

    .line 19
    return-wide v0
.end method
