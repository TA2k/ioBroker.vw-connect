.class public final Lb1/r;
.super Lb1/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public s:Lc1/q1;

.field public t:Ll2/b1;

.field public u:Lb1/t;

.field public v:J


# virtual methods
.method public final R0()V
    .locals 2

    .line 1
    sget-wide v0, Landroidx/compose/animation/a;->a:J

    .line 2
    .line 3
    iput-wide v0, p0, Lb1/r;->v:J

    .line 4
    .line 5
    return-void
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 7

    .line 1
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-interface {p1}, Lt3/t;->I()Z

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    const-wide v0, 0xffffffffL

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    const/16 p4, 0x20

    .line 15
    .line 16
    if-eqz p3, :cond_0

    .line 17
    .line 18
    iget p3, p2, Lt3/e1;->d:I

    .line 19
    .line 20
    iget v2, p2, Lt3/e1;->e:I

    .line 21
    .line 22
    int-to-long v3, p3

    .line 23
    shl-long/2addr v3, p4

    .line 24
    int-to-long v5, v2

    .line 25
    and-long/2addr v5, v0

    .line 26
    or-long v2, v3, v5

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    iget-object p3, p0, Lb1/r;->s:Lc1/q1;

    .line 30
    .line 31
    if-nez p3, :cond_1

    .line 32
    .line 33
    iget p3, p2, Lt3/e1;->d:I

    .line 34
    .line 35
    iget v2, p2, Lt3/e1;->e:I

    .line 36
    .line 37
    int-to-long v3, p3

    .line 38
    shl-long/2addr v3, p4

    .line 39
    int-to-long v5, v2

    .line 40
    and-long/2addr v5, v0

    .line 41
    or-long v2, v3, v5

    .line 42
    .line 43
    iput-wide v2, p0, Lb1/r;->v:J

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    iget v2, p2, Lt3/e1;->d:I

    .line 47
    .line 48
    iget v3, p2, Lt3/e1;->e:I

    .line 49
    .line 50
    int-to-long v4, v2

    .line 51
    shl-long/2addr v4, p4

    .line 52
    int-to-long v2, v3

    .line 53
    and-long/2addr v2, v0

    .line 54
    or-long/2addr v2, v4

    .line 55
    new-instance v4, Lb1/q;

    .line 56
    .line 57
    const/4 v5, 0x0

    .line 58
    invoke-direct {v4, p0, v2, v3, v5}, Lb1/q;-><init>(Ljava/lang/Object;JI)V

    .line 59
    .line 60
    .line 61
    new-instance v5, Lb1/q;

    .line 62
    .line 63
    const/4 v6, 0x1

    .line 64
    invoke-direct {v5, p0, v2, v3, v6}, Lb1/q;-><init>(Ljava/lang/Object;JI)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p3, v4, v5}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 68
    .line 69
    .line 70
    move-result-object p3

    .line 71
    iget-object v2, p0, Lb1/r;->u:Lb1/t;

    .line 72
    .line 73
    iput-object p3, v2, Lb1/t;->f:Lc1/p1;

    .line 74
    .line 75
    invoke-virtual {p3}, Lc1/p1;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Lt4/l;

    .line 80
    .line 81
    iget-wide v2, v2, Lt4/l;->a:J

    .line 82
    .line 83
    invoke-virtual {p3}, Lc1/p1;->getValue()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p3

    .line 87
    check-cast p3, Lt4/l;

    .line 88
    .line 89
    iget-wide v4, p3, Lt4/l;->a:J

    .line 90
    .line 91
    iput-wide v4, p0, Lb1/r;->v:J

    .line 92
    .line 93
    :goto_0
    shr-long p3, v2, p4

    .line 94
    .line 95
    long-to-int p3, p3

    .line 96
    and-long/2addr v0, v2

    .line 97
    long-to-int p4, v0

    .line 98
    new-instance v0, Lb1/p;

    .line 99
    .line 100
    invoke-direct {v0, p0, p2, v2, v3}, Lb1/p;-><init>(Lb1/r;Lt3/e1;J)V

    .line 101
    .line 102
    .line 103
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 104
    .line 105
    invoke-interface {p1, p3, p4, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0
.end method
