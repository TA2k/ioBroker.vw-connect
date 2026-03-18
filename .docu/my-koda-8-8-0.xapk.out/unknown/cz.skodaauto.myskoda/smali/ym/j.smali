.class public final Lym/j;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:I

.field public s:I


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 7

    .line 1
    const-string v0, "measurable"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lym/j;->r:I

    .line 7
    .line 8
    iget v1, p0, Lym/j;->s:I

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkp/f9;->a(II)J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-static {p3, p4, v0, v1}, Lt4/b;->d(JJ)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/16 v3, 0x20

    .line 23
    .line 24
    const v4, 0x7fffffff

    .line 25
    .line 26
    .line 27
    if-ne v2, v4, :cond_0

    .line 28
    .line 29
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eq v2, v4, :cond_0

    .line 34
    .line 35
    shr-long p3, v0, v3

    .line 36
    .line 37
    long-to-int p3, p3

    .line 38
    iget p4, p0, Lym/j;->s:I

    .line 39
    .line 40
    mul-int/2addr p4, p3

    .line 41
    iget p0, p0, Lym/j;->r:I

    .line 42
    .line 43
    div-int/2addr p4, p0

    .line 44
    invoke-static {p3, p3, p4, p4}, Lt4/b;->a(IIII)J

    .line 45
    .line 46
    .line 47
    move-result-wide p3

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    const-wide v5, 0xffffffffL

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    if-ne v2, v4, :cond_1

    .line 59
    .line 60
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 61
    .line 62
    .line 63
    move-result p3

    .line 64
    if-eq p3, v4, :cond_1

    .line 65
    .line 66
    and-long p3, v0, v5

    .line 67
    .line 68
    long-to-int p3, p3

    .line 69
    iget p4, p0, Lym/j;->r:I

    .line 70
    .line 71
    mul-int/2addr p4, p3

    .line 72
    iget p0, p0, Lym/j;->s:I

    .line 73
    .line 74
    div-int/2addr p4, p0

    .line 75
    invoke-static {p4, p4, p3, p3}, Lt4/b;->a(IIII)J

    .line 76
    .line 77
    .line 78
    move-result-wide p3

    .line 79
    goto :goto_0

    .line 80
    :cond_1
    shr-long p3, v0, v3

    .line 81
    .line 82
    long-to-int p0, p3

    .line 83
    and-long p3, v0, v5

    .line 84
    .line 85
    long-to-int p3, p3

    .line 86
    invoke-static {p0, p0, p3, p3}, Lt4/b;->a(IIII)J

    .line 87
    .line 88
    .line 89
    move-result-wide p3

    .line 90
    :goto_0
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    iget p2, p0, Lt3/e1;->d:I

    .line 95
    .line 96
    iget p3, p0, Lt3/e1;->e:I

    .line 97
    .line 98
    new-instance p4, Lb1/y;

    .line 99
    .line 100
    const/16 v0, 0x8

    .line 101
    .line 102
    invoke-direct {p4, p0, v0}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 103
    .line 104
    .line 105
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 106
    .line 107
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0
.end method
