.class public final Lk1/t1;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:Lk1/y;

.field public s:Z

.field public t:Lay0/n;


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 8

    .line 1
    iget-object v0, p0, Lk1/t1;->r:Lk1/y;

    .line 2
    .line 3
    sget-object v1, Lk1/y;->d:Lk1/y;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eq v0, v1, :cond_0

    .line 7
    .line 8
    move v0, v2

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    :goto_0
    iget-object v3, p0, Lk1/t1;->r:Lk1/y;

    .line 15
    .line 16
    sget-object v4, Lk1/y;->e:Lk1/y;

    .line 17
    .line 18
    if-eq v3, v4, :cond_1

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    :goto_1
    iget-object v3, p0, Lk1/t1;->r:Lk1/y;

    .line 26
    .line 27
    const v5, 0x7fffffff

    .line 28
    .line 29
    .line 30
    if-eq v3, v1, :cond_2

    .line 31
    .line 32
    iget-boolean v1, p0, Lk1/t1;->s:Z

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    move v1, v5

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    :goto_2
    iget-object v3, p0, Lk1/t1;->r:Lk1/y;

    .line 43
    .line 44
    if-eq v3, v4, :cond_3

    .line 45
    .line 46
    iget-boolean v3, p0, Lk1/t1;->s:Z

    .line 47
    .line 48
    if-eqz v3, :cond_3

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_3
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    :goto_3
    invoke-static {v0, v1, v2, v5}, Lt4/b;->a(IIII)J

    .line 56
    .line 57
    .line 58
    move-result-wide v0

    .line 59
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    iget p2, v5, Lt3/e1;->d:I

    .line 64
    .line 65
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    invoke-static {p2, v0, v1}, Lkp/r9;->e(III)I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    iget p2, v5, Lt3/e1;->e:I

    .line 78
    .line 79
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 84
    .line 85
    .line 86
    move-result p3

    .line 87
    invoke-static {p2, v0, p3}, Lkp/r9;->e(III)I

    .line 88
    .line 89
    .line 90
    move-result v6

    .line 91
    new-instance v2, Lk1/f1;

    .line 92
    .line 93
    move-object v3, p0

    .line 94
    move-object v7, p1

    .line 95
    invoke-direct/range {v2 .. v7}, Lk1/f1;-><init>(Lk1/t1;ILt3/e1;ILt3/s0;)V

    .line 96
    .line 97
    .line 98
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 99
    .line 100
    invoke-interface {v7, v4, v6, p0, v2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method
