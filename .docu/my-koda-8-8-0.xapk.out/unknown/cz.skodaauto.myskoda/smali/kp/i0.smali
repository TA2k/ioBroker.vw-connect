.class public abstract Lkp/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Li3/c;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "painter"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    check-cast p2, Ll2/t;

    .line 12
    .line 13
    const v0, -0x65d2a9d1

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/16 v0, 0x20

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/16 v0, 0x10

    .line 29
    .line 30
    :goto_0
    or-int/2addr v0, p3

    .line 31
    and-int/lit8 v1, v0, 0x13

    .line 32
    .line 33
    const/16 v2, 0x12

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    const/4 v4, 0x1

    .line 37
    if-eq v1, v2, :cond_1

    .line 38
    .line 39
    move v1, v4

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v1, v3

    .line 42
    :goto_1
    and-int/2addr v0, v4

    .line 43
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    const/4 v9, 0x0

    .line 50
    const/16 v10, 0x3e

    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    const/4 v7, 0x0

    .line 54
    const/4 v8, 0x0

    .line 55
    move-object v4, p0

    .line 56
    move-object v5, p1

    .line 57
    invoke-static/range {v4 .. v10}, Landroidx/compose/ui/draw/a;->d(Lx2/s;Li3/c;Lx2/e;Lt3/k;FLe3/m;I)Lx2/s;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-static {p0, p2, v3}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_2
    move-object v4, p0

    .line 66
    move-object v5, p1

    .line 67
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 68
    .line 69
    .line 70
    :goto_2
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-eqz p0, :cond_3

    .line 75
    .line 76
    new-instance p1, Ld90/m;

    .line 77
    .line 78
    const/16 p2, 0x8

    .line 79
    .line 80
    invoke-direct {p1, p3, p2, v4, v5}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 84
    .line 85
    :cond_3
    return-void
.end method

.method public static final b(Lx2/s;Li3/c;JLl2/o;I)V
    .locals 9

    .line 1
    const-string v2, "modifier"

    .line 2
    .line 3
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v2, "painter"

    .line 7
    .line 8
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v7, p4

    .line 12
    check-cast v7, Ll2/t;

    .line 13
    .line 14
    const v2, -0x45bb0508

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    and-int/lit8 v2, p5, 0x6

    .line 21
    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    const/4 v2, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v2, 0x2

    .line 33
    :goto_0
    or-int/2addr v2, p5

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v2, p5

    .line 36
    :goto_1
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    const/16 v3, 0x20

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/16 v3, 0x10

    .line 46
    .line 47
    :goto_2
    or-int/2addr v2, v3

    .line 48
    invoke-virtual {v7, p2, p3}, Ll2/t;->f(J)Z

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    if-eqz v3, :cond_3

    .line 53
    .line 54
    const/16 v3, 0x100

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    const/16 v3, 0x80

    .line 58
    .line 59
    :goto_3
    or-int/2addr v2, v3

    .line 60
    and-int/lit16 v3, v2, 0x93

    .line 61
    .line 62
    const/16 v4, 0x92

    .line 63
    .line 64
    const/4 v5, 0x1

    .line 65
    const/4 v8, 0x0

    .line 66
    if-eq v3, v4, :cond_4

    .line 67
    .line 68
    move v3, v5

    .line 69
    goto :goto_4

    .line 70
    :cond_4
    move v3, v8

    .line 71
    :goto_4
    and-int/2addr v2, v5

    .line 72
    invoke-virtual {v7, v2, v3}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_5

    .line 77
    .line 78
    new-instance v5, Le3/m;

    .line 79
    .line 80
    const/4 v2, 0x5

    .line 81
    invoke-direct {v5, p2, p3, v2}, Le3/m;-><init>(JI)V

    .line 82
    .line 83
    .line 84
    const/16 v6, 0x1e

    .line 85
    .line 86
    const/4 v2, 0x0

    .line 87
    const/4 v3, 0x0

    .line 88
    const/4 v4, 0x0

    .line 89
    move-object v0, p0

    .line 90
    move-object v1, p1

    .line 91
    invoke-static/range {v0 .. v6}, Landroidx/compose/ui/draw/a;->d(Lx2/s;Li3/c;Lx2/e;Lt3/k;FLe3/m;I)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-static {v2, v7, v8}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 96
    .line 97
    .line 98
    goto :goto_5

    .line 99
    :cond_5
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 100
    .line 101
    .line 102
    :goto_5
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 103
    .line 104
    .line 105
    move-result-object v6

    .line 106
    if-eqz v6, :cond_6

    .line 107
    .line 108
    new-instance v0, Lc41/d;

    .line 109
    .line 110
    move-object v1, p0

    .line 111
    move-object v2, p1

    .line 112
    move-wide v3, p2

    .line 113
    move v5, p5

    .line 114
    invoke-direct/range {v0 .. v5}, Lc41/d;-><init>(Lx2/s;Li3/c;JI)V

    .line 115
    .line 116
    .line 117
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 118
    .line 119
    :cond_6
    return-void
.end method

.method public static final c(Lri/d;)Llx0/o;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lri/b;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return-object p0

    .line 12
    :cond_0
    instance-of v0, p0, Lri/a;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    check-cast p0, Lri/a;

    .line 17
    .line 18
    iget-object p0, p0, Lri/a;->a:Ljava/lang/Object;

    .line 19
    .line 20
    new-instance v0, Llx0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :cond_1
    instance-of v0, p0, Lri/c;

    .line 27
    .line 28
    if-eqz v0, :cond_2

    .line 29
    .line 30
    check-cast p0, Lri/c;

    .line 31
    .line 32
    iget-object p0, p0, Lri/c;->a:Ljava/lang/Object;

    .line 33
    .line 34
    new-instance v0, Llx0/o;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    return-object v0

    .line 40
    :cond_2
    new-instance p0, La8/r0;

    .line 41
    .line 42
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 43
    .line 44
    .line 45
    throw p0
.end method
