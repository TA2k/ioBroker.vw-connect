.class public abstract Lkp/v8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 13

    .line 1
    move-object v9, p0

    .line 2
    check-cast v9, Ll2/t;

    .line 3
    .line 4
    const p0, 0x5e98fb5

    .line 5
    .line 6
    .line 7
    invoke-virtual {v9, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    and-int/lit8 v0, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {v9, v0, p0}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_5

    .line 22
    .line 23
    const-string p0, "InvoicesFlowScreen"

    .line 24
    .line 25
    invoke-static {p0, v9}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 34
    .line 35
    if-ne v0, v1, :cond_1

    .line 36
    .line 37
    new-instance v0, Lg4/z;

    .line 38
    .line 39
    const/16 v2, 0x15

    .line 40
    .line 41
    invoke-direct {v0, v2}, Lg4/z;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    check-cast v0, Lay0/n;

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    new-instance v2, Ly1/i;

    .line 54
    .line 55
    const/16 v3, 0x11

    .line 56
    .line 57
    invoke-direct {v2, p0, v3}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    if-ne v3, v1, :cond_2

    .line 65
    .line 66
    new-instance v3, Lg4/z;

    .line 67
    .line 68
    const/16 v4, 0x16

    .line 69
    .line 70
    invoke-direct {v3, v4}, Lg4/z;-><init>(I)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v9, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :cond_2
    check-cast v3, Lay0/n;

    .line 77
    .line 78
    invoke-virtual {p0}, Lzb/v0;->b()Lz9/y;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    invoke-virtual {v9, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    or-int/2addr v4, v5

    .line 91
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    if-nez v4, :cond_3

    .line 96
    .line 97
    if-ne v5, v1, :cond_4

    .line 98
    .line 99
    :cond_3
    new-instance v5, Laa/o;

    .line 100
    .line 101
    const/16 v1, 0x12

    .line 102
    .line 103
    invoke-direct {v5, v3, v2, v0, v1}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v9, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_4
    move-object v8, v5

    .line 110
    check-cast v8, Lay0/k;

    .line 111
    .line 112
    const/4 v11, 0x0

    .line 113
    const/16 v12, 0x3fc

    .line 114
    .line 115
    const-string v1, "/overview"

    .line 116
    .line 117
    const/4 v2, 0x0

    .line 118
    const/4 v3, 0x0

    .line 119
    const/4 v4, 0x0

    .line 120
    const/4 v5, 0x0

    .line 121
    const/4 v6, 0x0

    .line 122
    const/4 v7, 0x0

    .line 123
    const/16 v10, 0x30

    .line 124
    .line 125
    move-object v0, p0

    .line 126
    invoke-static/range {v0 .. v12}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_5
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 131
    .line 132
    .line 133
    :goto_1
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-eqz p0, :cond_6

    .line 138
    .line 139
    new-instance v0, Lg4/z;

    .line 140
    .line 141
    const/16 v1, 0x17

    .line 142
    .line 143
    invoke-direct {v0, p1, v1}, Lg4/z;-><init>(II)V

    .line 144
    .line 145
    .line 146
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 147
    .line 148
    :cond_6
    return-void
.end method

.method public static final b([Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 3

    .line 1
    array-length v0, p0

    .line 2
    add-int/lit8 v0, v0, 0x2

    .line 3
    .line 4
    new-array v0, v0, [Ljava/lang/Object;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x6

    .line 8
    invoke-static {v1, p1, v2, p0, v0}, Lmx0/n;->m(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    add-int/lit8 v1, p1, 0x2

    .line 12
    .line 13
    array-length v2, p0

    .line 14
    invoke-static {v1, p1, v2, p0, v0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    aput-object p2, v0, p1

    .line 18
    .line 19
    add-int/lit8 p1, p1, 0x1

    .line 20
    .line 21
    aput-object p3, v0, p1

    .line 22
    .line 23
    return-object v0
.end method

.method public static final c(I[Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 3

    .line 1
    array-length v0, p1

    .line 2
    add-int/lit8 v0, v0, -0x2

    .line 3
    .line 4
    new-array v0, v0, [Ljava/lang/Object;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x6

    .line 8
    invoke-static {v1, p0, v2, p1, v0}, Lmx0/n;->m(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    add-int/lit8 v1, p0, 0x2

    .line 12
    .line 13
    array-length v2, p1

    .line 14
    invoke-static {p0, v1, v2, p1, v0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public static final d(II)I
    .locals 0

    .line 1
    shr-int/2addr p0, p1

    .line 2
    and-int/lit8 p0, p0, 0x1f

    .line 3
    .line 4
    return p0
.end method
