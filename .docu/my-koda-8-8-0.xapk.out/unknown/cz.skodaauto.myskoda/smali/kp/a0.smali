.class public abstract Lkp/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lz70/a;Lr31/j;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x4db9cf67    # 3.8967216E8f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p4

    .line 19
    and-int/lit8 v1, p4, 0x30

    .line 20
    .line 21
    if-nez v1, :cond_3

    .line 22
    .line 23
    and-int/lit8 v1, p4, 0x40

    .line 24
    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    :goto_1
    if-eqz v1, :cond_2

    .line 37
    .line 38
    const/16 v1, 0x20

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/16 v1, 0x10

    .line 42
    .line 43
    :goto_2
    or-int/2addr v0, v1

    .line 44
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 45
    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_4

    .line 53
    .line 54
    const/16 v1, 0x100

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_4
    const/16 v1, 0x80

    .line 58
    .line 59
    :goto_3
    or-int/2addr v0, v1

    .line 60
    :cond_5
    and-int/lit16 v1, v0, 0x93

    .line 61
    .line 62
    const/16 v2, 0x92

    .line 63
    .line 64
    const/4 v3, 0x0

    .line 65
    const/4 v4, 0x1

    .line 66
    if-eq v1, v2, :cond_6

    .line 67
    .line 68
    move v1, v4

    .line 69
    goto :goto_4

    .line 70
    :cond_6
    move v1, v3

    .line 71
    :goto_4
    and-int/2addr v0, v4

    .line 72
    invoke-virtual {p3, v0, v1}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_7

    .line 77
    .line 78
    new-instance v0, Laa/w;

    .line 79
    .line 80
    const/16 v1, 0x1c

    .line 81
    .line 82
    invoke-direct {v0, p1, p2, p0, v1}, Laa/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    const v1, 0x18006779

    .line 86
    .line 87
    .line 88
    invoke-static {v1, p3, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    const/16 v1, 0x30

    .line 93
    .line 94
    invoke-static {v3, v0, p3, v1, v4}, Llp/pb;->b(ZLt2/b;Ll2/o;II)V

    .line 95
    .line 96
    .line 97
    goto :goto_5

    .line 98
    :cond_7
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 99
    .line 100
    .line 101
    :goto_5
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 102
    .line 103
    .line 104
    move-result-object p3

    .line 105
    if-eqz p3, :cond_8

    .line 106
    .line 107
    new-instance v0, La2/f;

    .line 108
    .line 109
    const/16 v2, 0xd

    .line 110
    .line 111
    move-object v3, p0

    .line 112
    move-object v4, p1

    .line 113
    move-object v5, p2

    .line 114
    move v1, p4

    .line 115
    invoke-direct/range {v0 .. v5}, La2/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 119
    .line 120
    :cond_8
    return-void
.end method

.method public static final b(Lz70/a;Lay0/k;Lr31/j;Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "setAppBarTitle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewState"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "onEvent"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "onFeatureStep"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    move-object/from16 v0, p5

    .line 22
    .line 23
    check-cast v0, Ll2/t;

    .line 24
    .line 25
    const v1, 0x41c0aae9

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    const/4 v1, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v1, 0x2

    .line 40
    :goto_0
    or-int v1, p6, v1

    .line 41
    .line 42
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    const/16 v3, 0x20

    .line 47
    .line 48
    if-eqz v2, :cond_1

    .line 49
    .line 50
    move v2, v3

    .line 51
    goto :goto_1

    .line 52
    :cond_1
    const/16 v2, 0x10

    .line 53
    .line 54
    :goto_1
    or-int/2addr v1, v2

    .line 55
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_2

    .line 60
    .line 61
    const/16 v2, 0x100

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    const/16 v2, 0x80

    .line 65
    .line 66
    :goto_2
    or-int/2addr v1, v2

    .line 67
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_3

    .line 72
    .line 73
    const/16 v2, 0x800

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_3
    const/16 v2, 0x400

    .line 77
    .line 78
    :goto_3
    or-int/2addr v1, v2

    .line 79
    invoke-virtual {v0, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    const/16 v6, 0x4000

    .line 84
    .line 85
    if-eqz v2, :cond_4

    .line 86
    .line 87
    move v2, v6

    .line 88
    goto :goto_4

    .line 89
    :cond_4
    const/16 v2, 0x2000

    .line 90
    .line 91
    :goto_4
    or-int/2addr v1, v2

    .line 92
    and-int/lit16 v2, v1, 0x2493

    .line 93
    .line 94
    const/16 v7, 0x2492

    .line 95
    .line 96
    const/4 v8, 0x0

    .line 97
    const/4 v9, 0x1

    .line 98
    if-eq v2, v7, :cond_5

    .line 99
    .line 100
    move v2, v9

    .line 101
    goto :goto_5

    .line 102
    :cond_5
    move v2, v8

    .line 103
    :goto_5
    and-int/lit8 v7, v1, 0x1

    .line 104
    .line 105
    invoke-virtual {v0, v7, v2}, Ll2/t;->O(IZ)Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_a

    .line 110
    .line 111
    const v2, 0x7f1207ae

    .line 112
    .line 113
    .line 114
    invoke-static {v0, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    and-int/lit8 v2, v1, 0x70

    .line 119
    .line 120
    if-ne v2, v3, :cond_6

    .line 121
    .line 122
    move v2, v9

    .line 123
    goto :goto_6

    .line 124
    :cond_6
    move v2, v8

    .line 125
    :goto_6
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    or-int/2addr v2, v3

    .line 130
    const v3, 0xe000

    .line 131
    .line 132
    .line 133
    and-int/2addr v3, v1

    .line 134
    if-ne v3, v6, :cond_7

    .line 135
    .line 136
    move v8, v9

    .line 137
    :cond_7
    or-int/2addr v2, v8

    .line 138
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    if-nez v2, :cond_8

    .line 143
    .line 144
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 145
    .line 146
    if-ne v3, v2, :cond_9

    .line 147
    .line 148
    :cond_8
    new-instance v5, Ld41/b;

    .line 149
    .line 150
    const/4 v9, 0x0

    .line 151
    const/4 v10, 0x1

    .line 152
    move-object v6, p1

    .line 153
    move-object v8, p4

    .line 154
    invoke-direct/range {v5 .. v10}, Ld41/b;-><init>(Lay0/k;Ljava/lang/String;Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    move-object v3, v5

    .line 161
    :cond_9
    check-cast v3, Lay0/n;

    .line 162
    .line 163
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    invoke-static {v3, v2, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    and-int/lit8 v2, v1, 0xe

    .line 169
    .line 170
    shr-int/lit8 v1, v1, 0x3

    .line 171
    .line 172
    and-int/lit8 v3, v1, 0x70

    .line 173
    .line 174
    or-int/2addr v2, v3

    .line 175
    and-int/lit16 v1, v1, 0x380

    .line 176
    .line 177
    or-int/2addr v1, v2

    .line 178
    invoke-static {p0, p2, p3, v0, v1}, Lkp/a0;->a(Lz70/a;Lr31/j;Lay0/k;Ll2/o;I)V

    .line 179
    .line 180
    .line 181
    goto :goto_7

    .line 182
    :cond_a
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    :goto_7
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 186
    .line 187
    .line 188
    move-result-object v8

    .line 189
    if-eqz v8, :cond_b

    .line 190
    .line 191
    new-instance v0, Lb10/c;

    .line 192
    .line 193
    const/4 v7, 0x5

    .line 194
    move-object v1, p0

    .line 195
    move-object v2, p1

    .line 196
    move-object v3, p2

    .line 197
    move-object v4, p3

    .line 198
    move-object v5, p4

    .line 199
    move/from16 v6, p6

    .line 200
    .line 201
    invoke-direct/range {v0 .. v7}, Lb10/c;-><init>(Ljava/lang/Object;Lay0/k;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 202
    .line 203
    .line 204
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 205
    .line 206
    :cond_b
    return-void
.end method

.method public static final c(Lrd0/b0;Z)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    iget-object p0, p0, Lrd0/b0;->a:Lrd0/j;

    .line 9
    .line 10
    iget-object p0, p0, Lrd0/j;->e:Lrd0/i;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Lrd0/i;->b:Lrd0/h;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    sget-object p1, Lrd0/h;->j:Lrd0/h;

    .line 19
    .line 20
    if-ne p0, p1, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public static final d(Lrd0/b0;Z)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lrd0/h;->j:Lrd0/h;

    .line 7
    .line 8
    sget-object v1, Lrd0/h;->i:Lrd0/h;

    .line 9
    .line 10
    filled-new-array {v0, v1}, [Lrd0/h;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    check-cast v0, Ljava/lang/Iterable;

    .line 21
    .line 22
    iget-object p0, p0, Lrd0/b0;->a:Lrd0/j;

    .line 23
    .line 24
    iget-object p0, p0, Lrd0/j;->e:Lrd0/i;

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    iget-object p0, p0, Lrd0/i;->b:Lrd0/h;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    :goto_0
    invoke-static {v0, p0}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    return p0

    .line 40
    :cond_1
    const/4 p0, 0x0

    .line 41
    return p0
.end method
