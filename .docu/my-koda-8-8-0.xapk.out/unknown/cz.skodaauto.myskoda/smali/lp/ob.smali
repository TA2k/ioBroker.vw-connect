.class public abstract Llp/ob;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(JLt2/b;Ll2/o;I)V
    .locals 11

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x613390c0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p0, p1}, Ll2/t;->f(J)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x4

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    move v0, v1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x2

    .line 19
    :goto_0
    or-int/2addr v0, p4

    .line 20
    and-int/lit8 v2, v0, 0x13

    .line 21
    .line 22
    const/16 v3, 0x12

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    const/4 v5, 0x1

    .line 26
    if-eq v2, v3, :cond_1

    .line 27
    .line 28
    move v2, v5

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move v2, v4

    .line 31
    :goto_1
    and-int/lit8 v3, v0, 0x1

    .line 32
    .line 33
    invoke-virtual {p3, v3, v2}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_8

    .line 38
    .line 39
    and-int/lit8 v0, v0, 0xe

    .line 40
    .line 41
    if-ne v0, v1, :cond_2

    .line 42
    .line 43
    move v2, v5

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    move v2, v4

    .line 46
    :goto_2
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 51
    .line 52
    if-nez v2, :cond_3

    .line 53
    .line 54
    if-ne v3, v6, :cond_4

    .line 55
    .line 56
    :cond_3
    new-instance v3, Lh2/v7;

    .line 57
    .line 58
    new-instance v2, Lg2/b;

    .line 59
    .line 60
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 65
    .line 66
    .line 67
    move-result v8

    .line 68
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 73
    .line 74
    .line 75
    move-result v10

    .line 76
    invoke-direct {v2, v7, v8, v9, v10}, Lg2/b;-><init>(FFFF)V

    .line 77
    .line 78
    .line 79
    invoke-direct {v3, p0, p1, v2}, Lh2/v7;-><init>(JLg2/b;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p3, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_4
    check-cast v3, Lh2/v7;

    .line 86
    .line 87
    if-ne v0, v1, :cond_5

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_5
    move v5, v4

    .line 91
    :goto_3
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    if-nez v5, :cond_6

    .line 96
    .line 97
    if-ne v0, v6, :cond_7

    .line 98
    .line 99
    :cond_6
    new-instance v0, Lh2/v7;

    .line 100
    .line 101
    new-instance v1, Lg2/b;

    .line 102
    .line 103
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 108
    .line 109
    .line 110
    move-result v5

    .line 111
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 112
    .line 113
    .line 114
    move-result v6

    .line 115
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 116
    .line 117
    .line 118
    move-result v7

    .line 119
    invoke-direct {v1, v2, v5, v6, v7}, Lg2/b;-><init>(FFFF)V

    .line 120
    .line 121
    .line 122
    invoke-direct {v0, p0, p1, v1}, Lh2/v7;-><init>(JLg2/b;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_7
    check-cast v0, Lh2/v7;

    .line 129
    .line 130
    sget-object v1, Landroidx/compose/foundation/c;->a:Ll2/e0;

    .line 131
    .line 132
    const/4 v2, 0x0

    .line 133
    const/4 v5, 0x3

    .line 134
    invoke-static {p0, p1, v2, v5, v4}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    invoke-virtual {v1, v2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    sget-object v2, Lh2/w7;->a:Ll2/e0;

    .line 143
    .line 144
    invoke-virtual {v2, v3}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    invoke-virtual {v2, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    filled-new-array {v1, v3, v0}, [Ll2/t1;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    new-instance v1, Ld71/d;

    .line 157
    .line 158
    const/16 v2, 0xa

    .line 159
    .line 160
    invoke-direct {v1, p2, v2}, Ld71/d;-><init>(Lt2/b;I)V

    .line 161
    .line 162
    .line 163
    const v2, 0x217f8400

    .line 164
    .line 165
    .line 166
    invoke-static {v2, p3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    const/16 v2, 0x38

    .line 171
    .line 172
    invoke-static {v0, v1, p3, v2}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 173
    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_8
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 177
    .line 178
    .line 179
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 180
    .line 181
    .line 182
    move-result-object p3

    .line 183
    if-eqz p3, :cond_9

    .line 184
    .line 185
    new-instance v0, Lj91/g;

    .line 186
    .line 187
    invoke-direct {v0, p0, p1, p2, p4}, Lj91/g;-><init>(JLt2/b;I)V

    .line 188
    .line 189
    .line 190
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 191
    .line 192
    :cond_9
    return-void
.end method

.method public static final b(Lvh/w;Lz9/y;Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move-object/from16 v15, p3

    .line 8
    .line 9
    move-object/from16 v11, p4

    .line 10
    .line 11
    check-cast v11, Ll2/t;

    .line 12
    .line 13
    const v3, -0x71c3aeae

    .line 14
    .line 15
    .line 16
    invoke-virtual {v11, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v9, 0x4

    .line 24
    if-eqz v3, :cond_0

    .line 25
    .line 26
    move v3, v9

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x2

    .line 29
    :goto_0
    or-int v3, p5, v3

    .line 30
    .line 31
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_1

    .line 36
    .line 37
    const/16 v4, 0x20

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v4, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v3, v4

    .line 43
    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    const/16 v10, 0x100

    .line 48
    .line 49
    if-eqz v4, :cond_2

    .line 50
    .line 51
    move v4, v10

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v4, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v3, v4

    .line 56
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    const/16 v12, 0x800

    .line 61
    .line 62
    if-eqz v4, :cond_3

    .line 63
    .line 64
    move v4, v12

    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/16 v4, 0x400

    .line 67
    .line 68
    :goto_3
    or-int v13, v3, v4

    .line 69
    .line 70
    and-int/lit16 v3, v13, 0x493

    .line 71
    .line 72
    const/16 v4, 0x492

    .line 73
    .line 74
    const/4 v14, 0x0

    .line 75
    const/16 v16, 0x1

    .line 76
    .line 77
    if-eq v3, v4, :cond_4

    .line 78
    .line 79
    move/from16 v3, v16

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_4
    move v3, v14

    .line 83
    :goto_4
    and-int/lit8 v4, v13, 0x1

    .line 84
    .line 85
    invoke-virtual {v11, v4, v3}, Ll2/t;->O(IZ)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-eqz v3, :cond_d

    .line 90
    .line 91
    shr-int/lit8 v3, v13, 0x3

    .line 92
    .line 93
    and-int/lit8 v17, v3, 0xe

    .line 94
    .line 95
    iget-object v3, v2, Lz9/y;->b:Lca/g;

    .line 96
    .line 97
    iget-object v3, v3, Lca/g;->z:Lyy0/q1;

    .line 98
    .line 99
    new-instance v4, Lyy0/k1;

    .line 100
    .line 101
    invoke-direct {v4, v3}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 102
    .line 103
    .line 104
    const/16 v7, 0x30

    .line 105
    .line 106
    const/4 v8, 0x2

    .line 107
    move-object v3, v4

    .line 108
    const/4 v4, 0x0

    .line 109
    const/4 v5, 0x0

    .line 110
    move-object v6, v11

    .line 111
    invoke-static/range {v3 .. v8}, Ll2/b;->e(Lyy0/i;Ljava/lang/Object;Lpx0/g;Ll2/o;II)Ll2/b1;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    check-cast v3, Lz9/k;

    .line 120
    .line 121
    if-eqz v3, :cond_5

    .line 122
    .line 123
    iget-object v3, v3, Lz9/k;->e:Lz9/u;

    .line 124
    .line 125
    if-eqz v3, :cond_5

    .line 126
    .line 127
    iget-object v3, v3, Lz9/u;->e:Lca/j;

    .line 128
    .line 129
    iget-object v3, v3, Lca/j;->e:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v3, Ljava/lang/String;

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_5
    move-object v3, v4

    .line 135
    :goto_5
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    and-int/lit16 v6, v13, 0x380

    .line 140
    .line 141
    if-ne v6, v10, :cond_6

    .line 142
    .line 143
    move/from16 v6, v16

    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_6
    move v6, v14

    .line 147
    :goto_6
    or-int/2addr v5, v6

    .line 148
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 153
    .line 154
    if-nez v5, :cond_7

    .line 155
    .line 156
    if-ne v6, v7, :cond_8

    .line 157
    .line 158
    :cond_7
    new-instance v6, Ls10/a0;

    .line 159
    .line 160
    const/16 v5, 0x12

    .line 161
    .line 162
    invoke-direct {v6, v5, v3, v0, v4}, Ls10/a0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    :cond_8
    check-cast v6, Lay0/n;

    .line 169
    .line 170
    invoke-static {v6, v3, v11}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    and-int/lit16 v3, v13, 0x1c00

    .line 174
    .line 175
    if-ne v3, v12, :cond_9

    .line 176
    .line 177
    move/from16 v3, v16

    .line 178
    .line 179
    goto :goto_7

    .line 180
    :cond_9
    move v3, v14

    .line 181
    :goto_7
    and-int/lit8 v4, v13, 0xe

    .line 182
    .line 183
    if-eq v4, v9, :cond_a

    .line 184
    .line 185
    goto :goto_8

    .line 186
    :cond_a
    move/from16 v14, v16

    .line 187
    .line 188
    :goto_8
    or-int/2addr v3, v14

    .line 189
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    if-nez v3, :cond_b

    .line 194
    .line 195
    if-ne v4, v7, :cond_c

    .line 196
    .line 197
    :cond_b
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 198
    .line 199
    const/16 v3, 0x14

    .line 200
    .line 201
    invoke-direct {v4, v3, v15, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    :cond_c
    move-object v10, v4

    .line 208
    check-cast v10, Lay0/k;

    .line 209
    .line 210
    const/4 v13, 0x0

    .line 211
    const/16 v14, 0x3fc

    .line 212
    .line 213
    const-string v3, "INFORMATION_SCREEN"

    .line 214
    .line 215
    const/4 v4, 0x0

    .line 216
    const/4 v5, 0x0

    .line 217
    const/4 v6, 0x0

    .line 218
    const/4 v7, 0x0

    .line 219
    const/4 v8, 0x0

    .line 220
    const/4 v9, 0x0

    .line 221
    move/from16 v12, v17

    .line 222
    .line 223
    invoke-static/range {v2 .. v14}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 224
    .line 225
    .line 226
    goto :goto_9

    .line 227
    :cond_d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 228
    .line 229
    .line 230
    :goto_9
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 231
    .line 232
    .line 233
    move-result-object v7

    .line 234
    if-eqz v7, :cond_e

    .line 235
    .line 236
    new-instance v0, Lo50/p;

    .line 237
    .line 238
    const/16 v6, 0x1b

    .line 239
    .line 240
    move-object/from16 v2, p1

    .line 241
    .line 242
    move-object/from16 v3, p2

    .line 243
    .line 244
    move/from16 v5, p5

    .line 245
    .line 246
    move-object v4, v15

    .line 247
    invoke-direct/range {v0 .. v6}, Lo50/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 248
    .line 249
    .line 250
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 251
    .line 252
    :cond_e
    return-void
.end method

.method public static final c(Lyj/b;Lxh/e;Lzg/c1;Lai/b;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move-object/from16 v10, p4

    .line 6
    .line 7
    check-cast v10, Ll2/t;

    .line 8
    .line 9
    const v0, 0x1a4a643

    .line 10
    .line 11
    .line 12
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    move-object/from16 v15, p0

    .line 16
    .line 17
    invoke-virtual {v10, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v1, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p5, v0

    .line 28
    .line 29
    move-object/from16 v2, p1

    .line 30
    .line 31
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    const/16 v11, 0x20

    .line 36
    .line 37
    if-eqz v5, :cond_1

    .line 38
    .line 39
    move v5, v11

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v5, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v0, v5

    .line 44
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    const/16 v6, 0x100

    .line 49
    .line 50
    if-eqz v5, :cond_2

    .line 51
    .line 52
    move v5, v6

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/16 v5, 0x80

    .line 55
    .line 56
    :goto_2
    or-int/2addr v0, v5

    .line 57
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    if-eqz v5, :cond_3

    .line 62
    .line 63
    const/16 v5, 0x800

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/16 v5, 0x400

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v5

    .line 69
    and-int/lit16 v5, v0, 0x493

    .line 70
    .line 71
    const/16 v7, 0x492

    .line 72
    .line 73
    const/4 v12, 0x1

    .line 74
    const/4 v13, 0x0

    .line 75
    if-eq v5, v7, :cond_4

    .line 76
    .line 77
    move v5, v12

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    move v5, v13

    .line 80
    :goto_4
    and-int/lit8 v7, v0, 0x1

    .line 81
    .line 82
    invoke-virtual {v10, v7, v5}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    if-eqz v5, :cond_1e

    .line 87
    .line 88
    and-int/lit16 v5, v0, 0x380

    .line 89
    .line 90
    if-ne v5, v6, :cond_5

    .line 91
    .line 92
    move v5, v12

    .line 93
    goto :goto_5

    .line 94
    :cond_5
    move v5, v13

    .line 95
    :goto_5
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v6

    .line 99
    or-int/2addr v5, v6

    .line 100
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 105
    .line 106
    if-nez v5, :cond_6

    .line 107
    .line 108
    if-ne v6, v14, :cond_7

    .line 109
    .line 110
    :cond_6
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 111
    .line 112
    const/16 v5, 0x13

    .line 113
    .line 114
    invoke-direct {v6, v5, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_7
    check-cast v6, Lay0/k;

    .line 121
    .line 122
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 123
    .line 124
    invoke-virtual {v10, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    check-cast v5, Ljava/lang/Boolean;

    .line 129
    .line 130
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 131
    .line 132
    .line 133
    move-result v5

    .line 134
    if-eqz v5, :cond_8

    .line 135
    .line 136
    const v5, -0x105bcaaa

    .line 137
    .line 138
    .line 139
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v10, v13}, Ll2/t;->q(Z)V

    .line 143
    .line 144
    .line 145
    const/4 v5, 0x0

    .line 146
    goto :goto_6

    .line 147
    :cond_8
    const v5, 0x31054eee

    .line 148
    .line 149
    .line 150
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 151
    .line 152
    .line 153
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 154
    .line 155
    invoke-virtual {v10, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v5

    .line 159
    check-cast v5, Lhi/a;

    .line 160
    .line 161
    invoke-virtual {v10, v13}, Ll2/t;->q(Z)V

    .line 162
    .line 163
    .line 164
    :goto_6
    new-instance v8, Lvh/i;

    .line 165
    .line 166
    const/4 v7, 0x0

    .line 167
    invoke-direct {v8, v7, v5, v6}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    invoke-static {v10}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 171
    .line 172
    .line 173
    move-result-object v6

    .line 174
    if-eqz v6, :cond_1d

    .line 175
    .line 176
    instance-of v5, v6, Landroidx/lifecycle/k;

    .line 177
    .line 178
    if-eqz v5, :cond_9

    .line 179
    .line 180
    move-object v5, v6

    .line 181
    check-cast v5, Landroidx/lifecycle/k;

    .line 182
    .line 183
    invoke-interface {v5}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 184
    .line 185
    .line 186
    move-result-object v5

    .line 187
    :goto_7
    move-object v9, v5

    .line 188
    goto :goto_8

    .line 189
    :cond_9
    sget-object v5, Lp7/a;->b:Lp7/a;

    .line 190
    .line 191
    goto :goto_7

    .line 192
    :goto_8
    const-class v5, Lvh/y;

    .line 193
    .line 194
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 195
    .line 196
    invoke-virtual {v7, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    const/4 v7, 0x0

    .line 201
    invoke-static/range {v5 .. v10}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 202
    .line 203
    .line 204
    move-result-object v5

    .line 205
    check-cast v5, Lvh/y;

    .line 206
    .line 207
    iget-object v6, v5, Lvh/y;->f:Lyy0/l1;

    .line 208
    .line 209
    invoke-static {v6, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 210
    .line 211
    .line 212
    move-result-object v23

    .line 213
    new-array v6, v13, [Lz9/j0;

    .line 214
    .line 215
    invoke-static {v6, v10}, Ljp/s0;->b([Lz9/j0;Ll2/o;)Lz9/y;

    .line 216
    .line 217
    .line 218
    move-result-object v6

    .line 219
    sget-object v7, Ln7/c;->a:Ll2/s1;

    .line 220
    .line 221
    invoke-virtual {v10, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v7

    .line 225
    check-cast v7, Landroidx/lifecycle/x;

    .line 226
    .line 227
    invoke-virtual {v10, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result v8

    .line 231
    invoke-virtual {v10, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    move-result v9

    .line 235
    or-int/2addr v8, v9

    .line 236
    invoke-virtual {v10, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v9

    .line 240
    or-int/2addr v8, v9

    .line 241
    and-int/lit8 v9, v0, 0xe

    .line 242
    .line 243
    if-ne v9, v1, :cond_a

    .line 244
    .line 245
    move v1, v12

    .line 246
    goto :goto_9

    .line 247
    :cond_a
    move v1, v13

    .line 248
    :goto_9
    or-int/2addr v1, v8

    .line 249
    and-int/lit8 v0, v0, 0x70

    .line 250
    .line 251
    if-ne v0, v11, :cond_b

    .line 252
    .line 253
    move v0, v12

    .line 254
    goto :goto_a

    .line 255
    :cond_b
    move v0, v13

    .line 256
    :goto_a
    or-int/2addr v0, v1

    .line 257
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    if-nez v0, :cond_d

    .line 262
    .line 263
    if-ne v1, v14, :cond_c

    .line 264
    .line 265
    goto :goto_b

    .line 266
    :cond_c
    move-object v11, v1

    .line 267
    move v1, v12

    .line 268
    move v2, v13

    .line 269
    move-object v0, v14

    .line 270
    move-object v13, v5

    .line 271
    move-object v14, v6

    .line 272
    goto :goto_c

    .line 273
    :cond_d
    :goto_b
    new-instance v11, Laa/i0;

    .line 274
    .line 275
    const/16 v17, 0x0

    .line 276
    .line 277
    const/16 v18, 0x16

    .line 278
    .line 279
    move-object/from16 v16, v2

    .line 280
    .line 281
    move v1, v12

    .line 282
    move v2, v13

    .line 283
    move-object v0, v14

    .line 284
    move-object v13, v5

    .line 285
    move-object v14, v6

    .line 286
    move-object v12, v7

    .line 287
    invoke-direct/range {v11 .. v18}, Laa/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v10, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    :goto_c
    check-cast v11, Lay0/n;

    .line 294
    .line 295
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    invoke-static {v11, v5, v10}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 298
    .line 299
    .line 300
    sget-object v5, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 301
    .line 302
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 303
    .line 304
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 305
    .line 306
    invoke-static {v6, v7, v10, v2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 307
    .line 308
    .line 309
    move-result-object v6

    .line 310
    iget-wide v7, v10, Ll2/t;->T:J

    .line 311
    .line 312
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 313
    .line 314
    .line 315
    move-result v7

    .line 316
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 317
    .line 318
    .line 319
    move-result-object v8

    .line 320
    invoke-static {v10, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 321
    .line 322
    .line 323
    move-result-object v5

    .line 324
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 325
    .line 326
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 327
    .line 328
    .line 329
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 330
    .line 331
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 332
    .line 333
    .line 334
    iget-boolean v11, v10, Ll2/t;->S:Z

    .line 335
    .line 336
    if-eqz v11, :cond_e

    .line 337
    .line 338
    invoke-virtual {v10, v9}, Ll2/t;->l(Lay0/a;)V

    .line 339
    .line 340
    .line 341
    goto :goto_d

    .line 342
    :cond_e
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 343
    .line 344
    .line 345
    :goto_d
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 346
    .line 347
    invoke-static {v9, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 348
    .line 349
    .line 350
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 351
    .line 352
    invoke-static {v6, v8, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 353
    .line 354
    .line 355
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 356
    .line 357
    iget-boolean v8, v10, Ll2/t;->S:Z

    .line 358
    .line 359
    if-nez v8, :cond_f

    .line 360
    .line 361
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v8

    .line 365
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 366
    .line 367
    .line 368
    move-result-object v9

    .line 369
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result v8

    .line 373
    if-nez v8, :cond_10

    .line 374
    .line 375
    :cond_f
    invoke-static {v7, v10, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 376
    .line 377
    .line 378
    :cond_10
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 379
    .line 380
    invoke-static {v6, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 381
    .line 382
    .line 383
    invoke-interface/range {v23 .. v23}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v5

    .line 387
    check-cast v5, Lvh/w;

    .line 388
    .line 389
    iget-object v5, v5, Lvh/w;->f:Lvh/u;

    .line 390
    .line 391
    iget-object v5, v5, Lvh/u;->b:Llc/l;

    .line 392
    .line 393
    const v11, -0x730740f7

    .line 394
    .line 395
    .line 396
    if-nez v5, :cond_13

    .line 397
    .line 398
    const v5, -0x72bad33e

    .line 399
    .line 400
    .line 401
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 402
    .line 403
    .line 404
    invoke-static {v10}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 405
    .line 406
    .line 407
    move-result-object v5

    .line 408
    invoke-interface/range {v23 .. v23}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v6

    .line 412
    check-cast v6, Lvh/w;

    .line 413
    .line 414
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 415
    .line 416
    .line 417
    move-result v7

    .line 418
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v8

    .line 422
    if-nez v7, :cond_11

    .line 423
    .line 424
    if-ne v8, v0, :cond_12

    .line 425
    .line 426
    :cond_11
    new-instance v15, Luz/c0;

    .line 427
    .line 428
    const/16 v21, 0x0

    .line 429
    .line 430
    const/16 v22, 0xa

    .line 431
    .line 432
    const/16 v16, 0x1

    .line 433
    .line 434
    const-class v18, Lvh/y;

    .line 435
    .line 436
    const-string v19, "onUiEvent"

    .line 437
    .line 438
    const-string v20, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding2/solar/SolarSystemOnboardingUiEvent;)V"

    .line 439
    .line 440
    move-object/from16 v17, v13

    .line 441
    .line 442
    invoke-direct/range {v15 .. v22}, Luz/c0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 443
    .line 444
    .line 445
    invoke-virtual {v10, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 446
    .line 447
    .line 448
    move-object v8, v15

    .line 449
    :cond_12
    check-cast v8, Lhy0/g;

    .line 450
    .line 451
    check-cast v8, Lay0/k;

    .line 452
    .line 453
    invoke-interface {v5, v6, v8, v10, v2}, Leh/n;->f0(Lvh/w;Lay0/k;Ll2/o;I)V

    .line 454
    .line 455
    .line 456
    :goto_e
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 457
    .line 458
    .line 459
    goto :goto_f

    .line 460
    :cond_13
    invoke-virtual {v10, v11}, Ll2/t;->Y(I)V

    .line 461
    .line 462
    .line 463
    goto :goto_e

    .line 464
    :goto_f
    invoke-interface/range {v23 .. v23}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v5

    .line 468
    check-cast v5, Lvh/w;

    .line 469
    .line 470
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 471
    .line 472
    .line 473
    move-result v6

    .line 474
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 475
    .line 476
    .line 477
    move-result-object v7

    .line 478
    if-nez v6, :cond_14

    .line 479
    .line 480
    if-ne v7, v0, :cond_15

    .line 481
    .line 482
    :cond_14
    new-instance v15, Luz/c0;

    .line 483
    .line 484
    const/16 v21, 0x0

    .line 485
    .line 486
    const/16 v22, 0xb

    .line 487
    .line 488
    const/16 v16, 0x1

    .line 489
    .line 490
    const-class v18, Lvh/y;

    .line 491
    .line 492
    const-string v19, "onRouteChanged"

    .line 493
    .line 494
    const-string v20, "onRouteChanged$kitten_wallboxes_release(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding2/solar/OnboardingNavigationRoute;)V"

    .line 495
    .line 496
    move-object/from16 v17, v13

    .line 497
    .line 498
    invoke-direct/range {v15 .. v22}, Luz/c0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 499
    .line 500
    .line 501
    invoke-virtual {v10, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 502
    .line 503
    .line 504
    move-object v7, v15

    .line 505
    :cond_15
    check-cast v7, Lhy0/g;

    .line 506
    .line 507
    check-cast v7, Lay0/k;

    .line 508
    .line 509
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 510
    .line 511
    .line 512
    move-result v6

    .line 513
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v8

    .line 517
    if-nez v6, :cond_16

    .line 518
    .line 519
    if-ne v8, v0, :cond_17

    .line 520
    .line 521
    :cond_16
    new-instance v15, Luz/c0;

    .line 522
    .line 523
    const/16 v21, 0x0

    .line 524
    .line 525
    const/16 v22, 0xc

    .line 526
    .line 527
    const/16 v16, 0x1

    .line 528
    .line 529
    const-class v18, Lvh/y;

    .line 530
    .line 531
    const-string v19, "onUiEvent"

    .line 532
    .line 533
    const-string v20, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding2/solar/SolarSystemOnboardingUiEvent;)V"

    .line 534
    .line 535
    move-object/from16 v17, v13

    .line 536
    .line 537
    invoke-direct/range {v15 .. v22}, Luz/c0;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 538
    .line 539
    .line 540
    invoke-virtual {v10, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 541
    .line 542
    .line 543
    move-object v8, v15

    .line 544
    :cond_17
    check-cast v8, Lhy0/g;

    .line 545
    .line 546
    check-cast v8, Lay0/k;

    .line 547
    .line 548
    move-object v9, v10

    .line 549
    const/4 v10, 0x0

    .line 550
    move-object v6, v14

    .line 551
    invoke-static/range {v5 .. v10}, Llp/ob;->b(Lvh/w;Lz9/y;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 552
    .line 553
    .line 554
    move-object v10, v9

    .line 555
    invoke-interface/range {v23 .. v23}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 556
    .line 557
    .line 558
    move-result-object v5

    .line 559
    check-cast v5, Lvh/w;

    .line 560
    .line 561
    iget-boolean v5, v5, Lvh/w;->d:Z

    .line 562
    .line 563
    if-eqz v5, :cond_1c

    .line 564
    .line 565
    const v5, -0x72b53902

    .line 566
    .line 567
    .line 568
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 569
    .line 570
    .line 571
    invoke-static {v10}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 572
    .line 573
    .line 574
    move-result-object v5

    .line 575
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 576
    .line 577
    .line 578
    move-result v6

    .line 579
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object v7

    .line 583
    if-nez v6, :cond_18

    .line 584
    .line 585
    if-ne v7, v0, :cond_19

    .line 586
    .line 587
    :cond_18
    new-instance v7, Lvh/h;

    .line 588
    .line 589
    const/4 v6, 0x0

    .line 590
    invoke-direct {v7, v13, v6}, Lvh/h;-><init>(Lvh/y;I)V

    .line 591
    .line 592
    .line 593
    invoke-virtual {v10, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 594
    .line 595
    .line 596
    :cond_19
    check-cast v7, Lay0/a;

    .line 597
    .line 598
    invoke-virtual {v10, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 599
    .line 600
    .line 601
    move-result v6

    .line 602
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    move-result-object v8

    .line 606
    if-nez v6, :cond_1a

    .line 607
    .line 608
    if-ne v8, v0, :cond_1b

    .line 609
    .line 610
    :cond_1a
    new-instance v8, Lvh/h;

    .line 611
    .line 612
    const/4 v0, 0x1

    .line 613
    invoke-direct {v8, v13, v0}, Lvh/h;-><init>(Lvh/y;I)V

    .line 614
    .line 615
    .line 616
    invoke-virtual {v10, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 617
    .line 618
    .line 619
    :cond_1b
    check-cast v8, Lay0/a;

    .line 620
    .line 621
    invoke-interface {v5, v7, v8, v10, v2}, Leh/n;->e(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 622
    .line 623
    .line 624
    :goto_10
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 625
    .line 626
    .line 627
    goto :goto_11

    .line 628
    :cond_1c
    invoke-virtual {v10, v11}, Ll2/t;->Y(I)V

    .line 629
    .line 630
    .line 631
    goto :goto_10

    .line 632
    :goto_11
    invoke-virtual {v10, v1}, Ll2/t;->q(Z)V

    .line 633
    .line 634
    .line 635
    goto :goto_12

    .line 636
    :cond_1d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 637
    .line 638
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 639
    .line 640
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    throw v0

    .line 644
    :cond_1e
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 645
    .line 646
    .line 647
    :goto_12
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 648
    .line 649
    .line 650
    move-result-object v7

    .line 651
    if-eqz v7, :cond_1f

    .line 652
    .line 653
    new-instance v0, Lo50/p;

    .line 654
    .line 655
    const/16 v6, 0x1a

    .line 656
    .line 657
    move-object/from16 v1, p0

    .line 658
    .line 659
    move-object/from16 v2, p1

    .line 660
    .line 661
    move/from16 v5, p5

    .line 662
    .line 663
    invoke-direct/range {v0 .. v6}, Lo50/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 664
    .line 665
    .line 666
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 667
    .line 668
    :cond_1f
    return-void
.end method
