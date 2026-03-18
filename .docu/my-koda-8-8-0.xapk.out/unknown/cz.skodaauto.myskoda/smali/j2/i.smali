.class public abstract Lj2/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F

.field public static final f:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-wide/high16 v0, 0x4004000000000000L    # 2.5

    .line 2
    .line 3
    double-to-float v0, v0

    .line 4
    sput v0, Lj2/i;->a:F

    .line 5
    .line 6
    const-wide/high16 v0, 0x4016000000000000L    # 5.5

    .line 7
    .line 8
    double-to-float v0, v0

    .line 9
    sput v0, Lj2/i;->b:F

    .line 10
    .line 11
    const/16 v0, 0x10

    .line 12
    .line 13
    int-to-float v0, v0

    .line 14
    sput v0, Lj2/i;->c:F

    .line 15
    .line 16
    const/16 v0, 0x28

    .line 17
    .line 18
    int-to-float v0, v0

    .line 19
    sput v0, Lj2/i;->d:F

    .line 20
    .line 21
    const/16 v0, 0xa

    .line 22
    .line 23
    int-to-float v0, v0

    .line 24
    sput v0, Lj2/i;->e:F

    .line 25
    .line 26
    const/4 v0, 0x5

    .line 27
    int-to-float v0, v0

    .line 28
    sput v0, Lj2/i;->f:F

    .line 29
    .line 30
    return-void
.end method

.method public static final a(Li2/l0;JLl2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v3, p1

    .line 4
    .line 5
    move/from16 v7, p4

    .line 6
    .line 7
    move-object/from16 v11, p3

    .line 8
    .line 9
    check-cast v11, Ll2/t;

    .line 10
    .line 11
    const v0, -0x50adbae4

    .line 12
    .line 13
    .line 14
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v2, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v2

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int/2addr v0, v7

    .line 28
    invoke-virtual {v11, v3, v4}, Ll2/t;->f(J)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    const/16 v6, 0x20

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    move v5, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v5, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v5

    .line 41
    and-int/lit8 v5, v0, 0x13

    .line 42
    .line 43
    const/16 v8, 0x12

    .line 44
    .line 45
    const/4 v14, 0x0

    .line 46
    const/4 v15, 0x1

    .line 47
    if-eq v5, v8, :cond_2

    .line 48
    .line 49
    move v5, v15

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    move v5, v14

    .line 52
    :goto_2
    and-int/lit8 v8, v0, 0x1

    .line 53
    .line 54
    invoke-virtual {v11, v8, v5}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_c

    .line 59
    .line 60
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 65
    .line 66
    if-ne v5, v8, :cond_3

    .line 67
    .line 68
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    invoke-virtual {v5, v15}, Le3/i;->l(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v11, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_3
    check-cast v5, Le3/i;

    .line 79
    .line 80
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v9

    .line 84
    if-ne v9, v8, :cond_4

    .line 85
    .line 86
    new-instance v9, Lh50/q0;

    .line 87
    .line 88
    const/16 v10, 0xe

    .line 89
    .line 90
    invoke-direct {v9, v1, v10}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    invoke-static {v9}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 94
    .line 95
    .line 96
    move-result-object v9

    .line 97
    invoke-virtual {v11, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_4
    check-cast v9, Ll2/t2;

    .line 101
    .line 102
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    check-cast v9, Ljava/lang/Number;

    .line 107
    .line 108
    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    sget-object v10, Lk2/w;->f:Lk2/w;

    .line 113
    .line 114
    invoke-static {v10, v11}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    const/4 v12, 0x0

    .line 119
    const/16 v13, 0x1c

    .line 120
    .line 121
    move-object/from16 v16, v8

    .line 122
    .line 123
    move v8, v9

    .line 124
    move-object v9, v10

    .line 125
    const/4 v10, 0x0

    .line 126
    move-object/from16 v15, v16

    .line 127
    .line 128
    invoke-static/range {v8 .. v13}, Lc1/e;->b(FLc1/a0;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 129
    .line 130
    .line 131
    move-result-object v8

    .line 132
    and-int/lit8 v9, v0, 0xe

    .line 133
    .line 134
    if-eq v9, v2, :cond_5

    .line 135
    .line 136
    move v10, v14

    .line 137
    goto :goto_3

    .line 138
    :cond_5
    const/4 v10, 0x1

    .line 139
    :goto_3
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v12

    .line 143
    if-nez v10, :cond_6

    .line 144
    .line 145
    if-ne v12, v15, :cond_7

    .line 146
    .line 147
    :cond_6
    new-instance v12, Li40/e1;

    .line 148
    .line 149
    const/16 v10, 0xa

    .line 150
    .line 151
    invoke-direct {v12, v1, v10}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v11, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    :cond_7
    check-cast v12, Lay0/k;

    .line 158
    .line 159
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 160
    .line 161
    invoke-static {v10, v12}, Ld4/n;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 162
    .line 163
    .line 164
    move-result-object v10

    .line 165
    sget v12, Lj2/i;->c:F

    .line 166
    .line 167
    invoke-static {v10, v12}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v10

    .line 171
    if-eq v9, v2, :cond_8

    .line 172
    .line 173
    move v2, v14

    .line 174
    goto :goto_4

    .line 175
    :cond_8
    const/4 v2, 0x1

    .line 176
    :goto_4
    invoke-virtual {v11, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    or-int/2addr v2, v9

    .line 181
    and-int/lit8 v0, v0, 0x70

    .line 182
    .line 183
    if-ne v0, v6, :cond_9

    .line 184
    .line 185
    const/4 v0, 0x1

    .line 186
    goto :goto_5

    .line 187
    :cond_9
    move v0, v14

    .line 188
    :goto_5
    or-int/2addr v0, v2

    .line 189
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v2

    .line 193
    or-int/2addr v0, v2

    .line 194
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    if-nez v0, :cond_a

    .line 199
    .line 200
    if-ne v2, v15, :cond_b

    .line 201
    .line 202
    :cond_a
    new-instance v0, Le1/r;

    .line 203
    .line 204
    const/4 v6, 0x2

    .line 205
    move-object v2, v8

    .line 206
    invoke-direct/range {v0 .. v6}, Le1/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;JLjava/lang/Object;I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    move-object v2, v0

    .line 213
    :cond_b
    check-cast v2, Lay0/k;

    .line 214
    .line 215
    invoke-static {v10, v2, v11, v14}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_c
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 220
    .line 221
    .line 222
    :goto_6
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    if-eqz v0, :cond_d

    .line 227
    .line 228
    new-instance v2, Lj91/g;

    .line 229
    .line 230
    invoke-direct {v2, v1, v3, v4, v7}, Lj91/g;-><init>(Li2/l0;JI)V

    .line 231
    .line 232
    .line 233
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 234
    .line 235
    :cond_d
    return-void
.end method

.method public static final b(ZLay0/a;Lx2/s;Lj2/p;Lx2/e;Lay0/o;Lt2/b;Ll2/o;II)V
    .locals 16

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v6, p5

    .line 8
    .line 9
    move-object/from16 v7, p6

    .line 10
    .line 11
    move/from16 v8, p8

    .line 12
    .line 13
    move-object/from16 v0, p7

    .line 14
    .line 15
    check-cast v0, Ll2/t;

    .line 16
    .line 17
    const v3, -0x1fbac127

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v3, v8, 0x6

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ll2/t;->h(Z)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    const/4 v3, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v3, 0x2

    .line 36
    :goto_0
    or-int/2addr v3, v8

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v3, v8

    .line 39
    :goto_1
    and-int/lit8 v5, v8, 0x30

    .line 40
    .line 41
    if-nez v5, :cond_3

    .line 42
    .line 43
    invoke-virtual {v0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    const/16 v5, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v5, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v3, v5

    .line 55
    :cond_3
    and-int/lit8 v5, p9, 0x4

    .line 56
    .line 57
    if-eqz v5, :cond_5

    .line 58
    .line 59
    or-int/lit16 v3, v3, 0x180

    .line 60
    .line 61
    :cond_4
    move-object/from16 v9, p2

    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_5
    and-int/lit16 v9, v8, 0x180

    .line 65
    .line 66
    if-nez v9, :cond_4

    .line 67
    .line 68
    move-object/from16 v9, p2

    .line 69
    .line 70
    invoke-virtual {v0, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v10

    .line 74
    if-eqz v10, :cond_6

    .line 75
    .line 76
    const/16 v10, 0x100

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_6
    const/16 v10, 0x80

    .line 80
    .line 81
    :goto_3
    or-int/2addr v3, v10

    .line 82
    :goto_4
    and-int/lit16 v10, v8, 0xc00

    .line 83
    .line 84
    if-nez v10, :cond_8

    .line 85
    .line 86
    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v10

    .line 90
    if-eqz v10, :cond_7

    .line 91
    .line 92
    const/16 v10, 0x800

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_7
    const/16 v10, 0x400

    .line 96
    .line 97
    :goto_5
    or-int/2addr v3, v10

    .line 98
    :cond_8
    or-int/lit16 v3, v3, 0x6000

    .line 99
    .line 100
    const/high16 v10, 0x30000

    .line 101
    .line 102
    and-int/2addr v10, v8

    .line 103
    if-nez v10, :cond_a

    .line 104
    .line 105
    invoke-virtual {v0, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v10

    .line 109
    if-eqz v10, :cond_9

    .line 110
    .line 111
    const/high16 v10, 0x20000

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_9
    const/high16 v10, 0x10000

    .line 115
    .line 116
    :goto_6
    or-int/2addr v3, v10

    .line 117
    :cond_a
    const/high16 v10, 0x180000

    .line 118
    .line 119
    and-int/2addr v10, v8

    .line 120
    if-nez v10, :cond_c

    .line 121
    .line 122
    invoke-virtual {v0, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v10

    .line 126
    if-eqz v10, :cond_b

    .line 127
    .line 128
    const/high16 v10, 0x100000

    .line 129
    .line 130
    goto :goto_7

    .line 131
    :cond_b
    const/high16 v10, 0x80000

    .line 132
    .line 133
    :goto_7
    or-int/2addr v3, v10

    .line 134
    :cond_c
    const v10, 0x92493

    .line 135
    .line 136
    .line 137
    and-int/2addr v10, v3

    .line 138
    const v11, 0x92492

    .line 139
    .line 140
    .line 141
    const/4 v12, 0x0

    .line 142
    if-eq v10, v11, :cond_d

    .line 143
    .line 144
    const/4 v10, 0x1

    .line 145
    goto :goto_8

    .line 146
    :cond_d
    move v10, v12

    .line 147
    :goto_8
    and-int/lit8 v11, v3, 0x1

    .line 148
    .line 149
    invoke-virtual {v0, v11, v10}, Ll2/t;->O(IZ)Z

    .line 150
    .line 151
    .line 152
    move-result v10

    .line 153
    if-eqz v10, :cond_14

    .line 154
    .line 155
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 156
    .line 157
    .line 158
    and-int/lit8 v10, v8, 0x1

    .line 159
    .line 160
    if-eqz v10, :cond_f

    .line 161
    .line 162
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 163
    .line 164
    .line 165
    move-result v10

    .line 166
    if-eqz v10, :cond_e

    .line 167
    .line 168
    goto :goto_9

    .line 169
    :cond_e
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 170
    .line 171
    .line 172
    move-object/from16 v5, p4

    .line 173
    .line 174
    goto :goto_a

    .line 175
    :cond_f
    :goto_9
    if-eqz v5, :cond_10

    .line 176
    .line 177
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 178
    .line 179
    move-object v9, v5

    .line 180
    :cond_10
    sget-object v5, Lx2/c;->d:Lx2/j;

    .line 181
    .line 182
    :goto_a
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 183
    .line 184
    .line 185
    sget v10, Lj2/h;->c:F

    .line 186
    .line 187
    new-instance v11, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;

    .line 188
    .line 189
    invoke-direct {v11, v1, v2, v4, v10}, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;-><init>(ZLay0/a;Lj2/p;F)V

    .line 190
    .line 191
    .line 192
    invoke-interface {v9, v11}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 193
    .line 194
    .line 195
    move-result-object v10

    .line 196
    invoke-static {v5, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 197
    .line 198
    .line 199
    move-result-object v11

    .line 200
    iget-wide v14, v0, Ll2/t;->T:J

    .line 201
    .line 202
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 203
    .line 204
    .line 205
    move-result v12

    .line 206
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 207
    .line 208
    .line 209
    move-result-object v14

    .line 210
    invoke-static {v0, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v10

    .line 214
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 215
    .line 216
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 217
    .line 218
    .line 219
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 220
    .line 221
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 222
    .line 223
    .line 224
    iget-boolean v13, v0, Ll2/t;->S:Z

    .line 225
    .line 226
    if-eqz v13, :cond_11

    .line 227
    .line 228
    invoke-virtual {v0, v15}, Ll2/t;->l(Lay0/a;)V

    .line 229
    .line 230
    .line 231
    goto :goto_b

    .line 232
    :cond_11
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 233
    .line 234
    .line 235
    :goto_b
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 236
    .line 237
    invoke-static {v13, v11, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 238
    .line 239
    .line 240
    sget-object v11, Lv3/j;->f:Lv3/h;

    .line 241
    .line 242
    invoke-static {v11, v14, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 243
    .line 244
    .line 245
    sget-object v11, Lv3/j;->j:Lv3/h;

    .line 246
    .line 247
    iget-boolean v13, v0, Ll2/t;->S:Z

    .line 248
    .line 249
    if-nez v13, :cond_12

    .line 250
    .line 251
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v13

    .line 255
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 256
    .line 257
    .line 258
    move-result-object v14

    .line 259
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v13

    .line 263
    if-nez v13, :cond_13

    .line 264
    .line 265
    :cond_12
    invoke-static {v12, v0, v12, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 266
    .line 267
    .line 268
    :cond_13
    sget-object v11, Lv3/j;->d:Lv3/h;

    .line 269
    .line 270
    invoke-static {v11, v10, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 271
    .line 272
    .line 273
    shr-int/lit8 v10, v3, 0xf

    .line 274
    .line 275
    and-int/lit8 v10, v10, 0x70

    .line 276
    .line 277
    const/4 v11, 0x6

    .line 278
    or-int/2addr v10, v11

    .line 279
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 280
    .line 281
    .line 282
    move-result-object v10

    .line 283
    sget-object v12, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 284
    .line 285
    invoke-virtual {v7, v12, v0, v10}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    shr-int/lit8 v3, v3, 0xc

    .line 289
    .line 290
    and-int/lit8 v3, v3, 0x70

    .line 291
    .line 292
    or-int/2addr v3, v11

    .line 293
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    invoke-interface {v6, v12, v0, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    const/4 v3, 0x1

    .line 301
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 302
    .line 303
    .line 304
    :goto_c
    move-object v3, v9

    .line 305
    goto :goto_d

    .line 306
    :cond_14
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 307
    .line 308
    .line 309
    move-object/from16 v5, p4

    .line 310
    .line 311
    goto :goto_c

    .line 312
    :goto_d
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 313
    .line 314
    .line 315
    move-result-object v10

    .line 316
    if-eqz v10, :cond_15

    .line 317
    .line 318
    new-instance v0, Lh2/t0;

    .line 319
    .line 320
    move/from16 v9, p9

    .line 321
    .line 322
    invoke-direct/range {v0 .. v9}, Lh2/t0;-><init>(ZLay0/a;Lx2/s;Lj2/p;Lx2/e;Lay0/o;Lt2/b;II)V

    .line 323
    .line 324
    .line 325
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 326
    .line 327
    :cond_15
    return-void
.end method

.method public static final c(Lg3/d;Le3/i;Ld3/c;JFLb1/x0;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p6

    .line 8
    .line 9
    invoke-virtual {v1}, Le3/i;->j()V

    .line 10
    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    invoke-virtual {v1, v4, v4}, Le3/i;->h(FF)V

    .line 14
    .line 15
    .line 16
    sget v5, Lj2/i;->e:F

    .line 17
    .line 18
    invoke-interface {v0, v5}, Lt4/c;->w0(F)F

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    iget v7, v3, Lb1/x0;->e:F

    .line 23
    .line 24
    mul-float/2addr v6, v7

    .line 25
    const/4 v8, 0x2

    .line 26
    int-to-float v8, v8

    .line 27
    div-float/2addr v6, v8

    .line 28
    sget v8, Lj2/i;->f:F

    .line 29
    .line 30
    invoke-interface {v0, v8}, Lt4/c;->w0(F)F

    .line 31
    .line 32
    .line 33
    move-result v8

    .line 34
    mul-float/2addr v8, v7

    .line 35
    invoke-virtual {v1, v6, v8}, Le3/i;->g(FF)V

    .line 36
    .line 37
    .line 38
    invoke-interface {v0, v5}, Lt4/c;->w0(F)F

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    mul-float/2addr v6, v7

    .line 43
    invoke-virtual {v1, v6, v4}, Le3/i;->g(FF)V

    .line 44
    .line 45
    .line 46
    iget v4, v2, Ld3/c;->c:F

    .line 47
    .line 48
    iget v6, v2, Ld3/c;->a:F

    .line 49
    .line 50
    sub-float/2addr v4, v6

    .line 51
    iget v6, v2, Ld3/c;->d:F

    .line 52
    .line 53
    iget v8, v2, Ld3/c;->b:F

    .line 54
    .line 55
    sub-float/2addr v6, v8

    .line 56
    invoke-static {v4, v6}, Ljava/lang/Math;->min(FF)F

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    const/high16 v6, 0x40000000    # 2.0f

    .line 61
    .line 62
    div-float/2addr v4, v6

    .line 63
    invoke-interface {v0, v5}, Lt4/c;->w0(F)F

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    mul-float/2addr v5, v7

    .line 68
    div-float/2addr v5, v6

    .line 69
    invoke-virtual {v2}, Ld3/c;->b()J

    .line 70
    .line 71
    .line 72
    move-result-wide v6

    .line 73
    const/16 v8, 0x20

    .line 74
    .line 75
    shr-long/2addr v6, v8

    .line 76
    long-to-int v6, v6

    .line 77
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    add-float/2addr v6, v4

    .line 82
    sub-float/2addr v6, v5

    .line 83
    invoke-virtual {v2}, Ld3/c;->b()J

    .line 84
    .line 85
    .line 86
    move-result-wide v4

    .line 87
    const-wide v9, 0xffffffffL

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    and-long/2addr v4, v9

    .line 93
    long-to-int v2, v4

    .line 94
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    sget v4, Lj2/i;->a:F

    .line 99
    .line 100
    invoke-interface {v0, v4}, Lt4/c;->w0(F)F

    .line 101
    .line 102
    .line 103
    move-result v5

    .line 104
    sub-float/2addr v2, v5

    .line 105
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    int-to-long v5, v5

    .line 110
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    int-to-long v11, v2

    .line 115
    shl-long/2addr v5, v8

    .line 116
    and-long v7, v11, v9

    .line 117
    .line 118
    or-long/2addr v5, v7

    .line 119
    invoke-virtual {v1, v5, v6}, Le3/i;->m(J)V

    .line 120
    .line 121
    .line 122
    iget v2, v3, Lb1/x0;->d:F

    .line 123
    .line 124
    invoke-interface {v0, v4}, Lt4/c;->w0(F)F

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    sub-float/2addr v2, v3

    .line 129
    invoke-interface {v0}, Lg3/d;->D0()J

    .line 130
    .line 131
    .line 132
    move-result-wide v5

    .line 133
    invoke-interface {v0}, Lg3/d;->x0()Lgw0/c;

    .line 134
    .line 135
    .line 136
    move-result-object v7

    .line 137
    invoke-virtual {v7}, Lgw0/c;->o()J

    .line 138
    .line 139
    .line 140
    move-result-wide v8

    .line 141
    invoke-virtual {v7}, Lgw0/c;->h()Le3/r;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    invoke-interface {v3}, Le3/r;->o()V

    .line 146
    .line 147
    .line 148
    :try_start_0
    iget-object v3, v7, Lgw0/c;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v3, Lbu/c;

    .line 151
    .line 152
    invoke-virtual {v3, v5, v6, v2}, Lbu/c;->z(JF)V

    .line 153
    .line 154
    .line 155
    new-instance v10, Lg3/h;

    .line 156
    .line 157
    invoke-interface {v0, v4}, Lt4/c;->w0(F)F

    .line 158
    .line 159
    .line 160
    move-result v11

    .line 161
    const/4 v15, 0x0

    .line 162
    const/16 v16, 0x1e

    .line 163
    .line 164
    const/4 v12, 0x0

    .line 165
    const/4 v13, 0x0

    .line 166
    const/4 v14, 0x0

    .line 167
    invoke-direct/range {v10 .. v16}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 168
    .line 169
    .line 170
    const/16 v6, 0x30

    .line 171
    .line 172
    move-wide/from16 v2, p3

    .line 173
    .line 174
    move/from16 v4, p5

    .line 175
    .line 176
    move-object v5, v10

    .line 177
    invoke-static/range {v0 .. v6}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 178
    .line 179
    .line 180
    invoke-static {v7, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 181
    .line 182
    .line 183
    return-void

    .line 184
    :catchall_0
    move-exception v0

    .line 185
    invoke-static {v7, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 186
    .line 187
    .line 188
    throw v0
.end method

.method public static final d(Ll2/o;)Lj2/p;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    check-cast p0, Ll2/t;

    .line 5
    .line 6
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 11
    .line 12
    if-ne v1, v2, :cond_0

    .line 13
    .line 14
    new-instance v1, Lj00/a;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-direct {v1, v2}, Lj00/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    check-cast v1, Lay0/a;

    .line 24
    .line 25
    const/16 v2, 0x180

    .line 26
    .line 27
    sget-object v3, Lj2/p;->b:Lu2/l;

    .line 28
    .line 29
    invoke-static {v0, v3, v1, p0, v2}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lj2/p;

    .line 34
    .line 35
    return-object p0
.end method
