.class public abstract Lh2/wa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lk2/c0;->a:Lk2/l;

    .line 2
    .line 3
    sget v0, Lk2/c0;->c:F

    .line 4
    .line 5
    sput v0, Lh2/wa;->a:F

    .line 6
    .line 7
    const/16 v0, 0x10

    .line 8
    .line 9
    int-to-float v0, v0

    .line 10
    sput v0, Lh2/wa;->b:F

    .line 11
    .line 12
    const/16 v0, 0xe

    .line 13
    .line 14
    int-to-float v0, v0

    .line 15
    sput v0, Lh2/wa;->c:F

    .line 16
    .line 17
    const/4 v0, 0x6

    .line 18
    int-to-float v0, v0

    .line 19
    sput v0, Lh2/wa;->d:F

    .line 20
    .line 21
    const/16 v0, 0x14

    .line 22
    .line 23
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    sput-wide v0, Lh2/wa;->e:J

    .line 28
    .line 29
    return-void
.end method

.method public static final a(ZLay0/a;Lx2/s;JJLt2/b;Ll2/o;I)V
    .locals 18

    .line 1
    move-wide/from16 v0, p3

    .line 2
    .line 3
    move/from16 v9, p9

    .line 4
    .line 5
    move-object/from16 v6, p8

    .line 6
    .line 7
    check-cast v6, Ll2/t;

    .line 8
    .line 9
    const v2, -0x5dc429d5

    .line 10
    .line 11
    .line 12
    invoke-virtual {v6, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v2, v9, 0x6

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    move/from16 v12, p0

    .line 19
    .line 20
    if-nez v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v6, v12}, Ll2/t;->h(Z)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    const/4 v2, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v2, v3

    .line 31
    :goto_0
    or-int/2addr v2, v9

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v2, v9

    .line 34
    :goto_1
    and-int/lit8 v4, v9, 0x30

    .line 35
    .line 36
    move-object/from16 v14, p1

    .line 37
    .line 38
    if-nez v4, :cond_3

    .line 39
    .line 40
    invoke-virtual {v6, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-eqz v4, :cond_2

    .line 45
    .line 46
    const/16 v4, 0x20

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v4, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v2, v4

    .line 52
    :cond_3
    and-int/lit16 v4, v9, 0x180

    .line 53
    .line 54
    move-object/from16 v11, p2

    .line 55
    .line 56
    if-nez v4, :cond_5

    .line 57
    .line 58
    invoke-virtual {v6, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_4

    .line 63
    .line 64
    const/16 v4, 0x100

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_4
    const/16 v4, 0x80

    .line 68
    .line 69
    :goto_3
    or-int/2addr v2, v4

    .line 70
    :cond_5
    and-int/lit16 v4, v9, 0xc00

    .line 71
    .line 72
    const/4 v5, 0x1

    .line 73
    if-nez v4, :cond_7

    .line 74
    .line 75
    invoke-virtual {v6, v5}, Ll2/t;->h(Z)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_6

    .line 80
    .line 81
    const/16 v4, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v4, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v2, v4

    .line 87
    :cond_7
    and-int/lit16 v4, v9, 0x6000

    .line 88
    .line 89
    if-nez v4, :cond_9

    .line 90
    .line 91
    invoke-virtual {v6, v0, v1}, Ll2/t;->f(J)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    if-eqz v4, :cond_8

    .line 96
    .line 97
    const/16 v4, 0x4000

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_8
    const/16 v4, 0x2000

    .line 101
    .line 102
    :goto_5
    or-int/2addr v2, v4

    .line 103
    :cond_9
    const/high16 v4, 0x30000

    .line 104
    .line 105
    and-int/2addr v4, v9

    .line 106
    move-wide/from16 v7, p5

    .line 107
    .line 108
    if-nez v4, :cond_b

    .line 109
    .line 110
    invoke-virtual {v6, v7, v8}, Ll2/t;->f(J)Z

    .line 111
    .line 112
    .line 113
    move-result v4

    .line 114
    if-eqz v4, :cond_a

    .line 115
    .line 116
    const/high16 v4, 0x20000

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_a
    const/high16 v4, 0x10000

    .line 120
    .line 121
    :goto_6
    or-int/2addr v2, v4

    .line 122
    :cond_b
    const/high16 v4, 0x180000

    .line 123
    .line 124
    and-int/2addr v4, v9

    .line 125
    if-nez v4, :cond_d

    .line 126
    .line 127
    const/4 v4, 0x0

    .line 128
    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    if-eqz v4, :cond_c

    .line 133
    .line 134
    const/high16 v4, 0x100000

    .line 135
    .line 136
    goto :goto_7

    .line 137
    :cond_c
    const/high16 v4, 0x80000

    .line 138
    .line 139
    :goto_7
    or-int/2addr v2, v4

    .line 140
    :cond_d
    const/high16 v4, 0xc00000

    .line 141
    .line 142
    and-int/2addr v4, v9

    .line 143
    move-object/from16 v15, p7

    .line 144
    .line 145
    if-nez v4, :cond_f

    .line 146
    .line 147
    invoke-virtual {v6, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v4

    .line 151
    if-eqz v4, :cond_e

    .line 152
    .line 153
    const/high16 v4, 0x800000

    .line 154
    .line 155
    goto :goto_8

    .line 156
    :cond_e
    const/high16 v4, 0x400000

    .line 157
    .line 158
    :goto_8
    or-int/2addr v2, v4

    .line 159
    :cond_f
    const v4, 0x492493

    .line 160
    .line 161
    .line 162
    and-int/2addr v4, v2

    .line 163
    const v10, 0x492492

    .line 164
    .line 165
    .line 166
    if-eq v4, v10, :cond_10

    .line 167
    .line 168
    move v4, v5

    .line 169
    goto :goto_9

    .line 170
    :cond_10
    const/4 v4, 0x0

    .line 171
    :goto_9
    and-int/lit8 v10, v2, 0x1

    .line 172
    .line 173
    invoke-virtual {v6, v10, v4}, Ll2/t;->O(IZ)Z

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    if-eqz v4, :cond_13

    .line 178
    .line 179
    invoke-virtual {v6}, Ll2/t;->T()V

    .line 180
    .line 181
    .line 182
    and-int/lit8 v4, v9, 0x1

    .line 183
    .line 184
    if-eqz v4, :cond_12

    .line 185
    .line 186
    invoke-virtual {v6}, Ll2/t;->y()Z

    .line 187
    .line 188
    .line 189
    move-result v4

    .line 190
    if-eqz v4, :cond_11

    .line 191
    .line 192
    goto :goto_a

    .line 193
    :cond_11
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 194
    .line 195
    .line 196
    :cond_12
    :goto_a
    invoke-virtual {v6}, Ll2/t;->r()V

    .line 197
    .line 198
    .line 199
    const/4 v4, 0x0

    .line 200
    invoke-static {v0, v1, v4, v3, v5}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 201
    .line 202
    .line 203
    move-result-object v13

    .line 204
    new-instance v10, Lh2/k0;

    .line 205
    .line 206
    invoke-direct/range {v10 .. v15}, Lh2/k0;-><init>(Lx2/s;ZLh2/x7;Lay0/a;Lt2/b;)V

    .line 207
    .line 208
    .line 209
    const v3, 0x434457e7

    .line 210
    .line 211
    .line 212
    invoke-static {v3, v6, v10}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 213
    .line 214
    .line 215
    move-result-object v5

    .line 216
    shr-int/lit8 v3, v2, 0xc

    .line 217
    .line 218
    and-int/lit8 v4, v3, 0xe

    .line 219
    .line 220
    or-int/lit16 v4, v4, 0xc00

    .line 221
    .line 222
    and-int/lit8 v3, v3, 0x70

    .line 223
    .line 224
    or-int/2addr v3, v4

    .line 225
    shl-int/lit8 v2, v2, 0x6

    .line 226
    .line 227
    and-int/lit16 v2, v2, 0x380

    .line 228
    .line 229
    or-int/2addr v2, v3

    .line 230
    move-wide/from16 v16, v7

    .line 231
    .line 232
    move v7, v2

    .line 233
    move-wide/from16 v2, v16

    .line 234
    .line 235
    move/from16 v4, p0

    .line 236
    .line 237
    invoke-static/range {v0 .. v7}, Lh2/wa;->d(JJZLt2/b;Ll2/o;I)V

    .line 238
    .line 239
    .line 240
    goto :goto_b

    .line 241
    :cond_13
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 242
    .line 243
    .line 244
    :goto_b
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 245
    .line 246
    .line 247
    move-result-object v10

    .line 248
    if-eqz v10, :cond_14

    .line 249
    .line 250
    new-instance v0, Lh2/ua;

    .line 251
    .line 252
    move/from16 v1, p0

    .line 253
    .line 254
    move-object/from16 v2, p1

    .line 255
    .line 256
    move-object/from16 v3, p2

    .line 257
    .line 258
    move-wide/from16 v4, p3

    .line 259
    .line 260
    move-wide/from16 v6, p5

    .line 261
    .line 262
    move-object/from16 v8, p7

    .line 263
    .line 264
    invoke-direct/range {v0 .. v9}, Lh2/ua;-><init>(ZLay0/a;Lx2/s;JJLt2/b;I)V

    .line 265
    .line 266
    .line 267
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 268
    .line 269
    :cond_14
    return-void
.end method

.method public static final b(ZLay0/a;Lx2/s;Lay0/n;JJLl2/o;I)V
    .locals 15

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move-object/from16 v13, p8

    .line 6
    .line 7
    check-cast v13, Ll2/t;

    .line 8
    .line 9
    const v0, 0x3c7ff1ed

    .line 10
    .line 11
    .line 12
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v13, p0}, Ll2/t;->h(Z)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int v0, p9, v0

    .line 25
    .line 26
    move-object/from16 v6, p1

    .line 27
    .line 28
    invoke-virtual {v13, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    const/16 v1, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v1, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v1

    .line 40
    invoke-virtual {v13, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_2

    .line 45
    .line 46
    const/16 v1, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v1, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v1

    .line 52
    const/high16 v1, 0x64b0000

    .line 53
    .line 54
    or-int/2addr v0, v1

    .line 55
    const v1, 0x2492493

    .line 56
    .line 57
    .line 58
    and-int/2addr v1, v0

    .line 59
    const v2, 0x2492492

    .line 60
    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    if-eq v1, v2, :cond_3

    .line 64
    .line 65
    const/4 v1, 0x1

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    move v1, v5

    .line 68
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 69
    .line 70
    invoke-virtual {v13, v2, v1}, Ll2/t;->O(IZ)Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-eqz v1, :cond_7

    .line 75
    .line 76
    invoke-virtual {v13}, Ll2/t;->T()V

    .line 77
    .line 78
    .line 79
    and-int/lit8 v1, p9, 0x1

    .line 80
    .line 81
    const v2, -0x1f80001

    .line 82
    .line 83
    .line 84
    if-eqz v1, :cond_5

    .line 85
    .line 86
    invoke-virtual {v13}, Ll2/t;->y()Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_4

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_4
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 94
    .line 95
    .line 96
    and-int/2addr v0, v2

    .line 97
    move-wide/from16 v8, p4

    .line 98
    .line 99
    move-wide/from16 v10, p6

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    :goto_4
    sget-object v1, Lh2/p1;->a:Ll2/e0;

    .line 103
    .line 104
    invoke-virtual {v13, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    check-cast v1, Le3/s;

    .line 109
    .line 110
    iget-wide v7, v1, Le3/s;->a:J

    .line 111
    .line 112
    and-int/2addr v0, v2

    .line 113
    move-wide v10, v7

    .line 114
    move-wide v8, v10

    .line 115
    :goto_5
    invoke-virtual {v13}, Ll2/t;->r()V

    .line 116
    .line 117
    .line 118
    if-nez v4, :cond_6

    .line 119
    .line 120
    const v1, 0x6d214fd5

    .line 121
    .line 122
    .line 123
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v13, v5}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    const/4 v1, 0x0

    .line 130
    goto :goto_6

    .line 131
    :cond_6
    const v1, 0x6d214fd6

    .line 132
    .line 133
    .line 134
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 135
    .line 136
    .line 137
    new-instance v1, Lh2/e;

    .line 138
    .line 139
    const/16 v2, 0x8

    .line 140
    .line 141
    invoke-direct {v1, v2, v4}, Lh2/e;-><init>(ILay0/n;)V

    .line 142
    .line 143
    .line 144
    const v2, -0x680681c4

    .line 145
    .line 146
    .line 147
    invoke-static {v2, v13, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v13, v5}, Ll2/t;->q(Z)V

    .line 152
    .line 153
    .line 154
    :goto_6
    new-instance v2, Lel/a;

    .line 155
    .line 156
    const/16 v5, 0x12

    .line 157
    .line 158
    invoke-direct {v2, v5}, Lel/a;-><init>(I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v3, v2}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    new-instance v2, Lh2/u6;

    .line 166
    .line 167
    const/4 v5, 0x1

    .line 168
    invoke-direct {v2, v5, v1}, Lh2/u6;-><init>(ILay0/n;)V

    .line 169
    .line 170
    .line 171
    const v1, -0x3601c460    # -2082676.0f

    .line 172
    .line 173
    .line 174
    invoke-static {v1, v13, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 175
    .line 176
    .line 177
    move-result-object v12

    .line 178
    and-int/lit8 v1, v0, 0xe

    .line 179
    .line 180
    const/high16 v2, 0xc00000

    .line 181
    .line 182
    or-int/2addr v1, v2

    .line 183
    and-int/lit8 v0, v0, 0x70

    .line 184
    .line 185
    or-int/2addr v0, v1

    .line 186
    const v1, 0x180c00

    .line 187
    .line 188
    .line 189
    or-int v14, v0, v1

    .line 190
    .line 191
    move v5, p0

    .line 192
    invoke-static/range {v5 .. v14}, Lh2/wa;->a(ZLay0/a;Lx2/s;JJLt2/b;Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    move-wide v5, v8

    .line 196
    move-wide v7, v10

    .line 197
    goto :goto_7

    .line 198
    :cond_7
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 199
    .line 200
    .line 201
    move-wide/from16 v5, p4

    .line 202
    .line 203
    move-wide/from16 v7, p6

    .line 204
    .line 205
    :goto_7
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 206
    .line 207
    .line 208
    move-result-object v10

    .line 209
    if-eqz v10, :cond_8

    .line 210
    .line 211
    new-instance v0, Lh2/ta;

    .line 212
    .line 213
    move v1, p0

    .line 214
    move-object/from16 v2, p1

    .line 215
    .line 216
    move/from16 v9, p9

    .line 217
    .line 218
    invoke-direct/range {v0 .. v9}, Lh2/ta;-><init>(ZLay0/a;Lx2/s;Lay0/n;JJI)V

    .line 219
    .line 220
    .line 221
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 222
    .line 223
    :cond_8
    return-void
.end method

.method public static final c(Lay0/n;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 6
    .line 7
    move-object/from16 v3, p1

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x5075dc56

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    const/4 v5, 0x2

    .line 22
    const/4 v6, 0x4

    .line 23
    if-eqz v4, :cond_0

    .line 24
    .line 25
    move v4, v6

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move v4, v5

    .line 28
    :goto_0
    or-int/2addr v4, v1

    .line 29
    const/4 v7, 0x0

    .line 30
    invoke-virtual {v3, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    const/16 v8, 0x20

    .line 35
    .line 36
    if-eqz v7, :cond_1

    .line 37
    .line 38
    move v7, v8

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v7, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v4, v7

    .line 43
    and-int/lit8 v7, v4, 0x13

    .line 44
    .line 45
    const/16 v9, 0x12

    .line 46
    .line 47
    const/4 v11, 0x0

    .line 48
    if-eq v7, v9, :cond_2

    .line 49
    .line 50
    const/4 v7, 0x1

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v7, v11

    .line 53
    :goto_2
    and-int/lit8 v9, v4, 0x1

    .line 54
    .line 55
    invoke-virtual {v3, v9, v7}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    if-eqz v7, :cond_e

    .line 60
    .line 61
    and-int/lit8 v7, v4, 0xe

    .line 62
    .line 63
    if-ne v7, v6, :cond_3

    .line 64
    .line 65
    const/4 v6, 0x1

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    move v6, v11

    .line 68
    :goto_3
    and-int/lit8 v4, v4, 0x70

    .line 69
    .line 70
    if-ne v4, v8, :cond_4

    .line 71
    .line 72
    const/4 v4, 0x1

    .line 73
    goto :goto_4

    .line 74
    :cond_4
    move v4, v11

    .line 75
    :goto_4
    or-int/2addr v4, v6

    .line 76
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    if-nez v4, :cond_5

    .line 81
    .line 82
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 83
    .line 84
    if-ne v6, v4, :cond_6

    .line 85
    .line 86
    :cond_5
    new-instance v6, Lh2/j9;

    .line 87
    .line 88
    const/4 v4, 0x2

    .line 89
    invoke-direct {v6, v0, v4}, Lh2/j9;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v3, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_6
    check-cast v6, Lt3/q0;

    .line 96
    .line 97
    iget-wide v8, v3, Ll2/t;->T:J

    .line 98
    .line 99
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 108
    .line 109
    invoke-static {v3, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 110
    .line 111
    .line 112
    move-result-object v12

    .line 113
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 114
    .line 115
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 119
    .line 120
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 121
    .line 122
    .line 123
    iget-boolean v14, v3, Ll2/t;->S:Z

    .line 124
    .line 125
    if-eqz v14, :cond_7

    .line 126
    .line 127
    invoke-virtual {v3, v13}, Ll2/t;->l(Lay0/a;)V

    .line 128
    .line 129
    .line 130
    goto :goto_5

    .line 131
    :cond_7
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 132
    .line 133
    .line 134
    :goto_5
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 135
    .line 136
    invoke-static {v14, v6, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 137
    .line 138
    .line 139
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 140
    .line 141
    invoke-static {v6, v8, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 142
    .line 143
    .line 144
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 145
    .line 146
    iget-boolean v15, v3, Ll2/t;->S:Z

    .line 147
    .line 148
    if-nez v15, :cond_8

    .line 149
    .line 150
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v15

    .line 154
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 155
    .line 156
    .line 157
    move-result-object v10

    .line 158
    invoke-static {v15, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v10

    .line 162
    if-nez v10, :cond_9

    .line 163
    .line 164
    :cond_8
    invoke-static {v4, v3, v4, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 165
    .line 166
    .line 167
    :cond_9
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 168
    .line 169
    invoke-static {v4, v12, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 170
    .line 171
    .line 172
    if-eqz v0, :cond_d

    .line 173
    .line 174
    const v10, 0x33e0a8f4

    .line 175
    .line 176
    .line 177
    invoke-virtual {v3, v10}, Ll2/t;->Y(I)V

    .line 178
    .line 179
    .line 180
    const-string v10, "text"

    .line 181
    .line 182
    invoke-static {v9, v10}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    .line 183
    .line 184
    .line 185
    move-result-object v9

    .line 186
    sget v10, Lh2/wa;->b:F

    .line 187
    .line 188
    const/4 v12, 0x0

    .line 189
    invoke-static {v9, v10, v12, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 190
    .line 191
    .line 192
    move-result-object v5

    .line 193
    invoke-static {v2, v11}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    iget-wide v9, v3, Ll2/t;->T:J

    .line 198
    .line 199
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 200
    .line 201
    .line 202
    move-result v9

    .line 203
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 204
    .line 205
    .line 206
    move-result-object v10

    .line 207
    invoke-static {v3, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 208
    .line 209
    .line 210
    move-result-object v5

    .line 211
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 212
    .line 213
    .line 214
    iget-boolean v12, v3, Ll2/t;->S:Z

    .line 215
    .line 216
    if-eqz v12, :cond_a

    .line 217
    .line 218
    invoke-virtual {v3, v13}, Ll2/t;->l(Lay0/a;)V

    .line 219
    .line 220
    .line 221
    goto :goto_6

    .line 222
    :cond_a
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 223
    .line 224
    .line 225
    :goto_6
    invoke-static {v14, v2, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 226
    .line 227
    .line 228
    invoke-static {v6, v10, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 229
    .line 230
    .line 231
    iget-boolean v2, v3, Ll2/t;->S:Z

    .line 232
    .line 233
    if-nez v2, :cond_b

    .line 234
    .line 235
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v2

    .line 247
    if-nez v2, :cond_c

    .line 248
    .line 249
    :cond_b
    invoke-static {v9, v3, v9, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 250
    .line 251
    .line 252
    :cond_c
    invoke-static {v4, v5, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 253
    .line 254
    .line 255
    const/4 v2, 0x1

    .line 256
    invoke-static {v7, v0, v3, v2, v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    .line 257
    .line 258
    .line 259
    goto :goto_7

    .line 260
    :cond_d
    const/4 v2, 0x1

    .line 261
    const v4, 0x33e24221

    .line 262
    .line 263
    .line 264
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 268
    .line 269
    .line 270
    :goto_7
    const v4, 0x33e3a6a1

    .line 271
    .line 272
    .line 273
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v3, v2}, Ll2/t;->q(Z)V

    .line 280
    .line 281
    .line 282
    goto :goto_8

    .line 283
    :cond_e
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 284
    .line 285
    .line 286
    :goto_8
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    if-eqz v2, :cond_f

    .line 291
    .line 292
    new-instance v3, Lcw0/j;

    .line 293
    .line 294
    invoke-direct {v3, v1, v0}, Lcw0/j;-><init>(ILay0/n;)V

    .line 295
    .line 296
    .line 297
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 298
    .line 299
    :cond_f
    return-void
.end method

.method public static final d(JJZLt2/b;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v6, p5

    .line 2
    .line 3
    move/from16 v7, p7

    .line 4
    .line 5
    move-object/from16 v13, p6

    .line 6
    .line 7
    check-cast v13, Ll2/t;

    .line 8
    .line 9
    const v0, -0x31a8c985

    .line 10
    .line 11
    .line 12
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v7, 0x6

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    move-wide/from16 v2, p0

    .line 19
    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    invoke-virtual {v13, v2, v3}, Ll2/t;->f(J)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v0, v1

    .line 31
    :goto_0
    or-int/2addr v0, v7

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v0, v7

    .line 34
    :goto_1
    and-int/lit8 v4, v7, 0x30

    .line 35
    .line 36
    if-nez v4, :cond_3

    .line 37
    .line 38
    move-wide/from16 v4, p2

    .line 39
    .line 40
    invoke-virtual {v13, v4, v5}, Ll2/t;->f(J)Z

    .line 41
    .line 42
    .line 43
    move-result v8

    .line 44
    if-eqz v8, :cond_2

    .line 45
    .line 46
    const/16 v8, 0x20

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v8, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v8

    .line 52
    goto :goto_3

    .line 53
    :cond_3
    move-wide/from16 v4, p2

    .line 54
    .line 55
    :goto_3
    and-int/lit16 v8, v7, 0x180

    .line 56
    .line 57
    move/from16 v15, p4

    .line 58
    .line 59
    if-nez v8, :cond_5

    .line 60
    .line 61
    invoke-virtual {v13, v15}, Ll2/t;->h(Z)Z

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    if-eqz v8, :cond_4

    .line 66
    .line 67
    const/16 v8, 0x100

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_4
    const/16 v8, 0x80

    .line 71
    .line 72
    :goto_4
    or-int/2addr v0, v8

    .line 73
    :cond_5
    and-int/lit16 v8, v7, 0xc00

    .line 74
    .line 75
    if-nez v8, :cond_7

    .line 76
    .line 77
    invoke-virtual {v13, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v8

    .line 81
    if-eqz v8, :cond_6

    .line 82
    .line 83
    const/16 v8, 0x800

    .line 84
    .line 85
    goto :goto_5

    .line 86
    :cond_6
    const/16 v8, 0x400

    .line 87
    .line 88
    :goto_5
    or-int/2addr v0, v8

    .line 89
    :cond_7
    and-int/lit16 v8, v0, 0x493

    .line 90
    .line 91
    const/16 v9, 0x492

    .line 92
    .line 93
    const/4 v10, 0x0

    .line 94
    if-eq v8, v9, :cond_8

    .line 95
    .line 96
    const/4 v8, 0x1

    .line 97
    goto :goto_6

    .line 98
    :cond_8
    move v8, v10

    .line 99
    :goto_6
    and-int/lit8 v9, v0, 0x1

    .line 100
    .line 101
    invoke-virtual {v13, v9, v8}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result v8

    .line 105
    if-eqz v8, :cond_f

    .line 106
    .line 107
    invoke-static {v15}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    shr-int/lit8 v0, v0, 0x6

    .line 112
    .line 113
    and-int/lit8 v9, v0, 0xe

    .line 114
    .line 115
    const/4 v11, 0x0

    .line 116
    invoke-static {v8, v11, v13, v9, v1}, Lc1/z1;->f(Ljava/lang/Object;Ljava/lang/String;Ll2/o;II)Lc1/w1;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    iget-object v1, v8, Lc1/w1;->d:Ll2/j1;

    .line 121
    .line 122
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v9

    .line 126
    check-cast v9, Ljava/lang/Boolean;

    .line 127
    .line 128
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 129
    .line 130
    .line 131
    move-result v9

    .line 132
    const v11, -0x3fbb3b28

    .line 133
    .line 134
    .line 135
    invoke-virtual {v13, v11}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    if-eqz v9, :cond_9

    .line 139
    .line 140
    move-wide/from16 v16, v2

    .line 141
    .line 142
    goto :goto_7

    .line 143
    :cond_9
    move-wide/from16 v16, v4

    .line 144
    .line 145
    :goto_7
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 146
    .line 147
    .line 148
    invoke-static/range {v16 .. v17}, Le3/s;->f(J)Lf3/c;

    .line 149
    .line 150
    .line 151
    move-result-object v9

    .line 152
    invoke-virtual {v13, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v12

    .line 156
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v14

    .line 160
    if-nez v12, :cond_a

    .line 161
    .line 162
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 163
    .line 164
    if-ne v14, v12, :cond_b

    .line 165
    .line 166
    :cond_a
    sget-object v12, Lb1/c;->l:Lb1/c;

    .line 167
    .line 168
    new-instance v14, La3/f;

    .line 169
    .line 170
    const/4 v10, 0x7

    .line 171
    invoke-direct {v14, v9, v10}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 172
    .line 173
    .line 174
    new-instance v9, Lc1/b2;

    .line 175
    .line 176
    invoke-direct {v9, v12, v14}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v13, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    move-object v14, v9

    .line 183
    :cond_b
    move-object v12, v14

    .line 184
    check-cast v12, Lc1/b2;

    .line 185
    .line 186
    iget-object v9, v8, Lc1/w1;->a:Lap0/o;

    .line 187
    .line 188
    invoke-virtual {v9}, Lap0/o;->D()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v9

    .line 192
    check-cast v9, Ljava/lang/Boolean;

    .line 193
    .line 194
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 195
    .line 196
    .line 197
    move-result v9

    .line 198
    invoke-virtual {v13, v11}, Ll2/t;->Y(I)V

    .line 199
    .line 200
    .line 201
    if-eqz v9, :cond_c

    .line 202
    .line 203
    move-wide v9, v2

    .line 204
    :goto_8
    const/4 v14, 0x0

    .line 205
    goto :goto_9

    .line 206
    :cond_c
    move-wide v9, v4

    .line 207
    goto :goto_8

    .line 208
    :goto_9
    invoke-virtual {v13, v14}, Ll2/t;->q(Z)V

    .line 209
    .line 210
    .line 211
    new-instance v14, Le3/s;

    .line 212
    .line 213
    invoke-direct {v14, v9, v10}, Le3/s;-><init>(J)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    check-cast v1, Ljava/lang/Boolean;

    .line 221
    .line 222
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 223
    .line 224
    .line 225
    move-result v1

    .line 226
    invoke-virtual {v13, v11}, Ll2/t;->Y(I)V

    .line 227
    .line 228
    .line 229
    if-eqz v1, :cond_d

    .line 230
    .line 231
    move-wide v9, v2

    .line 232
    :goto_a
    const/4 v1, 0x0

    .line 233
    goto :goto_b

    .line 234
    :cond_d
    move-wide v9, v4

    .line 235
    goto :goto_a

    .line 236
    :goto_b
    invoke-virtual {v13, v1}, Ll2/t;->q(Z)V

    .line 237
    .line 238
    .line 239
    new-instance v1, Le3/s;

    .line 240
    .line 241
    invoke-direct {v1, v9, v10}, Le3/s;-><init>(J)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v8}, Lc1/w1;->f()Lc1/r1;

    .line 245
    .line 246
    .line 247
    move-result-object v9

    .line 248
    const v10, 0x3f19b444

    .line 249
    .line 250
    .line 251
    invoke-virtual {v13, v10}, Ll2/t;->Y(I)V

    .line 252
    .line 253
    .line 254
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 255
    .line 256
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 257
    .line 258
    invoke-interface {v9, v10, v11}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v9

    .line 262
    if-eqz v9, :cond_e

    .line 263
    .line 264
    const v9, 0x10398cab

    .line 265
    .line 266
    .line 267
    invoke-virtual {v13, v9}, Ll2/t;->Y(I)V

    .line 268
    .line 269
    .line 270
    sget-object v9, Lk2/w;->f:Lk2/w;

    .line 271
    .line 272
    invoke-static {v9, v13}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 273
    .line 274
    .line 275
    move-result-object v9

    .line 276
    const/4 v10, 0x0

    .line 277
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 278
    .line 279
    .line 280
    :goto_c
    move-object v11, v9

    .line 281
    goto :goto_d

    .line 282
    :cond_e
    const/4 v10, 0x0

    .line 283
    const v9, 0x103b614d

    .line 284
    .line 285
    .line 286
    invoke-virtual {v13, v9}, Ll2/t;->Y(I)V

    .line 287
    .line 288
    .line 289
    sget-object v9, Lk2/w;->g:Lk2/w;

    .line 290
    .line 291
    invoke-static {v9, v13}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 292
    .line 293
    .line 294
    move-result-object v9

    .line 295
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 296
    .line 297
    .line 298
    goto :goto_c

    .line 299
    :goto_d
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 300
    .line 301
    .line 302
    move-object v9, v14

    .line 303
    const/4 v14, 0x0

    .line 304
    move-object v10, v1

    .line 305
    invoke-static/range {v8 .. v14}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    sget-object v8, Lh2/p1;->a:Ll2/e0;

    .line 310
    .line 311
    iget-object v1, v1, Lc1/t1;->m:Ll2/j1;

    .line 312
    .line 313
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    check-cast v1, Le3/s;

    .line 318
    .line 319
    iget-wide v9, v1, Le3/s;->a:J

    .line 320
    .line 321
    invoke-static {v9, v10, v8}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 322
    .line 323
    .line 324
    move-result-object v1

    .line 325
    and-int/lit8 v0, v0, 0x70

    .line 326
    .line 327
    const/16 v8, 0x8

    .line 328
    .line 329
    or-int/2addr v0, v8

    .line 330
    invoke-static {v1, v6, v13, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 331
    .line 332
    .line 333
    goto :goto_e

    .line 334
    :cond_f
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 335
    .line 336
    .line 337
    :goto_e
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 338
    .line 339
    .line 340
    move-result-object v9

    .line 341
    if-eqz v9, :cond_10

    .line 342
    .line 343
    new-instance v0, Lh2/va;

    .line 344
    .line 345
    const/4 v8, 0x0

    .line 346
    move-wide v1, v2

    .line 347
    move-wide v3, v4

    .line 348
    move v5, v15

    .line 349
    invoke-direct/range {v0 .. v8}, Lh2/va;-><init>(JJZLt2/b;II)V

    .line 350
    .line 351
    .line 352
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 353
    .line 354
    :cond_10
    return-void
.end method
