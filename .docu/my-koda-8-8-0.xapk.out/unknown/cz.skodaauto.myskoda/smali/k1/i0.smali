.class public final Lk1/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/v0;
.implements Lk1/c1;


# instance fields
.field public final a:Lk1/g;

.field public final b:Lk1/i;

.field public final c:F

.field public final d:Lk1/x;

.field public final e:F

.field public final f:I

.field public final g:Lk1/g0;


# direct methods
.method public constructor <init>(Lk1/g;Lk1/i;FLk1/x;FILk1/g0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk1/i0;->a:Lk1/g;

    .line 5
    .line 6
    iput-object p2, p0, Lk1/i0;->b:Lk1/i;

    .line 7
    .line 8
    iput p3, p0, Lk1/i0;->c:F

    .line 9
    .line 10
    iput-object p4, p0, Lk1/i0;->d:Lk1/x;

    .line 11
    .line 12
    iput p5, p0, Lk1/i0;->e:F

    .line 13
    .line 14
    iput p6, p0, Lk1/i0;->f:I

    .line 15
    .line 16
    iput-object p7, p0, Lk1/i0;->g:Lk1/g0;

    .line 17
    .line 18
    return-void
.end method

.method public static g(Ljava/util/List;IIIILk1/g0;)I
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v2, v2}, Landroidx/collection/n;->a(II)J

    .line 7
    .line 8
    .line 9
    move-result-wide v3

    .line 10
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v5

    .line 14
    if-eqz v5, :cond_0

    .line 15
    .line 16
    goto/16 :goto_d

    .line 17
    .line 18
    :cond_0
    const v5, 0x7fffffff

    .line 19
    .line 20
    .line 21
    invoke-static {v2, v1, v2, v5}, Lt4/b;->a(IIII)J

    .line 22
    .line 23
    .line 24
    move-result-wide v9

    .line 25
    new-instance v11, Lk1/d0;

    .line 26
    .line 27
    move/from16 v12, p3

    .line 28
    .line 29
    move/from16 v7, p4

    .line 30
    .line 31
    move-object/from16 v8, p5

    .line 32
    .line 33
    move-object v6, v11

    .line 34
    move/from16 v11, p2

    .line 35
    .line 36
    invoke-direct/range {v6 .. v12}, Lk1/d0;-><init>(ILk1/g0;JII)V

    .line 37
    .line 38
    .line 39
    move-object v11, v6

    .line 40
    invoke-static {v2, v0}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    check-cast v6, Lt3/p0;

    .line 45
    .line 46
    if-eqz v6, :cond_1

    .line 47
    .line 48
    invoke-interface {v6, v1}, Lt3/p0;->A(I)I

    .line 49
    .line 50
    .line 51
    move-result v7

    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move v7, v2

    .line 54
    :goto_0
    if-eqz v6, :cond_2

    .line 55
    .line 56
    invoke-interface {v6, v7}, Lt3/p0;->G(I)I

    .line 57
    .line 58
    .line 59
    move-result v8

    .line 60
    goto :goto_1

    .line 61
    :cond_2
    move v8, v2

    .line 62
    :goto_1
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    const/4 v10, 0x1

    .line 67
    if-le v9, v10, :cond_3

    .line 68
    .line 69
    move v12, v10

    .line 70
    goto :goto_2

    .line 71
    :cond_3
    move v12, v2

    .line 72
    :goto_2
    invoke-static {v1, v5}, Landroidx/collection/n;->a(II)J

    .line 73
    .line 74
    .line 75
    move-result-wide v14

    .line 76
    move-wide/from16 v22, v3

    .line 77
    .line 78
    if-nez v6, :cond_4

    .line 79
    .line 80
    const/16 v16, 0x0

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_4
    invoke-static {v8, v7}, Landroidx/collection/n;->a(II)J

    .line 84
    .line 85
    .line 86
    move-result-wide v2

    .line 87
    new-instance v4, Landroidx/collection/n;

    .line 88
    .line 89
    invoke-direct {v4, v2, v3}, Landroidx/collection/n;-><init>(J)V

    .line 90
    .line 91
    .line 92
    move-object/from16 v16, v4

    .line 93
    .line 94
    :goto_3
    const/16 v20, 0x0

    .line 95
    .line 96
    const/16 v21, 0x0

    .line 97
    .line 98
    const/4 v13, 0x0

    .line 99
    const/16 v17, 0x0

    .line 100
    .line 101
    const/16 v18, 0x0

    .line 102
    .line 103
    const/16 v19, 0x0

    .line 104
    .line 105
    invoke-virtual/range {v11 .. v21}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    iget-boolean v2, v2, Lk1/c0;->b:Z

    .line 110
    .line 111
    if-eqz v2, :cond_5

    .line 112
    .line 113
    invoke-virtual/range {p5 .. p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    sget-object v0, Lk1/f0;->d:Lk1/f0;

    .line 117
    .line 118
    move-wide/from16 v3, v22

    .line 119
    .line 120
    goto/16 :goto_d

    .line 121
    .line 122
    :cond_5
    move-object v2, v0

    .line 123
    check-cast v2, Ljava/util/Collection;

    .line 124
    .line 125
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 126
    .line 127
    .line 128
    move-result v2

    .line 129
    move v12, v1

    .line 130
    move/from16 v14, v17

    .line 131
    .line 132
    move/from16 v3, v19

    .line 133
    .line 134
    const/4 v4, 0x0

    .line 135
    const/4 v13, 0x0

    .line 136
    const/16 v22, 0x0

    .line 137
    .line 138
    :goto_4
    if-ge v4, v2, :cond_d

    .line 139
    .line 140
    sub-int v8, v12, v8

    .line 141
    .line 142
    add-int/lit8 v12, v4, 0x1

    .line 143
    .line 144
    invoke-static {v3, v7}, Ljava/lang/Math;->max(II)I

    .line 145
    .line 146
    .line 147
    move-result v19

    .line 148
    invoke-static {v12, v0}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    check-cast v3, Lt3/p0;

    .line 153
    .line 154
    if-eqz v3, :cond_6

    .line 155
    .line 156
    invoke-interface {v3, v1}, Lt3/p0;->A(I)I

    .line 157
    .line 158
    .line 159
    move-result v7

    .line 160
    goto :goto_5

    .line 161
    :cond_6
    const/4 v7, 0x0

    .line 162
    :goto_5
    if-eqz v3, :cond_7

    .line 163
    .line 164
    invoke-interface {v3, v7}, Lt3/p0;->G(I)I

    .line 165
    .line 166
    .line 167
    move-result v13

    .line 168
    add-int v13, v13, p2

    .line 169
    .line 170
    goto :goto_6

    .line 171
    :cond_7
    const/4 v13, 0x0

    .line 172
    :goto_6
    add-int/lit8 v4, v4, 0x2

    .line 173
    .line 174
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 175
    .line 176
    .line 177
    move-result v15

    .line 178
    if-ge v4, v15, :cond_8

    .line 179
    .line 180
    move v4, v12

    .line 181
    move v12, v10

    .line 182
    goto :goto_7

    .line 183
    :cond_8
    move v4, v12

    .line 184
    const/4 v12, 0x0

    .line 185
    :goto_7
    sub-int v17, v4, v22

    .line 186
    .line 187
    move/from16 v16, v17

    .line 188
    .line 189
    move/from16 v17, v14

    .line 190
    .line 191
    invoke-static {v8, v5}, Landroidx/collection/n;->a(II)J

    .line 192
    .line 193
    .line 194
    move-result-wide v14

    .line 195
    if-nez v3, :cond_9

    .line 196
    .line 197
    const/4 v9, 0x0

    .line 198
    goto :goto_8

    .line 199
    :cond_9
    invoke-static {v13, v7}, Landroidx/collection/n;->a(II)J

    .line 200
    .line 201
    .line 202
    move-result-wide v5

    .line 203
    new-instance v9, Landroidx/collection/n;

    .line 204
    .line 205
    invoke-direct {v9, v5, v6}, Landroidx/collection/n;-><init>(J)V

    .line 206
    .line 207
    .line 208
    :goto_8
    const/16 v20, 0x0

    .line 209
    .line 210
    const/16 v21, 0x0

    .line 211
    .line 212
    move v6, v13

    .line 213
    move/from16 v13, v16

    .line 214
    .line 215
    move-object/from16 v16, v9

    .line 216
    .line 217
    invoke-virtual/range {v11 .. v21}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 218
    .line 219
    .line 220
    move-result-object v12

    .line 221
    iget-boolean v5, v12, Lk1/c0;->a:Z

    .line 222
    .line 223
    if-eqz v5, :cond_c

    .line 224
    .line 225
    add-int v19, v19, p3

    .line 226
    .line 227
    add-int v15, v19, v18

    .line 228
    .line 229
    move/from16 v14, v17

    .line 230
    .line 231
    move/from16 v17, v13

    .line 232
    .line 233
    if-eqz v3, :cond_a

    .line 234
    .line 235
    move v13, v10

    .line 236
    :goto_9
    move/from16 v16, v8

    .line 237
    .line 238
    goto :goto_a

    .line 239
    :cond_a
    const/4 v13, 0x0

    .line 240
    goto :goto_9

    .line 241
    :goto_a
    invoke-virtual/range {v11 .. v17}, Lk1/d0;->a(Lk1/c0;ZIIII)Lk1/d;

    .line 242
    .line 243
    .line 244
    move/from16 v17, v14

    .line 245
    .line 246
    sub-int v13, v6, p2

    .line 247
    .line 248
    add-int/lit8 v14, v17, 0x1

    .line 249
    .line 250
    iget-boolean v3, v12, Lk1/c0;->b:Z

    .line 251
    .line 252
    if-eqz v3, :cond_b

    .line 253
    .line 254
    move v13, v4

    .line 255
    move/from16 v18, v15

    .line 256
    .line 257
    goto :goto_c

    .line 258
    :cond_b
    move v12, v1

    .line 259
    move/from16 v22, v4

    .line 260
    .line 261
    move v8, v13

    .line 262
    move/from16 v18, v15

    .line 263
    .line 264
    const/4 v3, 0x0

    .line 265
    goto :goto_b

    .line 266
    :cond_c
    move/from16 v16, v8

    .line 267
    .line 268
    move v8, v6

    .line 269
    move/from16 v12, v16

    .line 270
    .line 271
    move/from16 v14, v17

    .line 272
    .line 273
    move/from16 v3, v19

    .line 274
    .line 275
    :goto_b
    move v13, v4

    .line 276
    const v5, 0x7fffffff

    .line 277
    .line 278
    .line 279
    goto/16 :goto_4

    .line 280
    .line 281
    :cond_d
    :goto_c
    sub-int v0, v18, p3

    .line 282
    .line 283
    invoke-static {v0, v13}, Landroidx/collection/n;->a(II)J

    .line 284
    .line 285
    .line 286
    move-result-wide v3

    .line 287
    :goto_d
    const/16 v0, 0x20

    .line 288
    .line 289
    shr-long v0, v3, v0

    .line 290
    .line 291
    long-to-int v0, v0

    .line 292
    return v0
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 38

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
    move/from16 v3, p3

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    invoke-static {v4, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    check-cast v5, Ljava/util/List;

    .line 15
    .line 16
    if-eqz v5, :cond_0

    .line 17
    .line 18
    invoke-static {v5}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    check-cast v5, Lt3/p0;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v5, 0x0

    .line 26
    :goto_0
    const/4 v7, 0x2

    .line 27
    invoke-static {v7, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v8

    .line 31
    check-cast v8, Ljava/util/List;

    .line 32
    .line 33
    if-eqz v8, :cond_1

    .line 34
    .line 35
    invoke-static {v8}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    check-cast v8, Lt3/p0;

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/4 v8, 0x0

    .line 43
    :goto_1
    const/4 v9, 0x7

    .line 44
    const/4 v10, 0x0

    .line 45
    invoke-static {v10, v3, v9}, Lt4/b;->b(III)J

    .line 46
    .line 47
    .line 48
    move-result-wide v11

    .line 49
    iget-object v9, v0, Lk1/i0;->g:Lk1/g0;

    .line 50
    .line 51
    invoke-virtual {v9, v5, v8, v11, v12}, Lk1/g0;->a(Lt3/p0;Lt3/p0;J)V

    .line 52
    .line 53
    .line 54
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Ljava/util/List;

    .line 59
    .line 60
    if-nez v2, :cond_2

    .line 61
    .line 62
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 63
    .line 64
    :cond_2
    iget v5, v0, Lk1/i0;->c:F

    .line 65
    .line 66
    invoke-interface {v1, v5}, Lt4/c;->Q(F)I

    .line 67
    .line 68
    .line 69
    move-result v16

    .line 70
    iget v5, v0, Lk1/i0;->e:F

    .line 71
    .line 72
    invoke-interface {v1, v5}, Lt4/c;->Q(F)I

    .line 73
    .line 74
    .line 75
    move-result v17

    .line 76
    invoke-static {v10, v10}, Landroidx/collection/n;->a(II)J

    .line 77
    .line 78
    .line 79
    move-result-wide v8

    .line 80
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    if-eqz v1, :cond_3

    .line 85
    .line 86
    return v10

    .line 87
    :cond_3
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    new-array v5, v1, [I

    .line 92
    .line 93
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 94
    .line 95
    .line 96
    move-result v11

    .line 97
    new-array v12, v11, [I

    .line 98
    .line 99
    move-object/from16 v18, v2

    .line 100
    .line 101
    check-cast v18, Ljava/util/Collection;

    .line 102
    .line 103
    invoke-interface/range {v18 .. v18}, Ljava/util/Collection;->size()I

    .line 104
    .line 105
    .line 106
    move-result v13

    .line 107
    move v14, v10

    .line 108
    :goto_2
    if-ge v14, v13, :cond_4

    .line 109
    .line 110
    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v15

    .line 114
    check-cast v15, Lt3/p0;

    .line 115
    .line 116
    invoke-interface {v15, v3}, Lt3/p0;->G(I)I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    aput v6, v5, v14

    .line 121
    .line 122
    invoke-interface {v15, v6}, Lt3/p0;->A(I)I

    .line 123
    .line 124
    .line 125
    move-result v6

    .line 126
    aput v6, v12, v14

    .line 127
    .line 128
    add-int/lit8 v14, v14, 0x1

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_4
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    iget-object v13, v0, Lk1/i0;->g:Lk1/g0;

    .line 136
    .line 137
    const v14, 0x7fffffff

    .line 138
    .line 139
    .line 140
    if-ge v14, v6, :cond_5

    .line 141
    .line 142
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    sget-object v6, Lk1/f0;->d:Lk1/f0;

    .line 146
    .line 147
    :cond_5
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    if-lt v14, v6, :cond_6

    .line 152
    .line 153
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    sget-object v6, Lk1/f0;->d:Lk1/f0;

    .line 157
    .line 158
    :cond_6
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 159
    .line 160
    .line 161
    move-result v6

    .line 162
    invoke-static {v14, v6}, Ljava/lang/Math;->min(II)I

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    move v15, v10

    .line 167
    move/from16 v19, v15

    .line 168
    .line 169
    :goto_3
    if-ge v15, v1, :cond_7

    .line 170
    .line 171
    aget v20, v5, v15

    .line 172
    .line 173
    add-int v19, v19, v20

    .line 174
    .line 175
    add-int/lit8 v15, v15, 0x1

    .line 176
    .line 177
    goto :goto_3

    .line 178
    :cond_7
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 179
    .line 180
    .line 181
    move-result v15

    .line 182
    sub-int/2addr v15, v4

    .line 183
    mul-int v15, v15, v16

    .line 184
    .line 185
    add-int v15, v15, v19

    .line 186
    .line 187
    if-eqz v11, :cond_22

    .line 188
    .line 189
    aget v19, v12, v10

    .line 190
    .line 191
    sub-int/2addr v11, v4

    .line 192
    move/from16 v20, v7

    .line 193
    .line 194
    move/from16 v21, v10

    .line 195
    .line 196
    if-gt v4, v11, :cond_a

    .line 197
    .line 198
    move/from16 v7, v19

    .line 199
    .line 200
    move v10, v4

    .line 201
    :goto_4
    aget v14, v12, v10

    .line 202
    .line 203
    if-ge v7, v14, :cond_8

    .line 204
    .line 205
    move v7, v14

    .line 206
    :cond_8
    if-eq v10, v11, :cond_9

    .line 207
    .line 208
    add-int/lit8 v10, v10, 0x1

    .line 209
    .line 210
    goto :goto_4

    .line 211
    :cond_9
    move/from16 v19, v7

    .line 212
    .line 213
    :cond_a
    if-eqz v1, :cond_21

    .line 214
    .line 215
    aget v7, v5, v21

    .line 216
    .line 217
    sub-int/2addr v1, v4

    .line 218
    if-gt v4, v1, :cond_c

    .line 219
    .line 220
    move v10, v4

    .line 221
    :goto_5
    aget v11, v5, v10

    .line 222
    .line 223
    if-ge v7, v11, :cond_b

    .line 224
    .line 225
    move v7, v11

    .line 226
    :cond_b
    if-eq v10, v1, :cond_c

    .line 227
    .line 228
    add-int/lit8 v10, v10, 0x1

    .line 229
    .line 230
    goto :goto_5

    .line 231
    :cond_c
    move v1, v15

    .line 232
    move/from16 v10, v19

    .line 233
    .line 234
    :goto_6
    if-gt v7, v1, :cond_20

    .line 235
    .line 236
    if-ne v10, v3, :cond_d

    .line 237
    .line 238
    goto/16 :goto_16

    .line 239
    .line 240
    :cond_d
    add-int v10, v7, v1

    .line 241
    .line 242
    div-int/lit8 v10, v10, 0x2

    .line 243
    .line 244
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 245
    .line 246
    .line 247
    move-result v11

    .line 248
    if-eqz v11, :cond_e

    .line 249
    .line 250
    move-object/from16 v35, v2

    .line 251
    .line 252
    move-object v11, v5

    .line 253
    move-wide v2, v8

    .line 254
    move-object/from16 v21, v12

    .line 255
    .line 256
    goto/16 :goto_14

    .line 257
    .line 258
    :cond_e
    move/from16 v11, v21

    .line 259
    .line 260
    const v14, 0x7fffffff

    .line 261
    .line 262
    .line 263
    invoke-static {v11, v10, v11, v14}, Lt4/b;->a(IIII)J

    .line 264
    .line 265
    .line 266
    move-result-wide v21

    .line 267
    new-instance v23, Lk1/d0;

    .line 268
    .line 269
    move-object v15, v12

    .line 270
    iget v12, v0, Lk1/i0;->f:I

    .line 271
    .line 272
    move v4, v11

    .line 273
    move v0, v14

    .line 274
    move-object/from16 v11, v23

    .line 275
    .line 276
    move-wide/from16 v36, v21

    .line 277
    .line 278
    move-object/from16 v21, v15

    .line 279
    .line 280
    move-wide/from16 v14, v36

    .line 281
    .line 282
    invoke-direct/range {v11 .. v17}, Lk1/d0;-><init>(ILk1/g0;JII)V

    .line 283
    .line 284
    .line 285
    invoke-static {v4, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v11

    .line 289
    check-cast v11, Lt3/p0;

    .line 290
    .line 291
    if-eqz v11, :cond_f

    .line 292
    .line 293
    aget v12, v21, v4

    .line 294
    .line 295
    goto :goto_7

    .line 296
    :cond_f
    move v12, v4

    .line 297
    :goto_7
    if-eqz v11, :cond_10

    .line 298
    .line 299
    aget v14, v5, v4

    .line 300
    .line 301
    goto :goto_8

    .line 302
    :cond_10
    move v14, v4

    .line 303
    :goto_8
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 304
    .line 305
    .line 306
    move-result v15

    .line 307
    const/4 v4, 0x1

    .line 308
    if-le v15, v4, :cond_11

    .line 309
    .line 310
    move/from16 v24, v4

    .line 311
    .line 312
    goto :goto_9

    .line 313
    :cond_11
    const/16 v24, 0x0

    .line 314
    .line 315
    :goto_9
    invoke-static {v10, v0}, Landroidx/collection/n;->a(II)J

    .line 316
    .line 317
    .line 318
    move-result-wide v26

    .line 319
    if-nez v11, :cond_12

    .line 320
    .line 321
    move-object v11, v5

    .line 322
    const/16 v28, 0x0

    .line 323
    .line 324
    goto :goto_a

    .line 325
    :cond_12
    move-object v11, v5

    .line 326
    invoke-static {v14, v12}, Landroidx/collection/n;->a(II)J

    .line 327
    .line 328
    .line 329
    move-result-wide v4

    .line 330
    new-instance v15, Landroidx/collection/n;

    .line 331
    .line 332
    invoke-direct {v15, v4, v5}, Landroidx/collection/n;-><init>(J)V

    .line 333
    .line 334
    .line 335
    move-object/from16 v28, v15

    .line 336
    .line 337
    :goto_a
    const/16 v32, 0x0

    .line 338
    .line 339
    const/16 v33, 0x0

    .line 340
    .line 341
    const/16 v25, 0x0

    .line 342
    .line 343
    const/16 v29, 0x0

    .line 344
    .line 345
    const/16 v30, 0x0

    .line 346
    .line 347
    const/16 v31, 0x0

    .line 348
    .line 349
    invoke-virtual/range {v23 .. v33}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 350
    .line 351
    .line 352
    move-result-object v4

    .line 353
    iget-boolean v4, v4, Lk1/c0;->b:Z

    .line 354
    .line 355
    if-eqz v4, :cond_13

    .line 356
    .line 357
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 358
    .line 359
    .line 360
    sget-object v4, Lk1/f0;->d:Lk1/f0;

    .line 361
    .line 362
    move-object/from16 v35, v2

    .line 363
    .line 364
    move-wide v2, v8

    .line 365
    goto/16 :goto_14

    .line 366
    .line 367
    :cond_13
    invoke-interface/range {v18 .. v18}, Ljava/util/Collection;->size()I

    .line 368
    .line 369
    .line 370
    move-result v4

    .line 371
    move/from16 v25, v10

    .line 372
    .line 373
    move v15, v12

    .line 374
    move/from16 v24, v14

    .line 375
    .line 376
    move/from16 v0, v31

    .line 377
    .line 378
    const/4 v5, 0x0

    .line 379
    const/4 v12, 0x0

    .line 380
    const/4 v14, 0x0

    .line 381
    :goto_b
    if-ge v5, v4, :cond_1b

    .line 382
    .line 383
    sub-int v14, v25, v24

    .line 384
    .line 385
    move/from16 p2, v4

    .line 386
    .line 387
    add-int/lit8 v4, v5, 0x1

    .line 388
    .line 389
    invoke-static {v0, v15}, Ljava/lang/Math;->max(II)I

    .line 390
    .line 391
    .line 392
    move-result v31

    .line 393
    invoke-static {v4, v2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    check-cast v0, Lt3/p0;

    .line 398
    .line 399
    if-eqz v0, :cond_14

    .line 400
    .line 401
    aget v15, v21, v4

    .line 402
    .line 403
    goto :goto_c

    .line 404
    :cond_14
    const/4 v15, 0x0

    .line 405
    :goto_c
    if-eqz v0, :cond_15

    .line 406
    .line 407
    aget v24, v11, v4

    .line 408
    .line 409
    add-int v24, v24, v16

    .line 410
    .line 411
    move-object/from16 v34, v0

    .line 412
    .line 413
    move/from16 v0, v24

    .line 414
    .line 415
    goto :goto_d

    .line 416
    :cond_15
    move-object/from16 v34, v0

    .line 417
    .line 418
    const/4 v0, 0x0

    .line 419
    :goto_d
    add-int/lit8 v5, v5, 0x2

    .line 420
    .line 421
    move-object/from16 v35, v2

    .line 422
    .line 423
    invoke-interface/range {v35 .. v35}, Ljava/util/List;->size()I

    .line 424
    .line 425
    .line 426
    move-result v2

    .line 427
    if-ge v5, v2, :cond_16

    .line 428
    .line 429
    const/16 v24, 0x1

    .line 430
    .line 431
    goto :goto_e

    .line 432
    :cond_16
    const/16 v24, 0x0

    .line 433
    .line 434
    :goto_e
    sub-int v25, v4, v12

    .line 435
    .line 436
    const v2, 0x7fffffff

    .line 437
    .line 438
    .line 439
    invoke-static {v14, v2}, Landroidx/collection/n;->a(II)J

    .line 440
    .line 441
    .line 442
    move-result-wide v26

    .line 443
    if-nez v34, :cond_17

    .line 444
    .line 445
    const/16 v28, 0x0

    .line 446
    .line 447
    goto :goto_f

    .line 448
    :cond_17
    invoke-static {v0, v15}, Landroidx/collection/n;->a(II)J

    .line 449
    .line 450
    .line 451
    move-result-wide v2

    .line 452
    new-instance v5, Landroidx/collection/n;

    .line 453
    .line 454
    invoke-direct {v5, v2, v3}, Landroidx/collection/n;-><init>(J)V

    .line 455
    .line 456
    .line 457
    move-object/from16 v28, v5

    .line 458
    .line 459
    :goto_f
    const/16 v32, 0x0

    .line 460
    .line 461
    const/16 v33, 0x0

    .line 462
    .line 463
    invoke-virtual/range {v23 .. v33}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 464
    .line 465
    .line 466
    move-result-object v2

    .line 467
    iget-boolean v3, v2, Lk1/c0;->a:Z

    .line 468
    .line 469
    if-eqz v3, :cond_1a

    .line 470
    .line 471
    add-int v31, v31, v17

    .line 472
    .line 473
    add-int v27, v31, v30

    .line 474
    .line 475
    move/from16 v26, v29

    .line 476
    .line 477
    move/from16 v29, v25

    .line 478
    .line 479
    if-eqz v34, :cond_18

    .line 480
    .line 481
    const/16 v25, 0x1

    .line 482
    .line 483
    :goto_10
    move-object/from16 v24, v2

    .line 484
    .line 485
    move/from16 v28, v14

    .line 486
    .line 487
    goto :goto_11

    .line 488
    :cond_18
    const/16 v25, 0x0

    .line 489
    .line 490
    goto :goto_10

    .line 491
    :goto_11
    invoke-virtual/range {v23 .. v29}, Lk1/d0;->a(Lk1/c0;ZIIII)Lk1/d;

    .line 492
    .line 493
    .line 494
    move-object/from16 v2, v24

    .line 495
    .line 496
    move/from16 v29, v26

    .line 497
    .line 498
    sub-int v0, v0, v16

    .line 499
    .line 500
    add-int/lit8 v29, v29, 0x1

    .line 501
    .line 502
    iget-boolean v2, v2, Lk1/c0;->b:Z

    .line 503
    .line 504
    if-eqz v2, :cond_19

    .line 505
    .line 506
    move v14, v4

    .line 507
    move/from16 v30, v27

    .line 508
    .line 509
    goto :goto_13

    .line 510
    :cond_19
    move/from16 v24, v0

    .line 511
    .line 512
    move v12, v4

    .line 513
    move/from16 v25, v10

    .line 514
    .line 515
    move/from16 v30, v27

    .line 516
    .line 517
    const/4 v0, 0x0

    .line 518
    goto :goto_12

    .line 519
    :cond_1a
    move/from16 v28, v14

    .line 520
    .line 521
    move/from16 v24, v0

    .line 522
    .line 523
    move/from16 v25, v28

    .line 524
    .line 525
    move/from16 v0, v31

    .line 526
    .line 527
    :goto_12
    move/from16 v3, p3

    .line 528
    .line 529
    move v5, v4

    .line 530
    move v14, v5

    .line 531
    move-object/from16 v2, v35

    .line 532
    .line 533
    move/from16 v4, p2

    .line 534
    .line 535
    goto/16 :goto_b

    .line 536
    .line 537
    :cond_1b
    move-object/from16 v35, v2

    .line 538
    .line 539
    :goto_13
    sub-int v0, v30, v17

    .line 540
    .line 541
    invoke-static {v0, v14}, Landroidx/collection/n;->a(II)J

    .line 542
    .line 543
    .line 544
    move-result-wide v2

    .line 545
    :goto_14
    const/16 v0, 0x20

    .line 546
    .line 547
    shr-long v4, v2, v0

    .line 548
    .line 549
    long-to-int v0, v4

    .line 550
    const-wide v4, 0xffffffffL

    .line 551
    .line 552
    .line 553
    .line 554
    .line 555
    and-long/2addr v2, v4

    .line 556
    long-to-int v2, v2

    .line 557
    move/from16 v3, p3

    .line 558
    .line 559
    if-gt v0, v3, :cond_1f

    .line 560
    .line 561
    if-ge v2, v6, :cond_1c

    .line 562
    .line 563
    goto :goto_15

    .line 564
    :cond_1c
    if-ge v0, v3, :cond_1e

    .line 565
    .line 566
    add-int/lit8 v1, v10, -0x1

    .line 567
    .line 568
    :cond_1d
    move v15, v10

    .line 569
    move-object v5, v11

    .line 570
    move-object/from16 v12, v21

    .line 571
    .line 572
    move-object/from16 v2, v35

    .line 573
    .line 574
    const/4 v4, 0x1

    .line 575
    const/16 v21, 0x0

    .line 576
    .line 577
    move v10, v0

    .line 578
    move-object/from16 v0, p0

    .line 579
    .line 580
    goto/16 :goto_6

    .line 581
    .line 582
    :cond_1e
    return v10

    .line 583
    :cond_1f
    :goto_15
    add-int/lit8 v7, v10, 0x1

    .line 584
    .line 585
    if-le v7, v1, :cond_1d

    .line 586
    .line 587
    return v7

    .line 588
    :cond_20
    :goto_16
    return v15

    .line 589
    :cond_21
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 590
    .line 591
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 592
    .line 593
    .line 594
    throw v0

    .line 595
    :cond_22
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 596
    .line 597
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 598
    .line 599
    .line 600
    throw v0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 63

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    move-object/from16 v1, p2

    .line 6
    .line 7
    move-wide/from16 v2, p3

    .line 8
    .line 9
    iget v4, v0, Lk1/i0;->f:I

    .line 10
    .line 11
    const/16 v5, 0xe

    .line 12
    .line 13
    sget-object v13, Lmx0/t;->d:Lmx0/t;

    .line 14
    .line 15
    const/4 v14, 0x0

    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    move-object v4, v1

    .line 19
    check-cast v4, Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-nez v4, :cond_0

    .line 26
    .line 27
    invoke-static {v2, v3}, Lt4/a;->g(J)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    iget-object v7, v0, Lk1/i0;->g:Lk1/g0;

    .line 32
    .line 33
    if-nez v4, :cond_1

    .line 34
    .line 35
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    sget-object v0, Lk1/f0;->d:Lk1/f0;

    .line 39
    .line 40
    sget-object v0, Lk1/f0;->d:Lk1/f0;

    .line 41
    .line 42
    :cond_0
    move-object v15, v13

    .line 43
    goto/16 :goto_1e

    .line 44
    .line 45
    :cond_1
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    check-cast v4, Ljava/util/List;

    .line 50
    .line 51
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 52
    .line 53
    .line 54
    move-result v8

    .line 55
    if-eqz v8, :cond_2

    .line 56
    .line 57
    new-instance v0, Ldj/a;

    .line 58
    .line 59
    invoke-direct {v0, v5}, Ldj/a;-><init>(I)V

    .line 60
    .line 61
    .line 62
    invoke-interface {v6, v14, v14, v13, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    return-object v0

    .line 67
    :cond_2
    const/4 v15, 0x1

    .line 68
    invoke-static {v15, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    check-cast v8, Ljava/util/List;

    .line 73
    .line 74
    const/16 v16, 0x0

    .line 75
    .line 76
    if-eqz v8, :cond_3

    .line 77
    .line 78
    invoke-static {v8}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v8

    .line 82
    check-cast v8, Lt3/p0;

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_3
    move-object/from16 v8, v16

    .line 86
    .line 87
    :goto_0
    const/4 v9, 0x2

    .line 88
    invoke-static {v9, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    check-cast v1, Ljava/util/List;

    .line 93
    .line 94
    if-eqz v1, :cond_4

    .line 95
    .line 96
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    check-cast v1, Lt3/p0;

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    move-object/from16 v1, v16

    .line 104
    .line 105
    :goto_1
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 106
    .line 107
    .line 108
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    sget-object v7, Lk1/t0;->d:Lk1/t0;

    .line 112
    .line 113
    invoke-static {v2, v3, v7}, Lk1/d;->g(JLk1/t0;)J

    .line 114
    .line 115
    .line 116
    move-result-wide v10

    .line 117
    const/16 v12, 0xa

    .line 118
    .line 119
    invoke-static {v12, v10, v11}, Lk1/d;->h(IJ)J

    .line 120
    .line 121
    .line 122
    move-result-wide v10

    .line 123
    invoke-static {v10, v11}, Lk1/d;->o(J)J

    .line 124
    .line 125
    .line 126
    move-result-wide v10

    .line 127
    const v12, 0x7fffffff

    .line 128
    .line 129
    .line 130
    const/16 v17, 0x0

    .line 131
    .line 132
    if-eqz v8, :cond_6

    .line 133
    .line 134
    invoke-static {v8}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 135
    .line 136
    .line 137
    move-result-object v18

    .line 138
    invoke-static/range {v18 .. v18}, Lk1/d;->j(Lk1/d1;)F

    .line 139
    .line 140
    .line 141
    move-result v18

    .line 142
    cmpg-float v18, v18, v17

    .line 143
    .line 144
    if-nez v18, :cond_5

    .line 145
    .line 146
    invoke-static {v8}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 147
    .line 148
    .line 149
    invoke-interface {v8, v10, v11}, Lt3/p0;->L(J)Lt3/e1;

    .line 150
    .line 151
    .line 152
    move-result-object v8

    .line 153
    move/from16 v18, v9

    .line 154
    .line 155
    invoke-virtual {v8}, Lt3/e1;->d0()I

    .line 156
    .line 157
    .line 158
    move-result v9

    .line 159
    move/from16 v19, v15

    .line 160
    .line 161
    invoke-virtual {v8}, Lt3/e1;->b0()I

    .line 162
    .line 163
    .line 164
    move-result v15

    .line 165
    invoke-static {v9, v15}, Landroidx/collection/n;->a(II)J

    .line 166
    .line 167
    .line 168
    move-result-wide v14

    .line 169
    new-instance v9, Landroidx/collection/n;

    .line 170
    .line 171
    invoke-direct {v9, v14, v15}, Landroidx/collection/n;-><init>(J)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v8}, Lt3/e1;->d0()I

    .line 175
    .line 176
    .line 177
    invoke-virtual {v8}, Lt3/e1;->b0()I

    .line 178
    .line 179
    .line 180
    goto :goto_2

    .line 181
    :cond_5
    move/from16 v18, v9

    .line 182
    .line 183
    move/from16 v19, v15

    .line 184
    .line 185
    invoke-interface {v8, v12}, Lt3/p0;->G(I)I

    .line 186
    .line 187
    .line 188
    move-result v9

    .line 189
    invoke-interface {v8, v9}, Lt3/p0;->A(I)I

    .line 190
    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_6
    move/from16 v18, v9

    .line 194
    .line 195
    move/from16 v19, v15

    .line 196
    .line 197
    :goto_2
    if-eqz v1, :cond_8

    .line 198
    .line 199
    invoke-static {v1}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 200
    .line 201
    .line 202
    move-result-object v8

    .line 203
    invoke-static {v8}, Lk1/d;->j(Lk1/d1;)F

    .line 204
    .line 205
    .line 206
    move-result v8

    .line 207
    cmpg-float v8, v8, v17

    .line 208
    .line 209
    if-nez v8, :cond_7

    .line 210
    .line 211
    invoke-static {v1}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 212
    .line 213
    .line 214
    invoke-interface {v1, v10, v11}, Lt3/p0;->L(J)Lt3/e1;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    invoke-virtual {v1}, Lt3/e1;->d0()I

    .line 219
    .line 220
    .line 221
    move-result v8

    .line 222
    invoke-virtual {v1}, Lt3/e1;->b0()I

    .line 223
    .line 224
    .line 225
    move-result v9

    .line 226
    invoke-static {v8, v9}, Landroidx/collection/n;->a(II)J

    .line 227
    .line 228
    .line 229
    move-result-wide v8

    .line 230
    new-instance v10, Landroidx/collection/n;

    .line 231
    .line 232
    invoke-direct {v10, v8, v9}, Landroidx/collection/n;-><init>(J)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v1}, Lt3/e1;->d0()I

    .line 236
    .line 237
    .line 238
    invoke-virtual {v1}, Lt3/e1;->b0()I

    .line 239
    .line 240
    .line 241
    goto :goto_3

    .line 242
    :cond_7
    invoke-interface {v1, v12}, Lt3/p0;->G(I)I

    .line 243
    .line 244
    .line 245
    move-result v8

    .line 246
    invoke-interface {v1, v8}, Lt3/p0;->A(I)I

    .line 247
    .line 248
    .line 249
    :cond_8
    :goto_3
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    invoke-static {v2, v3, v7}, Lk1/d;->g(JLk1/t0;)J

    .line 254
    .line 255
    .line 256
    move-result-wide v23

    .line 257
    new-instance v14, Ln2/b;

    .line 258
    .line 259
    const/16 v2, 0x10

    .line 260
    .line 261
    new-array v3, v2, [Lt3/r0;

    .line 262
    .line 263
    invoke-direct {v14, v3}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    invoke-static/range {v23 .. v24}, Lt4/a;->h(J)I

    .line 267
    .line 268
    .line 269
    move-result v3

    .line 270
    invoke-static/range {v23 .. v24}, Lt4/a;->j(J)I

    .line 271
    .line 272
    .line 273
    move-result v4

    .line 274
    invoke-static/range {v23 .. v24}, Lt4/a;->g(J)I

    .line 275
    .line 276
    .line 277
    move-result v7

    .line 278
    sget-object v8, Landroidx/collection/q;->a:Landroidx/collection/b0;

    .line 279
    .line 280
    new-instance v8, Landroidx/collection/b0;

    .line 281
    .line 282
    invoke-direct {v8}, Landroidx/collection/b0;-><init>()V

    .line 283
    .line 284
    .line 285
    new-instance v9, Ljava/util/ArrayList;

    .line 286
    .line 287
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 288
    .line 289
    .line 290
    iget v10, v0, Lk1/i0;->c:F

    .line 291
    .line 292
    invoke-interface {v6, v10}, Lt4/c;->w0(F)F

    .line 293
    .line 294
    .line 295
    move-result v10

    .line 296
    float-to-double v10, v10

    .line 297
    invoke-static {v10, v11}, Ljava/lang/Math;->ceil(D)D

    .line 298
    .line 299
    .line 300
    move-result-wide v10

    .line 301
    double-to-float v10, v10

    .line 302
    float-to-int v10, v10

    .line 303
    iget v11, v0, Lk1/i0;->e:F

    .line 304
    .line 305
    invoke-interface {v6, v11}, Lt4/c;->w0(F)F

    .line 306
    .line 307
    .line 308
    move-result v11

    .line 309
    move-object v15, v13

    .line 310
    float-to-double v12, v11

    .line 311
    invoke-static {v12, v13}, Ljava/lang/Math;->ceil(D)D

    .line 312
    .line 313
    .line 314
    move-result-wide v11

    .line 315
    double-to-float v11, v11

    .line 316
    float-to-int v11, v11

    .line 317
    move-object/from16 p3, v14

    .line 318
    .line 319
    const/4 v12, 0x0

    .line 320
    invoke-static {v12, v3, v12, v7}, Lt4/b;->a(IIII)J

    .line 321
    .line 322
    .line 323
    move-result-wide v13

    .line 324
    invoke-static {v5, v13, v14}, Lk1/d;->h(IJ)J

    .line 325
    .line 326
    .line 327
    move-result-wide v20

    .line 328
    move/from16 v30, v3

    .line 329
    .line 330
    invoke-static/range {v20 .. v21}, Lk1/d;->o(J)J

    .line 331
    .line 332
    .line 333
    move-result-wide v2

    .line 334
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 335
    .line 336
    .line 337
    move-result v5

    .line 338
    if-nez v5, :cond_9

    .line 339
    .line 340
    :catch_0
    move-object/from16 v5, v16

    .line 341
    .line 342
    goto :goto_4

    .line 343
    :cond_9
    :try_start_0
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v5

    .line 347
    check-cast v5, Lt3/p0;
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 348
    .line 349
    :goto_4
    if-eqz v5, :cond_b

    .line 350
    .line 351
    invoke-static {v5}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 352
    .line 353
    .line 354
    move-result-object v12

    .line 355
    invoke-static {v12}, Lk1/d;->j(Lk1/d1;)F

    .line 356
    .line 357
    .line 358
    move-result v12

    .line 359
    cmpg-float v12, v12, v17

    .line 360
    .line 361
    if-nez v12, :cond_a

    .line 362
    .line 363
    invoke-static {v5}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 364
    .line 365
    .line 366
    invoke-interface {v5, v2, v3}, Lt3/p0;->L(J)Lt3/e1;

    .line 367
    .line 368
    .line 369
    move-result-object v12

    .line 370
    move-object/from16 v32, v1

    .line 371
    .line 372
    invoke-virtual {v12}, Lt3/e1;->d0()I

    .line 373
    .line 374
    .line 375
    move-result v1

    .line 376
    move/from16 v33, v4

    .line 377
    .line 378
    invoke-virtual {v12}, Lt3/e1;->b0()I

    .line 379
    .line 380
    .line 381
    move-result v4

    .line 382
    invoke-static {v1, v4}, Landroidx/collection/n;->a(II)J

    .line 383
    .line 384
    .line 385
    move-result-wide v20

    .line 386
    :goto_5
    move-object/from16 v34, v5

    .line 387
    .line 388
    move-wide/from16 v4, v20

    .line 389
    .line 390
    goto :goto_6

    .line 391
    :cond_a
    move-object/from16 v32, v1

    .line 392
    .line 393
    move/from16 v33, v4

    .line 394
    .line 395
    const v1, 0x7fffffff

    .line 396
    .line 397
    .line 398
    invoke-interface {v5, v1}, Lt3/p0;->G(I)I

    .line 399
    .line 400
    .line 401
    move-result v4

    .line 402
    invoke-interface {v5, v4}, Lt3/p0;->A(I)I

    .line 403
    .line 404
    .line 405
    move-result v1

    .line 406
    invoke-static {v4, v1}, Landroidx/collection/n;->a(II)J

    .line 407
    .line 408
    .line 409
    move-result-wide v20

    .line 410
    move-object/from16 v12, v16

    .line 411
    .line 412
    goto :goto_5

    .line 413
    :goto_6
    new-instance v1, Landroidx/collection/n;

    .line 414
    .line 415
    invoke-direct {v1, v4, v5}, Landroidx/collection/n;-><init>(J)V

    .line 416
    .line 417
    .line 418
    goto :goto_7

    .line 419
    :cond_b
    move-object/from16 v32, v1

    .line 420
    .line 421
    move/from16 v33, v4

    .line 422
    .line 423
    move-object/from16 v34, v5

    .line 424
    .line 425
    move-object/from16 v1, v16

    .line 426
    .line 427
    move-object v12, v1

    .line 428
    :goto_7
    const/16 v46, 0x20

    .line 429
    .line 430
    if-eqz v1, :cond_c

    .line 431
    .line 432
    iget-wide v4, v1, Landroidx/collection/n;->a:J

    .line 433
    .line 434
    shr-long v4, v4, v46

    .line 435
    .line 436
    long-to-int v4, v4

    .line 437
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 438
    .line 439
    .line 440
    move-result-object v4

    .line 441
    goto :goto_8

    .line 442
    :cond_c
    move-object/from16 v4, v16

    .line 443
    .line 444
    :goto_8
    const-wide v47, 0xffffffffL

    .line 445
    .line 446
    .line 447
    .line 448
    .line 449
    move-object/from16 v49, v4

    .line 450
    .line 451
    if-eqz v1, :cond_d

    .line 452
    .line 453
    iget-wide v4, v1, Landroidx/collection/n;->a:J

    .line 454
    .line 455
    and-long v4, v4, v47

    .line 456
    .line 457
    long-to-int v4, v4

    .line 458
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    :goto_9
    move-object/from16 v40, v1

    .line 463
    .line 464
    const/16 v5, 0x10

    .line 465
    .line 466
    goto :goto_a

    .line 467
    :cond_d
    move-object/from16 v4, v16

    .line 468
    .line 469
    goto :goto_9

    .line 470
    :goto_a
    new-array v1, v5, [I

    .line 471
    .line 472
    new-array v5, v5, [I

    .line 473
    .line 474
    move-wide/from16 v50, v13

    .line 475
    .line 476
    new-instance v13, Landroidx/collection/c0;

    .line 477
    .line 478
    invoke-direct {v13}, Landroidx/collection/c0;-><init>()V

    .line 479
    .line 480
    .line 481
    new-instance v52, Lk1/d0;

    .line 482
    .line 483
    iget v14, v0, Lk1/i0;->f:I

    .line 484
    .line 485
    move-object/from16 v53, v1

    .line 486
    .line 487
    iget-object v1, v0, Lk1/i0;->g:Lk1/g0;

    .line 488
    .line 489
    move-object/from16 v22, v1

    .line 490
    .line 491
    move/from16 v25, v10

    .line 492
    .line 493
    move/from16 v26, v11

    .line 494
    .line 495
    move/from16 v21, v14

    .line 496
    .line 497
    move-object/from16 v20, v52

    .line 498
    .line 499
    invoke-direct/range {v20 .. v26}, Lk1/d0;-><init>(ILk1/g0;JII)V

    .line 500
    .line 501
    .line 502
    move-object v10, v5

    .line 503
    move/from16 v5, v25

    .line 504
    .line 505
    move/from16 v1, v26

    .line 506
    .line 507
    invoke-interface/range {v32 .. v32}, Ljava/util/Iterator;->hasNext()Z

    .line 508
    .line 509
    .line 510
    move-result v36

    .line 511
    move/from16 v11, v30

    .line 512
    .line 513
    invoke-static {v11, v7}, Landroidx/collection/n;->a(II)J

    .line 514
    .line 515
    .line 516
    move-result-wide v38

    .line 517
    const/16 v44, 0x0

    .line 518
    .line 519
    const/16 v45, 0x0

    .line 520
    .line 521
    const/16 v37, 0x0

    .line 522
    .line 523
    const/16 v41, 0x0

    .line 524
    .line 525
    const/16 v42, 0x0

    .line 526
    .line 527
    const/16 v43, 0x0

    .line 528
    .line 529
    move-object/from16 v35, v52

    .line 530
    .line 531
    invoke-virtual/range {v35 .. v45}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 532
    .line 533
    .line 534
    move-result-object v14

    .line 535
    iget-boolean v0, v14, Lk1/c0;->b:Z

    .line 536
    .line 537
    if-eqz v0, :cond_f

    .line 538
    .line 539
    if-eqz v40, :cond_e

    .line 540
    .line 541
    move/from16 v27, v19

    .line 542
    .line 543
    goto :goto_b

    .line 544
    :cond_e
    const/16 v27, 0x0

    .line 545
    .line 546
    :goto_b
    const/16 v29, 0x0

    .line 547
    .line 548
    const/16 v31, 0x0

    .line 549
    .line 550
    const/16 v28, -0x1

    .line 551
    .line 552
    move/from16 v30, v11

    .line 553
    .line 554
    move-object/from16 v26, v14

    .line 555
    .line 556
    move-object/from16 v25, v52

    .line 557
    .line 558
    invoke-virtual/range {v25 .. v31}, Lk1/d0;->a(Lk1/c0;ZIIII)Lk1/d;

    .line 559
    .line 560
    .line 561
    goto :goto_c

    .line 562
    :cond_f
    move-object/from16 v26, v14

    .line 563
    .line 564
    :goto_c
    move-object/from16 v30, v4

    .line 565
    .line 566
    move/from16 v28, v5

    .line 567
    .line 568
    move/from16 v29, v7

    .line 569
    .line 570
    move/from16 p4, v11

    .line 571
    .line 572
    move-object v5, v12

    .line 573
    move-object/from16 v31, v13

    .line 574
    .line 575
    move-object/from16 v20, v15

    .line 576
    .line 577
    move/from16 v12, v33

    .line 578
    .line 579
    move-object/from16 v0, v34

    .line 580
    .line 581
    move-object/from16 v25, v49

    .line 582
    .line 583
    move-object/from16 v14, v53

    .line 584
    .line 585
    const/4 v4, 0x0

    .line 586
    const/4 v6, 0x0

    .line 587
    const/16 v21, 0x0

    .line 588
    .line 589
    const/16 v27, 0x0

    .line 590
    .line 591
    const/16 v58, 0x0

    .line 592
    .line 593
    const/16 v59, 0x0

    .line 594
    .line 595
    move/from16 v13, v29

    .line 596
    .line 597
    move-object v15, v10

    .line 598
    move-object/from16 v10, v26

    .line 599
    .line 600
    const/4 v7, 0x0

    .line 601
    move/from16 v26, v1

    .line 602
    .line 603
    const/4 v1, 0x0

    .line 604
    :goto_d
    iget-boolean v10, v10, Lk1/c0;->b:Z

    .line 605
    .line 606
    if-nez v10, :cond_1b

    .line 607
    .line 608
    if-eqz v0, :cond_1b

    .line 609
    .line 610
    invoke-static/range {v25 .. v25}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 611
    .line 612
    .line 613
    invoke-virtual/range {v25 .. v25}, Ljava/lang/Integer;->intValue()I

    .line 614
    .line 615
    .line 616
    move-result v10

    .line 617
    invoke-static/range {v30 .. v30}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 618
    .line 619
    .line 620
    move/from16 v25, v10

    .line 621
    .line 622
    invoke-virtual/range {v30 .. v30}, Ljava/lang/Integer;->intValue()I

    .line 623
    .line 624
    .line 625
    move-result v10

    .line 626
    move/from16 v30, v7

    .line 627
    .line 628
    add-int v7, v21, v25

    .line 629
    .line 630
    invoke-static {v1, v10}, Ljava/lang/Math;->max(II)I

    .line 631
    .line 632
    .line 633
    move-result v60

    .line 634
    sub-int v1, p4, v25

    .line 635
    .line 636
    add-int/lit8 v10, v4, 0x1

    .line 637
    .line 638
    invoke-virtual/range {v22 .. v22}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 639
    .line 640
    .line 641
    invoke-virtual {v9, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 642
    .line 643
    .line 644
    invoke-virtual {v8, v4, v5}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 645
    .line 646
    .line 647
    invoke-interface {v0}, Lt3/p0;->l()Ljava/lang/Object;

    .line 648
    .line 649
    .line 650
    sub-int v54, v10, v27

    .line 651
    .line 652
    invoke-interface/range {v32 .. v32}, Ljava/util/Iterator;->hasNext()Z

    .line 653
    .line 654
    .line 655
    move-result v0

    .line 656
    if-nez v0, :cond_10

    .line 657
    .line 658
    :catch_1
    move-object/from16 v0, v16

    .line 659
    .line 660
    goto :goto_e

    .line 661
    :cond_10
    :try_start_1
    invoke-interface/range {v32 .. v32}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 662
    .line 663
    .line 664
    move-result-object v0

    .line 665
    check-cast v0, Lt3/p0;
    :try_end_1
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_1

    .line 666
    .line 667
    :goto_e
    if-eqz v0, :cond_12

    .line 668
    .line 669
    invoke-static {v0}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 670
    .line 671
    .line 672
    move-result-object v4

    .line 673
    invoke-static {v4}, Lk1/d;->j(Lk1/d1;)F

    .line 674
    .line 675
    .line 676
    move-result v4

    .line 677
    cmpg-float v4, v4, v17

    .line 678
    .line 679
    if-nez v4, :cond_11

    .line 680
    .line 681
    invoke-static {v0}, Lk1/d;->i(Lt3/p0;)Lk1/d1;

    .line 682
    .line 683
    .line 684
    invoke-interface {v0, v2, v3}, Lt3/p0;->L(J)Lt3/e1;

    .line 685
    .line 686
    .line 687
    move-result-object v4

    .line 688
    invoke-virtual {v4}, Lt3/e1;->d0()I

    .line 689
    .line 690
    .line 691
    move-result v5

    .line 692
    move-wide/from16 v33, v2

    .line 693
    .line 694
    invoke-virtual {v4}, Lt3/e1;->b0()I

    .line 695
    .line 696
    .line 697
    move-result v2

    .line 698
    invoke-static {v5, v2}, Landroidx/collection/n;->a(II)J

    .line 699
    .line 700
    .line 701
    move-result-wide v2

    .line 702
    goto :goto_f

    .line 703
    :cond_11
    move-wide/from16 v33, v2

    .line 704
    .line 705
    const v2, 0x7fffffff

    .line 706
    .line 707
    .line 708
    invoke-interface {v0, v2}, Lt3/p0;->G(I)I

    .line 709
    .line 710
    .line 711
    move-result v3

    .line 712
    invoke-interface {v0, v3}, Lt3/p0;->A(I)I

    .line 713
    .line 714
    .line 715
    move-result v2

    .line 716
    invoke-static {v3, v2}, Landroidx/collection/n;->a(II)J

    .line 717
    .line 718
    .line 719
    move-result-wide v2

    .line 720
    move-object/from16 v4, v16

    .line 721
    .line 722
    :goto_f
    new-instance v5, Landroidx/collection/n;

    .line 723
    .line 724
    invoke-direct {v5, v2, v3}, Landroidx/collection/n;-><init>(J)V

    .line 725
    .line 726
    .line 727
    goto :goto_10

    .line 728
    :cond_12
    move-wide/from16 v33, v2

    .line 729
    .line 730
    move-object/from16 v4, v16

    .line 731
    .line 732
    move-object v5, v4

    .line 733
    :goto_10
    if-eqz v5, :cond_13

    .line 734
    .line 735
    iget-wide v2, v5, Landroidx/collection/n;->a:J

    .line 736
    .line 737
    shr-long v2, v2, v46

    .line 738
    .line 739
    long-to-int v2, v2

    .line 740
    add-int v2, v2, v28

    .line 741
    .line 742
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 743
    .line 744
    .line 745
    move-result-object v2

    .line 746
    goto :goto_11

    .line 747
    :cond_13
    move-object/from16 v2, v16

    .line 748
    .line 749
    :goto_11
    move-object/from16 p4, v2

    .line 750
    .line 751
    if-eqz v5, :cond_14

    .line 752
    .line 753
    iget-wide v2, v5, Landroidx/collection/n;->a:J

    .line 754
    .line 755
    and-long v2, v2, v47

    .line 756
    .line 757
    long-to-int v2, v2

    .line 758
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 759
    .line 760
    .line 761
    move-result-object v2

    .line 762
    goto :goto_12

    .line 763
    :cond_14
    move-object/from16 v2, v16

    .line 764
    .line 765
    :goto_12
    invoke-interface/range {v32 .. v32}, Ljava/util/Iterator;->hasNext()Z

    .line 766
    .line 767
    .line 768
    move-result v53

    .line 769
    invoke-static {v1, v13}, Landroidx/collection/n;->a(II)J

    .line 770
    .line 771
    .line 772
    move-result-wide v55

    .line 773
    if-nez v5, :cond_15

    .line 774
    .line 775
    move-object/from16 v21, v0

    .line 776
    .line 777
    move/from16 v25, v1

    .line 778
    .line 779
    move-object/from16 v57, v16

    .line 780
    .line 781
    goto :goto_13

    .line 782
    :cond_15
    invoke-static/range {p4 .. p4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 783
    .line 784
    .line 785
    invoke-virtual/range {p4 .. p4}, Ljava/lang/Integer;->intValue()I

    .line 786
    .line 787
    .line 788
    move-result v3

    .line 789
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 790
    .line 791
    .line 792
    move-object/from16 v21, v0

    .line 793
    .line 794
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 795
    .line 796
    .line 797
    move-result v0

    .line 798
    move/from16 v25, v1

    .line 799
    .line 800
    invoke-static {v3, v0}, Landroidx/collection/n;->a(II)J

    .line 801
    .line 802
    .line 803
    move-result-wide v0

    .line 804
    new-instance v3, Landroidx/collection/n;

    .line 805
    .line 806
    invoke-direct {v3, v0, v1}, Landroidx/collection/n;-><init>(J)V

    .line 807
    .line 808
    .line 809
    move-object/from16 v57, v3

    .line 810
    .line 811
    :goto_13
    const/16 v61, 0x0

    .line 812
    .line 813
    const/16 v62, 0x0

    .line 814
    .line 815
    invoke-virtual/range {v52 .. v62}, Lk1/d0;->b(ZIJLandroidx/collection/n;IIIZZ)Lk1/c0;

    .line 816
    .line 817
    .line 818
    move-result-object v0

    .line 819
    iget-boolean v1, v0, Lk1/c0;->a:Z

    .line 820
    .line 821
    if-eqz v1, :cond_1a

    .line 822
    .line 823
    invoke-static {v12, v7}, Ljava/lang/Math;->max(II)I

    .line 824
    .line 825
    .line 826
    move-result v1

    .line 827
    invoke-static {v1, v11}, Ljava/lang/Math;->min(II)I

    .line 828
    .line 829
    .line 830
    move-result v1

    .line 831
    add-int v56, v59, v60

    .line 832
    .line 833
    move/from16 v55, v58

    .line 834
    .line 835
    move/from16 v58, v54

    .line 836
    .line 837
    if-eqz v5, :cond_16

    .line 838
    .line 839
    move/from16 v54, v19

    .line 840
    .line 841
    :goto_14
    move-object/from16 v53, v0

    .line 842
    .line 843
    move/from16 v57, v25

    .line 844
    .line 845
    goto :goto_15

    .line 846
    :cond_16
    const/16 v54, 0x0

    .line 847
    .line 848
    goto :goto_14

    .line 849
    :goto_15
    invoke-virtual/range {v52 .. v58}, Lk1/d0;->a(Lk1/c0;ZIIII)Lk1/d;

    .line 850
    .line 851
    .line 852
    move/from16 v58, v55

    .line 853
    .line 854
    add-int/lit8 v7, v30, 0x1

    .line 855
    .line 856
    array-length v0, v15

    .line 857
    const-string v3, "copyOf(...)"

    .line 858
    .line 859
    if-ge v0, v7, :cond_17

    .line 860
    .line 861
    array-length v0, v15

    .line 862
    mul-int/lit8 v0, v0, 0x3

    .line 863
    .line 864
    div-int/lit8 v0, v0, 0x2

    .line 865
    .line 866
    invoke-static {v7, v0}, Ljava/lang/Math;->max(II)I

    .line 867
    .line 868
    .line 869
    move-result v0

    .line 870
    invoke-static {v15, v0}, Ljava/util/Arrays;->copyOf([II)[I

    .line 871
    .line 872
    .line 873
    move-result-object v15

    .line 874
    invoke-static {v15, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    :cond_17
    aput v60, v15, v30

    .line 878
    .line 879
    add-int/lit8 v7, v30, 0x1

    .line 880
    .line 881
    sub-int v0, v29, v56

    .line 882
    .line 883
    sub-int v13, v0, v26

    .line 884
    .line 885
    add-int/lit8 v0, v6, 0x1

    .line 886
    .line 887
    array-length v5, v14

    .line 888
    if-ge v5, v0, :cond_18

    .line 889
    .line 890
    array-length v5, v14

    .line 891
    mul-int/lit8 v5, v5, 0x3

    .line 892
    .line 893
    div-int/lit8 v5, v5, 0x2

    .line 894
    .line 895
    invoke-static {v0, v5}, Ljava/lang/Math;->max(II)I

    .line 896
    .line 897
    .line 898
    move-result v0

    .line 899
    invoke-static {v14, v0}, Ljava/util/Arrays;->copyOf([II)[I

    .line 900
    .line 901
    .line 902
    move-result-object v14

    .line 903
    invoke-static {v14, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 904
    .line 905
    .line 906
    :cond_18
    aput v10, v14, v6

    .line 907
    .line 908
    add-int/lit8 v6, v6, 0x1

    .line 909
    .line 910
    if-eqz p4, :cond_19

    .line 911
    .line 912
    invoke-virtual/range {p4 .. p4}, Ljava/lang/Integer;->intValue()I

    .line 913
    .line 914
    .line 915
    move-result v0

    .line 916
    sub-int v0, v0, v28

    .line 917
    .line 918
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 919
    .line 920
    .line 921
    move-result-object v0

    .line 922
    goto :goto_16

    .line 923
    :cond_19
    move-object/from16 v0, v16

    .line 924
    .line 925
    :goto_16
    add-int/lit8 v58, v58, 0x1

    .line 926
    .line 927
    add-int v56, v56, v26

    .line 928
    .line 929
    move-object/from16 v25, v0

    .line 930
    .line 931
    move v12, v1

    .line 932
    move/from16 v27, v10

    .line 933
    .line 934
    move/from16 v57, v11

    .line 935
    .line 936
    move/from16 v59, v56

    .line 937
    .line 938
    const/4 v0, 0x0

    .line 939
    const/4 v1, 0x0

    .line 940
    goto :goto_17

    .line 941
    :cond_1a
    move-object/from16 v53, v0

    .line 942
    .line 943
    move/from16 v57, v25

    .line 944
    .line 945
    move-object/from16 v25, p4

    .line 946
    .line 947
    move v0, v7

    .line 948
    move/from16 v7, v30

    .line 949
    .line 950
    move/from16 v1, v60

    .line 951
    .line 952
    :goto_17
    move-object/from16 p4, v21

    .line 953
    .line 954
    move/from16 v21, v0

    .line 955
    .line 956
    move-object/from16 v0, p4

    .line 957
    .line 958
    move-object/from16 v30, v2

    .line 959
    .line 960
    move-object v5, v4

    .line 961
    move v4, v10

    .line 962
    move-wide/from16 v2, v33

    .line 963
    .line 964
    move-object/from16 v10, v53

    .line 965
    .line 966
    move/from16 p4, v57

    .line 967
    .line 968
    goto/16 :goto_d

    .line 969
    .line 970
    :cond_1b
    move/from16 v30, v7

    .line 971
    .line 972
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 973
    .line 974
    .line 975
    move-result v0

    .line 976
    new-array v1, v0, [Lt3/e1;

    .line 977
    .line 978
    const/4 v2, 0x0

    .line 979
    :goto_18
    if-ge v2, v0, :cond_1c

    .line 980
    .line 981
    invoke-virtual {v8, v2}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 982
    .line 983
    .line 984
    move-result-object v3

    .line 985
    aput-object v3, v1, v2

    .line 986
    .line 987
    add-int/lit8 v2, v2, 0x1

    .line 988
    .line 989
    goto :goto_18

    .line 990
    :cond_1c
    new-array v11, v6, [I

    .line 991
    .line 992
    new-array v13, v6, [I

    .line 993
    .line 994
    move-object v8, v1

    .line 995
    move-object v7, v9

    .line 996
    move v1, v12

    .line 997
    const/4 v9, 0x0

    .line 998
    const/4 v12, 0x0

    .line 999
    const/16 v17, 0x0

    .line 1000
    .line 1001
    :goto_19
    if-ge v12, v6, :cond_20

    .line 1002
    .line 1003
    aget v10, v14, v12

    .line 1004
    .line 1005
    if-ltz v12, :cond_1f

    .line 1006
    .line 1007
    move/from16 v0, v30

    .line 1008
    .line 1009
    if-ge v12, v0, :cond_1f

    .line 1010
    .line 1011
    aget v2, v15, v12

    .line 1012
    .line 1013
    move-object/from16 v3, v31

    .line 1014
    .line 1015
    invoke-virtual {v3, v12}, Landroidx/collection/c0;->b(I)Z

    .line 1016
    .line 1017
    .line 1018
    move-result v4

    .line 1019
    if-eqz v4, :cond_1d

    .line 1020
    .line 1021
    const v4, 0x7fffffff

    .line 1022
    .line 1023
    .line 1024
    goto :goto_1a

    .line 1025
    :cond_1d
    invoke-static/range {v50 .. v51}, Lt4/a;->g(J)I

    .line 1026
    .line 1027
    .line 1028
    move-result v2

    .line 1029
    const v4, 0x7fffffff

    .line 1030
    .line 1031
    .line 1032
    if-ne v2, v4, :cond_1e

    .line 1033
    .line 1034
    move v2, v4

    .line 1035
    goto :goto_1a

    .line 1036
    :cond_1e
    invoke-static/range {v50 .. v51}, Lt4/a;->g(J)I

    .line 1037
    .line 1038
    .line 1039
    move-result v2

    .line 1040
    sub-int v2, v2, v17

    .line 1041
    .line 1042
    :goto_1a
    invoke-static/range {v50 .. v51}, Lt4/a;->i(J)I

    .line 1043
    .line 1044
    .line 1045
    move-result v5

    .line 1046
    move-object/from16 v31, v3

    .line 1047
    .line 1048
    invoke-static/range {v50 .. v51}, Lt4/a;->h(J)I

    .line 1049
    .line 1050
    .line 1051
    move-result v3

    .line 1052
    move/from16 v30, v0

    .line 1053
    .line 1054
    move/from16 v21, v4

    .line 1055
    .line 1056
    move/from16 v18, v6

    .line 1057
    .line 1058
    move-object/from16 v0, p0

    .line 1059
    .line 1060
    move-object/from16 v6, p1

    .line 1061
    .line 1062
    move v4, v2

    .line 1063
    move v2, v5

    .line 1064
    move/from16 v5, v28

    .line 1065
    .line 1066
    invoke-static/range {v0 .. v12}, Lk1/d;->l(Lk1/c1;IIIIILt3/s0;Ljava/util/List;[Lt3/e1;II[II)Lt3/r0;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v2

    .line 1070
    invoke-interface {v2}, Lt3/r0;->o()I

    .line 1071
    .line 1072
    .line 1073
    move-result v3

    .line 1074
    invoke-interface {v2}, Lt3/r0;->m()I

    .line 1075
    .line 1076
    .line 1077
    move-result v4

    .line 1078
    aput v4, v13, v12

    .line 1079
    .line 1080
    add-int v17, v17, v4

    .line 1081
    .line 1082
    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    .line 1083
    .line 1084
    .line 1085
    move-result v1

    .line 1086
    move-object/from16 v3, p3

    .line 1087
    .line 1088
    invoke-virtual {v3, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1089
    .line 1090
    .line 1091
    add-int/lit8 v12, v12, 0x1

    .line 1092
    .line 1093
    move v9, v10

    .line 1094
    move/from16 v6, v18

    .line 1095
    .line 1096
    goto :goto_19

    .line 1097
    :cond_1f
    const-string v0, "Index must be between 0 and size"

    .line 1098
    .line 1099
    invoke-static {v0}, La1/a;->d(Ljava/lang/String;)V

    .line 1100
    .line 1101
    .line 1102
    throw v16

    .line 1103
    :cond_20
    move-object/from16 v0, p0

    .line 1104
    .line 1105
    move-object/from16 v6, p1

    .line 1106
    .line 1107
    move-object/from16 v3, p3

    .line 1108
    .line 1109
    iget v2, v3, Ln2/b;->f:I

    .line 1110
    .line 1111
    if-nez v2, :cond_21

    .line 1112
    .line 1113
    const/4 v14, 0x0

    .line 1114
    const/16 v17, 0x0

    .line 1115
    .line 1116
    goto :goto_1b

    .line 1117
    :cond_21
    move v14, v1

    .line 1118
    :goto_1b
    iget-object v0, v0, Lk1/i0;->b:Lk1/i;

    .line 1119
    .line 1120
    invoke-interface {v0}, Lk1/i;->a()F

    .line 1121
    .line 1122
    .line 1123
    move-result v1

    .line 1124
    invoke-interface {v6, v1}, Lt4/c;->Q(F)I

    .line 1125
    .line 1126
    .line 1127
    move-result v1

    .line 1128
    iget v2, v3, Ln2/b;->f:I

    .line 1129
    .line 1130
    add-int/lit8 v2, v2, -0x1

    .line 1131
    .line 1132
    mul-int/2addr v2, v1

    .line 1133
    add-int v2, v2, v17

    .line 1134
    .line 1135
    invoke-static/range {v23 .. v24}, Lt4/a;->i(J)I

    .line 1136
    .line 1137
    .line 1138
    move-result v1

    .line 1139
    invoke-static/range {v23 .. v24}, Lt4/a;->g(J)I

    .line 1140
    .line 1141
    .line 1142
    move-result v4

    .line 1143
    if-ge v2, v1, :cond_22

    .line 1144
    .line 1145
    move v2, v1

    .line 1146
    :cond_22
    if-le v2, v4, :cond_23

    .line 1147
    .line 1148
    goto :goto_1c

    .line 1149
    :cond_23
    move v4, v2

    .line 1150
    :goto_1c
    invoke-interface {v0, v6, v4, v13, v11}, Lk1/i;->b(Lt4/c;I[I[I)V

    .line 1151
    .line 1152
    .line 1153
    invoke-static/range {v23 .. v24}, Lt4/a;->j(J)I

    .line 1154
    .line 1155
    .line 1156
    move-result v0

    .line 1157
    invoke-static/range {v23 .. v24}, Lt4/a;->h(J)I

    .line 1158
    .line 1159
    .line 1160
    move-result v1

    .line 1161
    if-ge v14, v0, :cond_24

    .line 1162
    .line 1163
    move v14, v0

    .line 1164
    :cond_24
    if-le v14, v1, :cond_25

    .line 1165
    .line 1166
    goto :goto_1d

    .line 1167
    :cond_25
    move v1, v14

    .line 1168
    :goto_1d
    new-instance v0, Li40/e1;

    .line 1169
    .line 1170
    const/16 v2, 0xf

    .line 1171
    .line 1172
    invoke-direct {v0, v3, v2}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 1173
    .line 1174
    .line 1175
    move-object/from16 v15, v20

    .line 1176
    .line 1177
    invoke-interface {v6, v1, v4, v15, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 1178
    .line 1179
    .line 1180
    move-result-object v0

    .line 1181
    return-object v0

    .line 1182
    :goto_1e
    new-instance v0, Ldj/a;

    .line 1183
    .line 1184
    invoke-direct {v0, v5}, Ldj/a;-><init>(I)V

    .line 1185
    .line 1186
    .line 1187
    const/4 v12, 0x0

    .line 1188
    invoke-interface {v6, v12, v12, v15, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v0

    .line 1192
    return-object v0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    check-cast v0, Ljava/util/List;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lt3/p0;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object v0, v1

    .line 19
    :goto_0
    const/4 v2, 0x2

    .line 20
    invoke-static {v2, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/util/List;

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lt3/p0;

    .line 33
    .line 34
    :cond_1
    const/4 v2, 0x0

    .line 35
    const/16 v3, 0xd

    .line 36
    .line 37
    invoke-static {p3, v2, v3}, Lt4/b;->b(III)J

    .line 38
    .line 39
    .line 40
    move-result-wide v2

    .line 41
    iget-object v4, p0, Lk1/i0;->g:Lk1/g0;

    .line 42
    .line 43
    invoke-virtual {v4, v0, v1, v2, v3}, Lk1/g0;->a(Lt3/p0;Lt3/p0;J)V

    .line 44
    .line 45
    .line 46
    invoke-static {p2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    check-cast p2, Ljava/util/List;

    .line 51
    .line 52
    if-nez p2, :cond_2

    .line 53
    .line 54
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 55
    .line 56
    :cond_2
    move-object v0, p2

    .line 57
    iget p2, p0, Lk1/i0;->c:F

    .line 58
    .line 59
    invoke-interface {p1, p2}, Lt4/c;->Q(F)I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    iget p2, p0, Lk1/i0;->e:F

    .line 64
    .line 65
    invoke-interface {p1, p2}, Lt4/c;->Q(F)I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    iget v4, p0, Lk1/i0;->f:I

    .line 70
    .line 71
    iget-object v5, p0, Lk1/i0;->g:Lk1/g0;

    .line 72
    .line 73
    move v1, p3

    .line 74
    invoke-static/range {v0 .. v5}, Lk1/i0;->g(Ljava/util/List;IIIILk1/g0;)I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    check-cast v0, Ljava/util/List;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lt3/p0;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object v0, v1

    .line 19
    :goto_0
    const/4 v2, 0x2

    .line 20
    invoke-static {v2, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/util/List;

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lt3/p0;

    .line 33
    .line 34
    :cond_1
    const/4 v2, 0x0

    .line 35
    const/16 v3, 0xd

    .line 36
    .line 37
    invoke-static {p3, v2, v3}, Lt4/b;->b(III)J

    .line 38
    .line 39
    .line 40
    move-result-wide v2

    .line 41
    iget-object v4, p0, Lk1/i0;->g:Lk1/g0;

    .line 42
    .line 43
    invoke-virtual {v4, v0, v1, v2, v3}, Lk1/g0;->a(Lt3/p0;Lt3/p0;J)V

    .line 44
    .line 45
    .line 46
    invoke-static {p2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    check-cast p2, Ljava/util/List;

    .line 51
    .line 52
    if-nez p2, :cond_2

    .line 53
    .line 54
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 55
    .line 56
    :cond_2
    move-object v0, p2

    .line 57
    iget p2, p0, Lk1/i0;->c:F

    .line 58
    .line 59
    invoke-interface {p1, p2}, Lt4/c;->Q(F)I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    iget p2, p0, Lk1/i0;->e:F

    .line 64
    .line 65
    invoke-interface {p1, p2}, Lt4/c;->Q(F)I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    iget v4, p0, Lk1/i0;->f:I

    .line 70
    .line 71
    iget-object v5, p0, Lk1/i0;->g:Lk1/g0;

    .line 72
    .line 73
    move v1, p3

    .line 74
    invoke-static/range {v0 .. v5}, Lk1/i0;->g(Ljava/util/List;IIIILk1/g0;)I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    check-cast v0, Ljava/util/List;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lt3/p0;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object v0, v1

    .line 19
    :goto_0
    const/4 v2, 0x2

    .line 20
    invoke-static {v2, p2}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ljava/util/List;

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lt3/p0;

    .line 33
    .line 34
    :cond_1
    const/4 v2, 0x7

    .line 35
    const/4 v3, 0x0

    .line 36
    invoke-static {v3, p3, v2}, Lt4/b;->b(III)J

    .line 37
    .line 38
    .line 39
    move-result-wide v4

    .line 40
    iget-object v2, p0, Lk1/i0;->g:Lk1/g0;

    .line 41
    .line 42
    invoke-virtual {v2, v0, v1, v4, v5}, Lk1/g0;->a(Lt3/p0;Lt3/p0;J)V

    .line 43
    .line 44
    .line 45
    invoke-static {p2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    check-cast p2, Ljava/util/List;

    .line 50
    .line 51
    if-nez p2, :cond_2

    .line 52
    .line 53
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 54
    .line 55
    :cond_2
    iget v0, p0, Lk1/i0;->c:F

    .line 56
    .line 57
    invoke-interface {p1, v0}, Lt4/c;->Q(F)I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    move-object v0, p2

    .line 62
    check-cast v0, Ljava/util/Collection;

    .line 63
    .line 64
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    move v1, v3

    .line 69
    move v2, v1

    .line 70
    move v4, v2

    .line 71
    move v5, v4

    .line 72
    :goto_1
    if-ge v1, v0, :cond_5

    .line 73
    .line 74
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v6

    .line 78
    check-cast v6, Lt3/p0;

    .line 79
    .line 80
    invoke-interface {v6, p3}, Lt3/p0;->J(I)I

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    add-int/2addr v6, p1

    .line 85
    add-int/lit8 v7, v1, 0x1

    .line 86
    .line 87
    sub-int v8, v7, v4

    .line 88
    .line 89
    iget v9, p0, Lk1/i0;->f:I

    .line 90
    .line 91
    if-eq v8, v9, :cond_4

    .line 92
    .line 93
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    if-ne v7, v8, :cond_3

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_3
    add-int/2addr v5, v6

    .line 101
    goto :goto_3

    .line 102
    :cond_4
    :goto_2
    add-int/2addr v5, v6

    .line 103
    sub-int/2addr v5, p1

    .line 104
    invoke-static {v2, v5}, Ljava/lang/Math;->max(II)I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    move v4, v1

    .line 109
    move v5, v3

    .line 110
    :goto_3
    move v1, v7

    .line 111
    goto :goto_1

    .line 112
    :cond_5
    return v2
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lk1/i0;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lk1/i0;

    .line 10
    .line 11
    iget-object v0, p0, Lk1/i0;->a:Lk1/g;

    .line 12
    .line 13
    iget-object v1, p1, Lk1/i0;->a:Lk1/g;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-object v0, p0, Lk1/i0;->b:Lk1/i;

    .line 23
    .line 24
    iget-object v1, p1, Lk1/i0;->b:Lk1/i;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    iget v0, p0, Lk1/i0;->c:F

    .line 34
    .line 35
    iget v1, p1, Lk1/i0;->c:F

    .line 36
    .line 37
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_4

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    iget-object v0, p0, Lk1/i0;->d:Lk1/x;

    .line 45
    .line 46
    iget-object v1, p1, Lk1/i0;->d:Lk1/x;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Lk1/x;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_5

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    iget v0, p0, Lk1/i0;->e:F

    .line 56
    .line 57
    iget v1, p1, Lk1/i0;->e:F

    .line 58
    .line 59
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-nez v0, :cond_6

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_6
    iget v0, p0, Lk1/i0;->f:I

    .line 67
    .line 68
    iget v1, p1, Lk1/i0;->f:I

    .line 69
    .line 70
    if-eq v0, v1, :cond_7

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_7
    iget-object p0, p0, Lk1/i0;->g:Lk1/g0;

    .line 74
    .line 75
    iget-object p1, p1, Lk1/i0;->g:Lk1/g0;

    .line 76
    .line 77
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-nez p0, :cond_8

    .line 82
    .line 83
    :goto_0
    const/4 p0, 0x0

    .line 84
    return p0

    .line 85
    :cond_8
    :goto_1
    const/4 p0, 0x1

    .line 86
    return p0
.end method

.method public final f(Lt3/e1;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Lt3/e1;->b0()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    const/16 v1, 0x1f

    .line 7
    .line 8
    mul-int/2addr v0, v1

    .line 9
    iget-object v2, p0, Lk1/i0;->a:Lk1/g;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    add-int/2addr v2, v0

    .line 16
    mul-int/2addr v2, v1

    .line 17
    iget-object v0, p0, Lk1/i0;->b:Lk1/i;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    add-int/2addr v0, v2

    .line 24
    mul-int/2addr v0, v1

    .line 25
    iget v2, p0, Lk1/i0;->c:F

    .line 26
    .line 27
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    iget-object v2, p0, Lk1/i0;->d:Lk1/x;

    .line 32
    .line 33
    invoke-virtual {v2}, Lk1/x;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    add-int/2addr v2, v0

    .line 38
    mul-int/2addr v2, v1

    .line 39
    iget v0, p0, Lk1/i0;->e:F

    .line 40
    .line 41
    invoke-static {v0, v2, v1}, La7/g0;->c(FII)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    iget v2, p0, Lk1/i0;->f:I

    .line 46
    .line 47
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    const v2, 0x7fffffff

    .line 52
    .line 53
    .line 54
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object p0, p0, Lk1/i0;->g:Lk1/g0;

    .line 59
    .line 60
    invoke-virtual {p0}, Lk1/g0;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    add-int/2addr p0, v0

    .line 65
    return p0
.end method

.method public final i(I[I[ILt3/s0;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lk1/i0;->a:Lk1/g;

    .line 2
    .line 3
    invoke-interface {p4}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 4
    .line 5
    .line 6
    move-result-object v4

    .line 7
    move v2, p1

    .line 8
    move-object v3, p2

    .line 9
    move-object v5, p3

    .line 10
    move-object v1, p4

    .line 11
    invoke-interface/range {v0 .. v5}, Lk1/g;->c(Lt4/c;I[ILt4/m;[I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final k([Lt3/e1;Lt3/s0;I[III[IIII)Lt3/r0;
    .locals 11

    .line 1
    sget-object v8, Lt4/m;->d:Lt4/m;

    .line 2
    .line 3
    new-instance v0, Lk1/h0;

    .line 4
    .line 5
    move-object v6, p0

    .line 6
    move-object v5, p1

    .line 7
    move v9, p3

    .line 8
    move-object v10, p4

    .line 9
    move/from16 v7, p6

    .line 10
    .line 11
    move-object/from16 v1, p7

    .line 12
    .line 13
    move/from16 v2, p8

    .line 14
    .line 15
    move/from16 v3, p9

    .line 16
    .line 17
    move/from16 v4, p10

    .line 18
    .line 19
    invoke-direct/range {v0 .. v10}, Lk1/h0;-><init>([IIII[Lt3/e1;Lk1/i0;ILt4/m;I[I)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 23
    .line 24
    move/from16 p1, p5

    .line 25
    .line 26
    invoke-interface {p2, p1, v7, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final l(IIIZ)J
    .locals 0

    .line 1
    sget-object p0, Lk1/e1;->a:Lk1/g1;

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    if-nez p4, :cond_0

    .line 5
    .line 6
    invoke-static {p1, p2, p0, p3}, Lt4/b;->a(IIII)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :cond_0
    invoke-static {p1, p2, p0, p3}, Lkp/a9;->b(IIII)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0
.end method

.method public final m(Lt3/e1;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Lt3/e1;->d0()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "FlowMeasurePolicy(isHorizontal=true, horizontalArrangement="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lk1/i0;->a:Lk1/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", verticalArrangement="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lk1/i0;->b:Lk1/i;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", mainAxisSpacing="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lk1/i0;->c:F

    .line 29
    .line 30
    const-string v2, ", crossAxisAlignment="

    .line 31
    .line 32
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->t(FLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lk1/i0;->d:Lk1/x;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", crossAxisArrangementSpacing="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget v1, p0, Lk1/i0;->e:F

    .line 46
    .line 47
    const-string v2, ", maxItemsInMainAxis="

    .line 48
    .line 49
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->t(FLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 50
    .line 51
    .line 52
    iget v1, p0, Lk1/i0;->f:I

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v1, ", maxLines=2147483647, overflow="

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget-object p0, p0, Lk1/i0;->g:Lk1/g0;

    .line 63
    .line 64
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const/16 p0, 0x29

    .line 68
    .line 69
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
