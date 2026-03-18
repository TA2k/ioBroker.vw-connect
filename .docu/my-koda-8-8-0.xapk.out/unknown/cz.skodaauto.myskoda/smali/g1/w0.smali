.class public abstract Lg1/w0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-wide/high16 v0, 0x3fc0000000000000L    # 0.125

    .line 2
    .line 3
    double-to-float v0, v0

    .line 4
    const/16 v1, 0x12

    .line 5
    .line 6
    int-to-float v1, v1

    .line 7
    div-float/2addr v0, v1

    .line 8
    sput v0, Lg1/w0;->a:F

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lp3/i0;JLrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-wide/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v2, p3

    .line 4
    .line 5
    instance-of v3, v2, Lg1/l0;

    .line 6
    .line 7
    if-eqz v3, :cond_0

    .line 8
    .line 9
    move-object v3, v2

    .line 10
    check-cast v3, Lg1/l0;

    .line 11
    .line 12
    iget v4, v3, Lg1/l0;->g:I

    .line 13
    .line 14
    const/high16 v5, -0x80000000

    .line 15
    .line 16
    and-int v6, v4, v5

    .line 17
    .line 18
    if-eqz v6, :cond_0

    .line 19
    .line 20
    sub-int/2addr v4, v5

    .line 21
    iput v4, v3, Lg1/l0;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v3, Lg1/l0;

    .line 25
    .line 26
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v2, v3, Lg1/l0;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v5, v3, Lg1/l0;->g:I

    .line 34
    .line 35
    const/4 v6, 0x1

    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v5, :cond_2

    .line 38
    .line 39
    if-ne v5, v6, :cond_1

    .line 40
    .line 41
    iget-object v0, v3, Lg1/l0;->e:Lkotlin/jvm/internal/e0;

    .line 42
    .line 43
    iget-object v1, v3, Lg1/l0;->d:Lp3/i0;

    .line 44
    .line 45
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v0

    .line 57
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object/from16 v2, p0

    .line 61
    .line 62
    iget-object v5, v2, Lp3/i0;->i:Lp3/j0;

    .line 63
    .line 64
    iget-object v5, v5, Lp3/j0;->w:Lp3/k;

    .line 65
    .line 66
    invoke-static {v5, v0, v1}, Lg1/w0;->g(Lp3/k;J)Z

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    if-eqz v5, :cond_3

    .line 71
    .line 72
    goto/16 :goto_8

    .line 73
    .line 74
    :cond_3
    new-instance v5, Lkotlin/jvm/internal/e0;

    .line 75
    .line 76
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 77
    .line 78
    .line 79
    iput-wide v0, v5, Lkotlin/jvm/internal/e0;->d:J

    .line 80
    .line 81
    move-object v0, v5

    .line 82
    :goto_1
    iput-object v2, v3, Lg1/l0;->d:Lp3/i0;

    .line 83
    .line 84
    iput-object v0, v3, Lg1/l0;->e:Lkotlin/jvm/internal/e0;

    .line 85
    .line 86
    iput v6, v3, Lg1/l0;->g:I

    .line 87
    .line 88
    sget-object v1, Lp3/l;->e:Lp3/l;

    .line 89
    .line 90
    invoke-virtual {v2, v1, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    if-ne v1, v4, :cond_4

    .line 95
    .line 96
    return-object v4

    .line 97
    :cond_4
    move-object/from16 v16, v2

    .line 98
    .line 99
    move-object v2, v1

    .line 100
    move-object/from16 v1, v16

    .line 101
    .line 102
    :goto_2
    check-cast v2, Lp3/k;

    .line 103
    .line 104
    iget-object v5, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 105
    .line 106
    move-object v8, v5

    .line 107
    check-cast v8, Ljava/util/Collection;

    .line 108
    .line 109
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    const/4 v9, 0x0

    .line 114
    move v10, v9

    .line 115
    :goto_3
    if-ge v10, v8, :cond_6

    .line 116
    .line 117
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v11

    .line 121
    move-object v12, v11

    .line 122
    check-cast v12, Lp3/t;

    .line 123
    .line 124
    iget-wide v12, v12, Lp3/t;->a:J

    .line 125
    .line 126
    iget-wide v14, v0, Lkotlin/jvm/internal/e0;->d:J

    .line 127
    .line 128
    invoke-static {v12, v13, v14, v15}, Lp3/s;->e(JJ)Z

    .line 129
    .line 130
    .line 131
    move-result v12

    .line 132
    if-eqz v12, :cond_5

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_5
    add-int/lit8 v10, v10, 0x1

    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_6
    move-object v11, v7

    .line 139
    :goto_4
    check-cast v11, Lp3/t;

    .line 140
    .line 141
    if-nez v11, :cond_7

    .line 142
    .line 143
    move-object v11, v7

    .line 144
    goto :goto_7

    .line 145
    :cond_7
    invoke-static {v11}, Lp3/s;->d(Lp3/t;)Z

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    if-eqz v5, :cond_b

    .line 150
    .line 151
    iget-object v2, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 152
    .line 153
    move-object v5, v2

    .line 154
    check-cast v5, Ljava/util/Collection;

    .line 155
    .line 156
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 157
    .line 158
    .line 159
    move-result v5

    .line 160
    :goto_5
    if-ge v9, v5, :cond_9

    .line 161
    .line 162
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v8

    .line 166
    move-object v10, v8

    .line 167
    check-cast v10, Lp3/t;

    .line 168
    .line 169
    iget-boolean v10, v10, Lp3/t;->d:Z

    .line 170
    .line 171
    if-eqz v10, :cond_8

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_8
    add-int/lit8 v9, v9, 0x1

    .line 175
    .line 176
    goto :goto_5

    .line 177
    :cond_9
    move-object v8, v7

    .line 178
    :goto_6
    check-cast v8, Lp3/t;

    .line 179
    .line 180
    if-nez v8, :cond_a

    .line 181
    .line 182
    goto :goto_7

    .line 183
    :cond_a
    iget-wide v8, v8, Lp3/t;->a:J

    .line 184
    .line 185
    iput-wide v8, v0, Lkotlin/jvm/internal/e0;->d:J

    .line 186
    .line 187
    goto :goto_9

    .line 188
    :cond_b
    invoke-static {v11, v6}, Lp3/s;->h(Lp3/t;Z)J

    .line 189
    .line 190
    .line 191
    move-result-wide v8

    .line 192
    const-wide/16 v12, 0x0

    .line 193
    .line 194
    invoke-static {v8, v9, v12, v13}, Ld3/b;->c(JJ)Z

    .line 195
    .line 196
    .line 197
    move-result v2

    .line 198
    if-nez v2, :cond_d

    .line 199
    .line 200
    :goto_7
    if-eqz v11, :cond_c

    .line 201
    .line 202
    invoke-virtual {v11}, Lp3/t;->b()Z

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    if-nez v0, :cond_c

    .line 207
    .line 208
    return-object v11

    .line 209
    :cond_c
    :goto_8
    return-object v7

    .line 210
    :cond_d
    :goto_9
    move-object v2, v1

    .line 211
    goto/16 :goto_1
.end method

.method public static final b(Lp3/i0;JILg1/r0;Lrx0/a;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-wide/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v2, p5

    .line 4
    .line 5
    instance-of v3, v2, Lg1/m0;

    .line 6
    .line 7
    if-eqz v3, :cond_0

    .line 8
    .line 9
    move-object v3, v2

    .line 10
    check-cast v3, Lg1/m0;

    .line 11
    .line 12
    iget v4, v3, Lg1/m0;->k:I

    .line 13
    .line 14
    const/high16 v5, -0x80000000

    .line 15
    .line 16
    and-int v6, v4, v5

    .line 17
    .line 18
    if-eqz v6, :cond_0

    .line 19
    .line 20
    sub-int/2addr v4, v5

    .line 21
    iput v4, v3, Lg1/m0;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v3, Lg1/m0;

    .line 25
    .line 26
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v2, v3, Lg1/m0;->j:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v5, v3, Lg1/m0;->k:I

    .line 34
    .line 35
    const-wide/16 v6, 0x0

    .line 36
    .line 37
    const/4 v8, 0x2

    .line 38
    const/4 v9, 0x1

    .line 39
    const/4 v10, 0x0

    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    if-eq v5, v9, :cond_2

    .line 43
    .line 44
    if-ne v5, v8, :cond_1

    .line 45
    .line 46
    iget v0, v3, Lg1/m0;->i:F

    .line 47
    .line 48
    iget-object v1, v3, Lg1/m0;->h:Lp3/t;

    .line 49
    .line 50
    iget-object v5, v3, Lg1/m0;->g:Lg1/i3;

    .line 51
    .line 52
    iget-object v11, v3, Lg1/m0;->f:Lkotlin/jvm/internal/e0;

    .line 53
    .line 54
    iget-object v12, v3, Lg1/m0;->e:Lp3/i0;

    .line 55
    .line 56
    iget-object v13, v3, Lg1/m0;->d:Lay0/n;

    .line 57
    .line 58
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    move v9, v8

    .line 62
    move-object/from16 v17, v10

    .line 63
    .line 64
    move-object v2, v11

    .line 65
    move v11, v0

    .line 66
    move-wide v7, v6

    .line 67
    move-object v0, v13

    .line 68
    goto/16 :goto_9

    .line 69
    .line 70
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 73
    .line 74
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0

    .line 78
    :cond_2
    iget v0, v3, Lg1/m0;->i:F

    .line 79
    .line 80
    iget-object v1, v3, Lg1/m0;->g:Lg1/i3;

    .line 81
    .line 82
    iget-object v5, v3, Lg1/m0;->f:Lkotlin/jvm/internal/e0;

    .line 83
    .line 84
    iget-object v11, v3, Lg1/m0;->e:Lp3/i0;

    .line 85
    .line 86
    iget-object v12, v3, Lg1/m0;->d:Lay0/n;

    .line 87
    .line 88
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object/from16 v18, v11

    .line 92
    .line 93
    move v11, v0

    .line 94
    move-object v0, v12

    .line 95
    move-object v12, v5

    .line 96
    move-object/from16 v5, v18

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    sget-object v2, Lg1/w1;->e:Lg1/w1;

    .line 103
    .line 104
    move-object/from16 v5, p0

    .line 105
    .line 106
    iget-object v11, v5, Lp3/i0;->i:Lp3/j0;

    .line 107
    .line 108
    iget-object v11, v11, Lp3/j0;->w:Lp3/k;

    .line 109
    .line 110
    invoke-static {v11, v0, v1}, Lg1/w0;->g(Lp3/k;J)Z

    .line 111
    .line 112
    .line 113
    move-result v11

    .line 114
    if-eqz v11, :cond_4

    .line 115
    .line 116
    move-object/from16 v17, v10

    .line 117
    .line 118
    goto/16 :goto_a

    .line 119
    .line 120
    :cond_4
    invoke-virtual {v5}, Lp3/i0;->f()Lw3/h2;

    .line 121
    .line 122
    .line 123
    move-result-object v11

    .line 124
    move/from16 v12, p3

    .line 125
    .line 126
    invoke-static {v11, v12}, Lg1/w0;->h(Lw3/h2;I)F

    .line 127
    .line 128
    .line 129
    move-result v11

    .line 130
    new-instance v12, Lkotlin/jvm/internal/e0;

    .line 131
    .line 132
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 133
    .line 134
    .line 135
    iput-wide v0, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 136
    .line 137
    new-instance v0, Lg1/i3;

    .line 138
    .line 139
    const/4 v1, 0x0

    .line 140
    invoke-direct {v0, v2, v6, v7, v1}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 141
    .line 142
    .line 143
    move-object v1, v0

    .line 144
    move-object/from16 v0, p4

    .line 145
    .line 146
    :goto_1
    iput-object v0, v3, Lg1/m0;->d:Lay0/n;

    .line 147
    .line 148
    iput-object v5, v3, Lg1/m0;->e:Lp3/i0;

    .line 149
    .line 150
    iput-object v12, v3, Lg1/m0;->f:Lkotlin/jvm/internal/e0;

    .line 151
    .line 152
    iput-object v1, v3, Lg1/m0;->g:Lg1/i3;

    .line 153
    .line 154
    iput-object v10, v3, Lg1/m0;->h:Lp3/t;

    .line 155
    .line 156
    iput v11, v3, Lg1/m0;->i:F

    .line 157
    .line 158
    iput v9, v3, Lg1/m0;->k:I

    .line 159
    .line 160
    sget-object v2, Lp3/l;->e:Lp3/l;

    .line 161
    .line 162
    invoke-virtual {v5, v2, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    if-ne v2, v4, :cond_5

    .line 167
    .line 168
    goto/16 :goto_8

    .line 169
    .line 170
    :cond_5
    :goto_2
    check-cast v2, Lp3/k;

    .line 171
    .line 172
    iget-object v13, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 173
    .line 174
    move-object v14, v13

    .line 175
    check-cast v14, Ljava/util/Collection;

    .line 176
    .line 177
    invoke-interface {v14}, Ljava/util/Collection;->size()I

    .line 178
    .line 179
    .line 180
    move-result v14

    .line 181
    const/4 v15, 0x0

    .line 182
    move v9, v15

    .line 183
    :goto_3
    if-ge v9, v14, :cond_7

    .line 184
    .line 185
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v16

    .line 189
    move-object/from16 v17, v10

    .line 190
    .line 191
    move-object/from16 v10, v16

    .line 192
    .line 193
    check-cast v10, Lp3/t;

    .line 194
    .line 195
    move/from16 p0, v9

    .line 196
    .line 197
    iget-wide v8, v10, Lp3/t;->a:J

    .line 198
    .line 199
    iget-wide v6, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 200
    .line 201
    invoke-static {v8, v9, v6, v7}, Lp3/s;->e(JJ)Z

    .line 202
    .line 203
    .line 204
    move-result v6

    .line 205
    if-eqz v6, :cond_6

    .line 206
    .line 207
    goto :goto_4

    .line 208
    :cond_6
    add-int/lit8 v9, p0, 0x1

    .line 209
    .line 210
    move-object/from16 v10, v17

    .line 211
    .line 212
    const-wide/16 v6, 0x0

    .line 213
    .line 214
    const/4 v8, 0x2

    .line 215
    goto :goto_3

    .line 216
    :cond_7
    move-object/from16 v17, v10

    .line 217
    .line 218
    move-object/from16 v16, v17

    .line 219
    .line 220
    :goto_4
    move-object/from16 v6, v16

    .line 221
    .line 222
    check-cast v6, Lp3/t;

    .line 223
    .line 224
    if-nez v6, :cond_8

    .line 225
    .line 226
    goto/16 :goto_a

    .line 227
    .line 228
    :cond_8
    invoke-virtual {v6}, Lp3/t;->b()Z

    .line 229
    .line 230
    .line 231
    move-result v7

    .line 232
    if-eqz v7, :cond_9

    .line 233
    .line 234
    goto/16 :goto_a

    .line 235
    .line 236
    :cond_9
    invoke-static {v6}, Lp3/s;->d(Lp3/t;)Z

    .line 237
    .line 238
    .line 239
    move-result v7

    .line 240
    if-eqz v7, :cond_d

    .line 241
    .line 242
    iget-object v2, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 243
    .line 244
    move-object v6, v2

    .line 245
    check-cast v6, Ljava/util/Collection;

    .line 246
    .line 247
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 248
    .line 249
    .line 250
    move-result v6

    .line 251
    :goto_5
    if-ge v15, v6, :cond_b

    .line 252
    .line 253
    invoke-interface {v2, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v7

    .line 257
    move-object v8, v7

    .line 258
    check-cast v8, Lp3/t;

    .line 259
    .line 260
    iget-boolean v8, v8, Lp3/t;->d:Z

    .line 261
    .line 262
    if-eqz v8, :cond_a

    .line 263
    .line 264
    goto :goto_6

    .line 265
    :cond_a
    add-int/lit8 v15, v15, 0x1

    .line 266
    .line 267
    goto :goto_5

    .line 268
    :cond_b
    move-object/from16 v7, v17

    .line 269
    .line 270
    :goto_6
    check-cast v7, Lp3/t;

    .line 271
    .line 272
    if-nez v7, :cond_c

    .line 273
    .line 274
    goto :goto_a

    .line 275
    :cond_c
    iget-wide v6, v7, Lp3/t;->a:J

    .line 276
    .line 277
    iput-wide v6, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 278
    .line 279
    const-wide/16 v7, 0x0

    .line 280
    .line 281
    goto :goto_7

    .line 282
    :cond_d
    invoke-virtual {v1, v6, v11}, Lg1/i3;->p(Lp3/t;F)J

    .line 283
    .line 284
    .line 285
    move-result-wide v7

    .line 286
    const-wide v9, 0x7fffffff7fffffffL

    .line 287
    .line 288
    .line 289
    .line 290
    .line 291
    and-long/2addr v9, v7

    .line 292
    const-wide v13, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 293
    .line 294
    .line 295
    .line 296
    .line 297
    cmp-long v2, v9, v13

    .line 298
    .line 299
    if-eqz v2, :cond_f

    .line 300
    .line 301
    const/16 v2, 0x20

    .line 302
    .line 303
    shr-long/2addr v7, v2

    .line 304
    long-to-int v2, v7

    .line 305
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 306
    .line 307
    .line 308
    move-result v2

    .line 309
    new-instance v7, Ljava/lang/Float;

    .line 310
    .line 311
    invoke-direct {v7, v2}, Ljava/lang/Float;-><init>(F)V

    .line 312
    .line 313
    .line 314
    invoke-interface {v0, v6, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    invoke-virtual {v6}, Lp3/t;->b()Z

    .line 318
    .line 319
    .line 320
    move-result v2

    .line 321
    if-eqz v2, :cond_e

    .line 322
    .line 323
    return-object v6

    .line 324
    :cond_e
    const-wide/16 v7, 0x0

    .line 325
    .line 326
    iput-wide v7, v1, Lg1/i3;->e:J

    .line 327
    .line 328
    :goto_7
    move-wide v6, v7

    .line 329
    move-object/from16 v10, v17

    .line 330
    .line 331
    const/4 v8, 0x2

    .line 332
    const/4 v9, 0x1

    .line 333
    goto/16 :goto_1

    .line 334
    .line 335
    :cond_f
    const-wide/16 v7, 0x0

    .line 336
    .line 337
    sget-object v2, Lp3/l;->f:Lp3/l;

    .line 338
    .line 339
    iput-object v0, v3, Lg1/m0;->d:Lay0/n;

    .line 340
    .line 341
    iput-object v5, v3, Lg1/m0;->e:Lp3/i0;

    .line 342
    .line 343
    iput-object v12, v3, Lg1/m0;->f:Lkotlin/jvm/internal/e0;

    .line 344
    .line 345
    iput-object v1, v3, Lg1/m0;->g:Lg1/i3;

    .line 346
    .line 347
    iput-object v6, v3, Lg1/m0;->h:Lp3/t;

    .line 348
    .line 349
    iput v11, v3, Lg1/m0;->i:F

    .line 350
    .line 351
    const/4 v9, 0x2

    .line 352
    iput v9, v3, Lg1/m0;->k:I

    .line 353
    .line 354
    invoke-virtual {v5, v2, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    if-ne v2, v4, :cond_10

    .line 359
    .line 360
    :goto_8
    return-object v4

    .line 361
    :cond_10
    move-object v2, v12

    .line 362
    move-object v12, v5

    .line 363
    move-object v5, v1

    .line 364
    move-object v1, v6

    .line 365
    :goto_9
    invoke-virtual {v1}, Lp3/t;->b()Z

    .line 366
    .line 367
    .line 368
    move-result v1

    .line 369
    if-eqz v1, :cond_11

    .line 370
    .line 371
    :goto_a
    return-object v17

    .line 372
    :cond_11
    move-object v1, v5

    .line 373
    move-wide v6, v7

    .line 374
    move v8, v9

    .line 375
    move-object v5, v12

    .line 376
    move-object/from16 v10, v17

    .line 377
    .line 378
    const/4 v9, 0x1

    .line 379
    move-object v12, v2

    .line 380
    goto/16 :goto_1
.end method

.method public static final c(Lp3/i0;JLrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p3, Lg1/n0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg1/n0;

    .line 7
    .line 8
    iget v1, v0, Lg1/n0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lg1/n0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/n0;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg1/n0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/n0;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-object p0, v0, Lg1/n0;->f:Lkotlin/jvm/internal/b0;

    .line 38
    .line 39
    iget-object p1, v0, Lg1/n0;->e:Lkotlin/jvm/internal/f0;

    .line 40
    .line 41
    iget-object p2, v0, Lg1/n0;->d:Lp3/t;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lp3/n; {:try_start_0 .. :try_end_0} :catch_0

    .line 44
    .line 45
    .line 46
    goto/16 :goto_3

    .line 47
    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p3, p0, Lp3/i0;->i:Lp3/j0;

    .line 60
    .line 61
    iget-object p3, p3, Lp3/j0;->w:Lp3/k;

    .line 62
    .line 63
    invoke-static {p3, p1, p2}, Lg1/w0;->g(Lp3/k;J)Z

    .line 64
    .line 65
    .line 66
    move-result p3

    .line 67
    if-eqz p3, :cond_3

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_3
    iget-object p3, p0, Lp3/i0;->i:Lp3/j0;

    .line 71
    .line 72
    iget-object p3, p3, Lp3/j0;->w:Lp3/k;

    .line 73
    .line 74
    iget-object p3, p3, Lp3/k;->a:Ljava/lang/Object;

    .line 75
    .line 76
    move-object v2, p3

    .line 77
    check-cast v2, Ljava/util/Collection;

    .line 78
    .line 79
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    const/4 v5, 0x0

    .line 84
    :goto_1
    if-ge v5, v2, :cond_5

    .line 85
    .line 86
    invoke-interface {p3, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    move-object v7, v6

    .line 91
    check-cast v7, Lp3/t;

    .line 92
    .line 93
    iget-wide v7, v7, Lp3/t;->a:J

    .line 94
    .line 95
    invoke-static {v7, v8, p1, p2}, Lp3/s;->e(JJ)Z

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    if-eqz v7, :cond_4

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_4
    add-int/lit8 v5, v5, 0x1

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_5
    move-object v6, v4

    .line 106
    :goto_2
    move-object p2, v6

    .line 107
    check-cast p2, Lp3/t;

    .line 108
    .line 109
    if-nez p2, :cond_6

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_6
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 113
    .line 114
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 115
    .line 116
    .line 117
    new-instance p3, Lkotlin/jvm/internal/f0;

    .line 118
    .line 119
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 120
    .line 121
    .line 122
    iput-object p2, p3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 123
    .line 124
    invoke-virtual {p0}, Lp3/i0;->f()Lw3/h2;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    invoke-interface {v2}, Lw3/h2;->b()J

    .line 129
    .line 130
    .line 131
    move-result-wide v5

    .line 132
    :try_start_1
    new-instance v2, Lkotlin/jvm/internal/b0;

    .line 133
    .line 134
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 135
    .line 136
    .line 137
    new-instance v7, Lg1/o0;

    .line 138
    .line 139
    invoke-direct {v7, v2, p3, p1, v4}, Lg1/o0;-><init>(Lkotlin/jvm/internal/b0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Lkotlin/coroutines/Continuation;)V

    .line 140
    .line 141
    .line 142
    iput-object p2, v0, Lg1/n0;->d:Lp3/t;

    .line 143
    .line 144
    iput-object p1, v0, Lg1/n0;->e:Lkotlin/jvm/internal/f0;

    .line 145
    .line 146
    iput-object v2, v0, Lg1/n0;->f:Lkotlin/jvm/internal/b0;

    .line 147
    .line 148
    iput v3, v0, Lg1/n0;->h:I

    .line 149
    .line 150
    invoke-virtual {p0, v5, v6, v7, v0}, Lp3/i0;->g(JLay0/n;Lrx0/a;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    if-ne p0, v1, :cond_7

    .line 155
    .line 156
    return-object v1

    .line 157
    :cond_7
    move-object p0, v2

    .line 158
    :goto_3
    iget-boolean p0, p0, Lkotlin/jvm/internal/b0;->d:Z

    .line 159
    .line 160
    if-eqz p0, :cond_9

    .line 161
    .line 162
    iget-object p0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast p0, Lp3/t;
    :try_end_1
    .catch Lp3/n; {:try_start_1 .. :try_end_1} :catch_0

    .line 165
    .line 166
    if-nez p0, :cond_8

    .line 167
    .line 168
    return-object p2

    .line 169
    :cond_8
    return-object p0

    .line 170
    :cond_9
    :goto_4
    return-object v4

    .line 171
    :catch_0
    iget-object p0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast p0, Lp3/t;

    .line 174
    .line 175
    if-nez p0, :cond_a

    .line 176
    .line 177
    goto :goto_5

    .line 178
    :cond_a
    move-object p2, p0

    .line 179
    :goto_5
    return-object p2
.end method

.method public static final d(Lp3/i0;JILg1/r0;Lrx0/a;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-wide/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v2, p5

    .line 4
    .line 5
    instance-of v3, v2, Lg1/p0;

    .line 6
    .line 7
    if-eqz v3, :cond_0

    .line 8
    .line 9
    move-object v3, v2

    .line 10
    check-cast v3, Lg1/p0;

    .line 11
    .line 12
    iget v4, v3, Lg1/p0;->k:I

    .line 13
    .line 14
    const/high16 v5, -0x80000000

    .line 15
    .line 16
    and-int v6, v4, v5

    .line 17
    .line 18
    if-eqz v6, :cond_0

    .line 19
    .line 20
    sub-int/2addr v4, v5

    .line 21
    iput v4, v3, Lg1/p0;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v3, Lg1/p0;

    .line 25
    .line 26
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v2, v3, Lg1/p0;->j:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v5, v3, Lg1/p0;->k:I

    .line 34
    .line 35
    const-wide/16 v6, 0x0

    .line 36
    .line 37
    const/4 v8, 0x2

    .line 38
    const/4 v9, 0x1

    .line 39
    const/4 v10, 0x0

    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    if-eq v5, v9, :cond_2

    .line 43
    .line 44
    if-ne v5, v8, :cond_1

    .line 45
    .line 46
    iget v0, v3, Lg1/p0;->i:F

    .line 47
    .line 48
    iget-object v1, v3, Lg1/p0;->h:Lp3/t;

    .line 49
    .line 50
    iget-object v5, v3, Lg1/p0;->g:Lg1/i3;

    .line 51
    .line 52
    iget-object v11, v3, Lg1/p0;->f:Lkotlin/jvm/internal/e0;

    .line 53
    .line 54
    iget-object v12, v3, Lg1/p0;->e:Lp3/i0;

    .line 55
    .line 56
    iget-object v13, v3, Lg1/p0;->d:Lay0/n;

    .line 57
    .line 58
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    move v9, v8

    .line 62
    move-object/from16 v17, v10

    .line 63
    .line 64
    move-object v2, v11

    .line 65
    move v11, v0

    .line 66
    move-wide v7, v6

    .line 67
    move-object v0, v13

    .line 68
    goto/16 :goto_9

    .line 69
    .line 70
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 73
    .line 74
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0

    .line 78
    :cond_2
    iget v0, v3, Lg1/p0;->i:F

    .line 79
    .line 80
    iget-object v1, v3, Lg1/p0;->g:Lg1/i3;

    .line 81
    .line 82
    iget-object v5, v3, Lg1/p0;->f:Lkotlin/jvm/internal/e0;

    .line 83
    .line 84
    iget-object v11, v3, Lg1/p0;->e:Lp3/i0;

    .line 85
    .line 86
    iget-object v12, v3, Lg1/p0;->d:Lay0/n;

    .line 87
    .line 88
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object/from16 v18, v11

    .line 92
    .line 93
    move v11, v0

    .line 94
    move-object v0, v12

    .line 95
    move-object v12, v5

    .line 96
    move-object/from16 v5, v18

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 103
    .line 104
    move-object/from16 v5, p0

    .line 105
    .line 106
    iget-object v11, v5, Lp3/i0;->i:Lp3/j0;

    .line 107
    .line 108
    iget-object v11, v11, Lp3/j0;->w:Lp3/k;

    .line 109
    .line 110
    invoke-static {v11, v0, v1}, Lg1/w0;->g(Lp3/k;J)Z

    .line 111
    .line 112
    .line 113
    move-result v11

    .line 114
    if-eqz v11, :cond_4

    .line 115
    .line 116
    move-object/from16 v17, v10

    .line 117
    .line 118
    goto/16 :goto_a

    .line 119
    .line 120
    :cond_4
    invoke-virtual {v5}, Lp3/i0;->f()Lw3/h2;

    .line 121
    .line 122
    .line 123
    move-result-object v11

    .line 124
    move/from16 v12, p3

    .line 125
    .line 126
    invoke-static {v11, v12}, Lg1/w0;->h(Lw3/h2;I)F

    .line 127
    .line 128
    .line 129
    move-result v11

    .line 130
    new-instance v12, Lkotlin/jvm/internal/e0;

    .line 131
    .line 132
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 133
    .line 134
    .line 135
    iput-wide v0, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 136
    .line 137
    new-instance v0, Lg1/i3;

    .line 138
    .line 139
    const/4 v1, 0x0

    .line 140
    invoke-direct {v0, v2, v6, v7, v1}, Lg1/i3;-><init>(Ljava/lang/Object;JI)V

    .line 141
    .line 142
    .line 143
    move-object v1, v0

    .line 144
    move-object/from16 v0, p4

    .line 145
    .line 146
    :goto_1
    iput-object v0, v3, Lg1/p0;->d:Lay0/n;

    .line 147
    .line 148
    iput-object v5, v3, Lg1/p0;->e:Lp3/i0;

    .line 149
    .line 150
    iput-object v12, v3, Lg1/p0;->f:Lkotlin/jvm/internal/e0;

    .line 151
    .line 152
    iput-object v1, v3, Lg1/p0;->g:Lg1/i3;

    .line 153
    .line 154
    iput-object v10, v3, Lg1/p0;->h:Lp3/t;

    .line 155
    .line 156
    iput v11, v3, Lg1/p0;->i:F

    .line 157
    .line 158
    iput v9, v3, Lg1/p0;->k:I

    .line 159
    .line 160
    sget-object v2, Lp3/l;->e:Lp3/l;

    .line 161
    .line 162
    invoke-virtual {v5, v2, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    if-ne v2, v4, :cond_5

    .line 167
    .line 168
    goto/16 :goto_8

    .line 169
    .line 170
    :cond_5
    :goto_2
    check-cast v2, Lp3/k;

    .line 171
    .line 172
    iget-object v13, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 173
    .line 174
    move-object v14, v13

    .line 175
    check-cast v14, Ljava/util/Collection;

    .line 176
    .line 177
    invoke-interface {v14}, Ljava/util/Collection;->size()I

    .line 178
    .line 179
    .line 180
    move-result v14

    .line 181
    const/4 v15, 0x0

    .line 182
    move v9, v15

    .line 183
    :goto_3
    if-ge v9, v14, :cond_7

    .line 184
    .line 185
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v16

    .line 189
    move-object/from16 v17, v10

    .line 190
    .line 191
    move-object/from16 v10, v16

    .line 192
    .line 193
    check-cast v10, Lp3/t;

    .line 194
    .line 195
    move/from16 p0, v9

    .line 196
    .line 197
    iget-wide v8, v10, Lp3/t;->a:J

    .line 198
    .line 199
    iget-wide v6, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 200
    .line 201
    invoke-static {v8, v9, v6, v7}, Lp3/s;->e(JJ)Z

    .line 202
    .line 203
    .line 204
    move-result v6

    .line 205
    if-eqz v6, :cond_6

    .line 206
    .line 207
    goto :goto_4

    .line 208
    :cond_6
    add-int/lit8 v9, p0, 0x1

    .line 209
    .line 210
    move-object/from16 v10, v17

    .line 211
    .line 212
    const-wide/16 v6, 0x0

    .line 213
    .line 214
    const/4 v8, 0x2

    .line 215
    goto :goto_3

    .line 216
    :cond_7
    move-object/from16 v17, v10

    .line 217
    .line 218
    move-object/from16 v16, v17

    .line 219
    .line 220
    :goto_4
    move-object/from16 v6, v16

    .line 221
    .line 222
    check-cast v6, Lp3/t;

    .line 223
    .line 224
    if-nez v6, :cond_8

    .line 225
    .line 226
    goto/16 :goto_a

    .line 227
    .line 228
    :cond_8
    invoke-virtual {v6}, Lp3/t;->b()Z

    .line 229
    .line 230
    .line 231
    move-result v7

    .line 232
    if-eqz v7, :cond_9

    .line 233
    .line 234
    goto/16 :goto_a

    .line 235
    .line 236
    :cond_9
    invoke-static {v6}, Lp3/s;->d(Lp3/t;)Z

    .line 237
    .line 238
    .line 239
    move-result v7

    .line 240
    if-eqz v7, :cond_d

    .line 241
    .line 242
    iget-object v2, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 243
    .line 244
    move-object v6, v2

    .line 245
    check-cast v6, Ljava/util/Collection;

    .line 246
    .line 247
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 248
    .line 249
    .line 250
    move-result v6

    .line 251
    :goto_5
    if-ge v15, v6, :cond_b

    .line 252
    .line 253
    invoke-interface {v2, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v7

    .line 257
    move-object v8, v7

    .line 258
    check-cast v8, Lp3/t;

    .line 259
    .line 260
    iget-boolean v8, v8, Lp3/t;->d:Z

    .line 261
    .line 262
    if-eqz v8, :cond_a

    .line 263
    .line 264
    goto :goto_6

    .line 265
    :cond_a
    add-int/lit8 v15, v15, 0x1

    .line 266
    .line 267
    goto :goto_5

    .line 268
    :cond_b
    move-object/from16 v7, v17

    .line 269
    .line 270
    :goto_6
    check-cast v7, Lp3/t;

    .line 271
    .line 272
    if-nez v7, :cond_c

    .line 273
    .line 274
    goto :goto_a

    .line 275
    :cond_c
    iget-wide v6, v7, Lp3/t;->a:J

    .line 276
    .line 277
    iput-wide v6, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 278
    .line 279
    const-wide/16 v7, 0x0

    .line 280
    .line 281
    goto :goto_7

    .line 282
    :cond_d
    invoke-virtual {v1, v6, v11}, Lg1/i3;->p(Lp3/t;F)J

    .line 283
    .line 284
    .line 285
    move-result-wide v7

    .line 286
    const-wide v9, 0x7fffffff7fffffffL

    .line 287
    .line 288
    .line 289
    .line 290
    .line 291
    and-long/2addr v9, v7

    .line 292
    const-wide v13, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 293
    .line 294
    .line 295
    .line 296
    .line 297
    cmp-long v2, v9, v13

    .line 298
    .line 299
    if-eqz v2, :cond_f

    .line 300
    .line 301
    const-wide v9, 0xffffffffL

    .line 302
    .line 303
    .line 304
    .line 305
    .line 306
    and-long/2addr v7, v9

    .line 307
    long-to-int v2, v7

    .line 308
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 309
    .line 310
    .line 311
    move-result v2

    .line 312
    new-instance v7, Ljava/lang/Float;

    .line 313
    .line 314
    invoke-direct {v7, v2}, Ljava/lang/Float;-><init>(F)V

    .line 315
    .line 316
    .line 317
    invoke-interface {v0, v6, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    invoke-virtual {v6}, Lp3/t;->b()Z

    .line 321
    .line 322
    .line 323
    move-result v2

    .line 324
    if-eqz v2, :cond_e

    .line 325
    .line 326
    return-object v6

    .line 327
    :cond_e
    const-wide/16 v7, 0x0

    .line 328
    .line 329
    iput-wide v7, v1, Lg1/i3;->e:J

    .line 330
    .line 331
    :goto_7
    move-wide v6, v7

    .line 332
    move-object/from16 v10, v17

    .line 333
    .line 334
    const/4 v8, 0x2

    .line 335
    const/4 v9, 0x1

    .line 336
    goto/16 :goto_1

    .line 337
    .line 338
    :cond_f
    const-wide/16 v7, 0x0

    .line 339
    .line 340
    sget-object v2, Lp3/l;->f:Lp3/l;

    .line 341
    .line 342
    iput-object v0, v3, Lg1/p0;->d:Lay0/n;

    .line 343
    .line 344
    iput-object v5, v3, Lg1/p0;->e:Lp3/i0;

    .line 345
    .line 346
    iput-object v12, v3, Lg1/p0;->f:Lkotlin/jvm/internal/e0;

    .line 347
    .line 348
    iput-object v1, v3, Lg1/p0;->g:Lg1/i3;

    .line 349
    .line 350
    iput-object v6, v3, Lg1/p0;->h:Lp3/t;

    .line 351
    .line 352
    iput v11, v3, Lg1/p0;->i:F

    .line 353
    .line 354
    const/4 v9, 0x2

    .line 355
    iput v9, v3, Lg1/p0;->k:I

    .line 356
    .line 357
    invoke-virtual {v5, v2, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v2

    .line 361
    if-ne v2, v4, :cond_10

    .line 362
    .line 363
    :goto_8
    return-object v4

    .line 364
    :cond_10
    move-object v2, v12

    .line 365
    move-object v12, v5

    .line 366
    move-object v5, v1

    .line 367
    move-object v1, v6

    .line 368
    :goto_9
    invoke-virtual {v1}, Lp3/t;->b()Z

    .line 369
    .line 370
    .line 371
    move-result v1

    .line 372
    if-eqz v1, :cond_11

    .line 373
    .line 374
    :goto_a
    return-object v17

    .line 375
    :cond_11
    move-object v1, v5

    .line 376
    move-wide v6, v7

    .line 377
    move v8, v9

    .line 378
    move-object v5, v12

    .line 379
    move-object/from16 v10, v17

    .line 380
    .line 381
    const/4 v9, 0x1

    .line 382
    move-object v12, v2

    .line 383
    goto/16 :goto_1
.end method

.method public static final e(Lp3/i0;JLay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p4, Lg1/t0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lg1/t0;

    .line 7
    .line 8
    iget v1, v0, Lg1/t0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lg1/t0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/t0;

    .line 21
    .line 22
    invoke-direct {v0, p4}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lg1/t0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/t0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lg1/t0;->e:Lay0/k;

    .line 37
    .line 38
    iget-object p1, v0, Lg1/t0;->d:Lp3/i0;

    .line 39
    .line 40
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object p3, p0

    .line 44
    move-object p0, p1

    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :goto_1
    iput-object p0, v0, Lg1/t0;->d:Lp3/i0;

    .line 58
    .line 59
    iput-object p3, v0, Lg1/t0;->e:Lay0/k;

    .line 60
    .line 61
    iput v3, v0, Lg1/t0;->g:I

    .line 62
    .line 63
    invoke-static {p0, p1, p2, v0}, Lg1/w0;->a(Lp3/i0;JLrx0/c;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p4

    .line 67
    if-ne p4, v1, :cond_3

    .line 68
    .line 69
    return-object v1

    .line 70
    :cond_3
    :goto_2
    check-cast p4, Lp3/t;

    .line 71
    .line 72
    if-nez p4, :cond_4

    .line 73
    .line 74
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_4
    invoke-static {p4}, Lp3/s;->d(Lp3/t;)Z

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-eqz p1, :cond_5

    .line 82
    .line 83
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 84
    .line 85
    return-object p0

    .line 86
    :cond_5
    invoke-interface {p3, p4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    iget-wide p1, p4, Lp3/t;->a:J

    .line 90
    .line 91
    goto :goto_1
.end method

.method public static final f(Lp3/i0;JLay0/k;Lrx0/a;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Lg1/u0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lg1/u0;

    .line 9
    .line 10
    iget v2, v1, Lg1/u0;->j:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lg1/u0;->j:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lg1/u0;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v0, v1, Lg1/u0;->i:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lg1/u0;->j:I

    .line 32
    .line 33
    const/4 v6, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v6, :cond_1

    .line 37
    .line 38
    iget-object v3, v1, Lg1/u0;->h:Lkotlin/jvm/internal/e0;

    .line 39
    .line 40
    iget-object v7, v1, Lg1/u0;->g:Lp3/i0;

    .line 41
    .line 42
    iget-object v8, v1, Lg1/u0;->f:Lg1/w1;

    .line 43
    .line 44
    iget-object v9, v1, Lg1/u0;->e:Lp3/i0;

    .line 45
    .line 46
    iget-object v10, v1, Lg1/u0;->d:Lay0/k;

    .line 47
    .line 48
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object/from16 v16, v9

    .line 52
    .line 53
    move-object v9, v3

    .line 54
    move-object/from16 v3, v16

    .line 55
    .line 56
    goto :goto_4

    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 69
    .line 70
    move-object/from16 v3, p0

    .line 71
    .line 72
    iget-object v7, v3, Lp3/i0;->i:Lp3/j0;

    .line 73
    .line 74
    iget-object v7, v7, Lp3/j0;->w:Lp3/k;

    .line 75
    .line 76
    move-wide/from16 v8, p1

    .line 77
    .line 78
    invoke-static {v7, v8, v9}, Lg1/w0;->g(Lp3/k;J)Z

    .line 79
    .line 80
    .line 81
    move-result v7

    .line 82
    if-eqz v7, :cond_3

    .line 83
    .line 84
    move v15, v6

    .line 85
    :goto_1
    const/4 v5, 0x0

    .line 86
    goto/16 :goto_f

    .line 87
    .line 88
    :cond_3
    move-object v7, v1

    .line 89
    move-object v1, v0

    .line 90
    move-object/from16 v0, p3

    .line 91
    .line 92
    :goto_2
    new-instance v10, Lkotlin/jvm/internal/e0;

    .line 93
    .line 94
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 95
    .line 96
    .line 97
    iput-wide v8, v10, Lkotlin/jvm/internal/e0;->d:J

    .line 98
    .line 99
    move-object v8, v1

    .line 100
    move-object v1, v7

    .line 101
    move-object v7, v3

    .line 102
    :goto_3
    iput-object v0, v1, Lg1/u0;->d:Lay0/k;

    .line 103
    .line 104
    iput-object v3, v1, Lg1/u0;->e:Lp3/i0;

    .line 105
    .line 106
    iput-object v8, v1, Lg1/u0;->f:Lg1/w1;

    .line 107
    .line 108
    iput-object v7, v1, Lg1/u0;->g:Lp3/i0;

    .line 109
    .line 110
    iput-object v10, v1, Lg1/u0;->h:Lkotlin/jvm/internal/e0;

    .line 111
    .line 112
    iput v6, v1, Lg1/u0;->j:I

    .line 113
    .line 114
    sget-object v9, Lp3/l;->e:Lp3/l;

    .line 115
    .line 116
    invoke-virtual {v7, v9, v1}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    if-ne v9, v2, :cond_4

    .line 121
    .line 122
    return-object v2

    .line 123
    :cond_4
    move-object/from16 v16, v10

    .line 124
    .line 125
    move-object v10, v0

    .line 126
    move-object v0, v9

    .line 127
    move-object/from16 v9, v16

    .line 128
    .line 129
    :goto_4
    check-cast v0, Lp3/k;

    .line 130
    .line 131
    iget-object v11, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 132
    .line 133
    move-object v12, v11

    .line 134
    check-cast v12, Ljava/util/Collection;

    .line 135
    .line 136
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 137
    .line 138
    .line 139
    move-result v12

    .line 140
    const/4 v13, 0x0

    .line 141
    :goto_5
    if-ge v13, v12, :cond_6

    .line 142
    .line 143
    invoke-interface {v11, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v14

    .line 147
    move-object v15, v14

    .line 148
    check-cast v15, Lp3/t;

    .line 149
    .line 150
    iget-wide v4, v15, Lp3/t;->a:J

    .line 151
    .line 152
    move-object/from16 p0, v7

    .line 153
    .line 154
    iget-wide v6, v9, Lkotlin/jvm/internal/e0;->d:J

    .line 155
    .line 156
    invoke-static {v4, v5, v6, v7}, Lp3/s;->e(JJ)Z

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    if-eqz v4, :cond_5

    .line 161
    .line 162
    goto :goto_6

    .line 163
    :cond_5
    add-int/lit8 v13, v13, 0x1

    .line 164
    .line 165
    move-object/from16 v7, p0

    .line 166
    .line 167
    const/4 v6, 0x1

    .line 168
    goto :goto_5

    .line 169
    :cond_6
    move-object/from16 p0, v7

    .line 170
    .line 171
    const/4 v14, 0x0

    .line 172
    :goto_6
    check-cast v14, Lp3/t;

    .line 173
    .line 174
    if-nez v14, :cond_7

    .line 175
    .line 176
    const/4 v14, 0x0

    .line 177
    :goto_7
    const/4 v15, 0x1

    .line 178
    goto :goto_d

    .line 179
    :cond_7
    invoke-static {v14}, Lp3/s;->d(Lp3/t;)Z

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    if-eqz v4, :cond_b

    .line 184
    .line 185
    iget-object v0, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 186
    .line 187
    move-object v4, v0

    .line 188
    check-cast v4, Ljava/util/Collection;

    .line 189
    .line 190
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    const/4 v5, 0x0

    .line 195
    :goto_8
    if-ge v5, v4, :cond_9

    .line 196
    .line 197
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v6

    .line 201
    move-object v7, v6

    .line 202
    check-cast v7, Lp3/t;

    .line 203
    .line 204
    iget-boolean v7, v7, Lp3/t;->d:Z

    .line 205
    .line 206
    if-eqz v7, :cond_8

    .line 207
    .line 208
    goto :goto_9

    .line 209
    :cond_8
    add-int/lit8 v5, v5, 0x1

    .line 210
    .line 211
    goto :goto_8

    .line 212
    :cond_9
    const/4 v6, 0x0

    .line 213
    :goto_9
    check-cast v6, Lp3/t;

    .line 214
    .line 215
    if-nez v6, :cond_a

    .line 216
    .line 217
    goto :goto_7

    .line 218
    :cond_a
    iget-wide v4, v6, Lp3/t;->a:J

    .line 219
    .line 220
    iput-wide v4, v9, Lkotlin/jvm/internal/e0;->d:J

    .line 221
    .line 222
    const/4 v15, 0x1

    .line 223
    goto :goto_c

    .line 224
    :cond_b
    const/4 v15, 0x1

    .line 225
    invoke-static {v14, v15}, Lp3/s;->h(Lp3/t;Z)J

    .line 226
    .line 227
    .line 228
    move-result-wide v4

    .line 229
    if-nez v8, :cond_c

    .line 230
    .line 231
    invoke-static {v4, v5}, Ld3/b;->d(J)F

    .line 232
    .line 233
    .line 234
    move-result v0

    .line 235
    goto :goto_b

    .line 236
    :cond_c
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 237
    .line 238
    if-ne v8, v0, :cond_d

    .line 239
    .line 240
    const-wide v6, 0xffffffffL

    .line 241
    .line 242
    .line 243
    .line 244
    .line 245
    and-long/2addr v4, v6

    .line 246
    :goto_a
    long-to-int v0, v4

    .line 247
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 248
    .line 249
    .line 250
    move-result v0

    .line 251
    goto :goto_b

    .line 252
    :cond_d
    const/16 v0, 0x20

    .line 253
    .line 254
    shr-long/2addr v4, v0

    .line 255
    goto :goto_a

    .line 256
    :goto_b
    const/4 v4, 0x0

    .line 257
    cmpg-float v0, v0, v4

    .line 258
    .line 259
    if-nez v0, :cond_e

    .line 260
    .line 261
    :goto_c
    move-object/from16 v7, p0

    .line 262
    .line 263
    move-object v0, v10

    .line 264
    move v6, v15

    .line 265
    move-object v10, v9

    .line 266
    goto/16 :goto_3

    .line 267
    .line 268
    :cond_e
    :goto_d
    if-nez v14, :cond_f

    .line 269
    .line 270
    :goto_e
    goto/16 :goto_1

    .line 271
    .line 272
    :cond_f
    invoke-virtual {v14}, Lp3/t;->b()Z

    .line 273
    .line 274
    .line 275
    move-result v0

    .line 276
    if-eqz v0, :cond_10

    .line 277
    .line 278
    goto :goto_e

    .line 279
    :cond_10
    invoke-static {v14}, Lp3/s;->d(Lp3/t;)Z

    .line 280
    .line 281
    .line 282
    move-result v0

    .line 283
    if-eqz v0, :cond_12

    .line 284
    .line 285
    move-object v5, v14

    .line 286
    :goto_f
    if-eqz v5, :cond_11

    .line 287
    .line 288
    move v4, v15

    .line 289
    goto :goto_10

    .line 290
    :cond_11
    const/4 v4, 0x0

    .line 291
    :goto_10
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    return-object v0

    .line 296
    :cond_12
    invoke-interface {v10, v14}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    iget-wide v4, v14, Lp3/t;->a:J

    .line 300
    .line 301
    move-object v7, v1

    .line 302
    move-object v1, v8

    .line 303
    move-object v0, v10

    .line 304
    move v6, v15

    .line 305
    move-wide v8, v4

    .line 306
    goto/16 :goto_2
.end method

.method public static final g(Lp3/k;J)Z
    .locals 6

    .line 1
    iget-object p0, p0, Lp3/k;->a:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Ljava/util/Collection;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    move v2, v1

    .line 12
    :goto_0
    if-ge v2, v0, :cond_1

    .line 13
    .line 14
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    move-object v4, v3

    .line 19
    check-cast v4, Lp3/t;

    .line 20
    .line 21
    iget-wide v4, v4, Lp3/t;->a:J

    .line 22
    .line 23
    invoke-static {v4, v5, p1, p2}, Lp3/s;->e(JJ)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v3, 0x0

    .line 34
    :goto_1
    check-cast v3, Lp3/t;

    .line 35
    .line 36
    const/4 p0, 0x1

    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    iget-boolean p1, v3, Lp3/t;->d:Z

    .line 40
    .line 41
    if-ne p1, p0, :cond_2

    .line 42
    .line 43
    move v1, p0

    .line 44
    :cond_2
    xor-int/2addr p0, v1

    .line 45
    return p0
.end method

.method public static final h(Lw3/h2;I)F
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    if-ne p1, v0, :cond_0

    .line 3
    .line 4
    invoke-interface {p0}, Lw3/h2;->f()F

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    sget p1, Lg1/w0;->a:F

    .line 9
    .line 10
    mul-float/2addr p0, p1

    .line 11
    return p0

    .line 12
    :cond_0
    invoke-interface {p0}, Lw3/h2;->f()F

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public static final i(Lp3/i0;JLe81/w;Lrx0/a;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Lg1/v0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lg1/v0;

    .line 9
    .line 10
    iget v2, v1, Lg1/v0;->j:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lg1/v0;->j:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lg1/v0;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v0, v1, Lg1/v0;->i:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lg1/v0;->j:I

    .line 32
    .line 33
    const/4 v6, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v6, :cond_1

    .line 37
    .line 38
    iget-object v3, v1, Lg1/v0;->h:Lkotlin/jvm/internal/e0;

    .line 39
    .line 40
    iget-object v7, v1, Lg1/v0;->g:Lp3/i0;

    .line 41
    .line 42
    iget-object v8, v1, Lg1/v0;->f:Lg1/w1;

    .line 43
    .line 44
    iget-object v9, v1, Lg1/v0;->e:Lp3/i0;

    .line 45
    .line 46
    iget-object v10, v1, Lg1/v0;->d:Lay0/k;

    .line 47
    .line 48
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object/from16 v16, v9

    .line 52
    .line 53
    move-object v9, v3

    .line 54
    move-object/from16 v3, v16

    .line 55
    .line 56
    goto :goto_4

    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 69
    .line 70
    move-object/from16 v3, p0

    .line 71
    .line 72
    iget-object v7, v3, Lp3/i0;->i:Lp3/j0;

    .line 73
    .line 74
    iget-object v7, v7, Lp3/j0;->w:Lp3/k;

    .line 75
    .line 76
    move-wide/from16 v8, p1

    .line 77
    .line 78
    invoke-static {v7, v8, v9}, Lg1/w0;->g(Lp3/k;J)Z

    .line 79
    .line 80
    .line 81
    move-result v7

    .line 82
    if-eqz v7, :cond_3

    .line 83
    .line 84
    move v15, v6

    .line 85
    :goto_1
    const/4 v5, 0x0

    .line 86
    goto/16 :goto_f

    .line 87
    .line 88
    :cond_3
    move-object v7, v1

    .line 89
    move-object v1, v0

    .line 90
    move-object/from16 v0, p3

    .line 91
    .line 92
    :goto_2
    new-instance v10, Lkotlin/jvm/internal/e0;

    .line 93
    .line 94
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 95
    .line 96
    .line 97
    iput-wide v8, v10, Lkotlin/jvm/internal/e0;->d:J

    .line 98
    .line 99
    move-object v8, v1

    .line 100
    move-object v1, v7

    .line 101
    move-object v7, v3

    .line 102
    :goto_3
    iput-object v0, v1, Lg1/v0;->d:Lay0/k;

    .line 103
    .line 104
    iput-object v3, v1, Lg1/v0;->e:Lp3/i0;

    .line 105
    .line 106
    iput-object v8, v1, Lg1/v0;->f:Lg1/w1;

    .line 107
    .line 108
    iput-object v7, v1, Lg1/v0;->g:Lp3/i0;

    .line 109
    .line 110
    iput-object v10, v1, Lg1/v0;->h:Lkotlin/jvm/internal/e0;

    .line 111
    .line 112
    iput v6, v1, Lg1/v0;->j:I

    .line 113
    .line 114
    sget-object v9, Lp3/l;->e:Lp3/l;

    .line 115
    .line 116
    invoke-virtual {v7, v9, v1}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    if-ne v9, v2, :cond_4

    .line 121
    .line 122
    return-object v2

    .line 123
    :cond_4
    move-object/from16 v16, v10

    .line 124
    .line 125
    move-object v10, v0

    .line 126
    move-object v0, v9

    .line 127
    move-object/from16 v9, v16

    .line 128
    .line 129
    :goto_4
    check-cast v0, Lp3/k;

    .line 130
    .line 131
    iget-object v11, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 132
    .line 133
    move-object v12, v11

    .line 134
    check-cast v12, Ljava/util/Collection;

    .line 135
    .line 136
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 137
    .line 138
    .line 139
    move-result v12

    .line 140
    const/4 v13, 0x0

    .line 141
    :goto_5
    if-ge v13, v12, :cond_6

    .line 142
    .line 143
    invoke-interface {v11, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v14

    .line 147
    move-object v15, v14

    .line 148
    check-cast v15, Lp3/t;

    .line 149
    .line 150
    iget-wide v4, v15, Lp3/t;->a:J

    .line 151
    .line 152
    move-object/from16 p0, v7

    .line 153
    .line 154
    iget-wide v6, v9, Lkotlin/jvm/internal/e0;->d:J

    .line 155
    .line 156
    invoke-static {v4, v5, v6, v7}, Lp3/s;->e(JJ)Z

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    if-eqz v4, :cond_5

    .line 161
    .line 162
    goto :goto_6

    .line 163
    :cond_5
    add-int/lit8 v13, v13, 0x1

    .line 164
    .line 165
    move-object/from16 v7, p0

    .line 166
    .line 167
    const/4 v6, 0x1

    .line 168
    goto :goto_5

    .line 169
    :cond_6
    move-object/from16 p0, v7

    .line 170
    .line 171
    const/4 v14, 0x0

    .line 172
    :goto_6
    check-cast v14, Lp3/t;

    .line 173
    .line 174
    if-nez v14, :cond_7

    .line 175
    .line 176
    const/4 v14, 0x0

    .line 177
    :goto_7
    const/4 v15, 0x1

    .line 178
    goto :goto_d

    .line 179
    :cond_7
    invoke-static {v14}, Lp3/s;->d(Lp3/t;)Z

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    if-eqz v4, :cond_b

    .line 184
    .line 185
    iget-object v0, v0, Lp3/k;->a:Ljava/lang/Object;

    .line 186
    .line 187
    move-object v4, v0

    .line 188
    check-cast v4, Ljava/util/Collection;

    .line 189
    .line 190
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    const/4 v5, 0x0

    .line 195
    :goto_8
    if-ge v5, v4, :cond_9

    .line 196
    .line 197
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v6

    .line 201
    move-object v7, v6

    .line 202
    check-cast v7, Lp3/t;

    .line 203
    .line 204
    iget-boolean v7, v7, Lp3/t;->d:Z

    .line 205
    .line 206
    if-eqz v7, :cond_8

    .line 207
    .line 208
    goto :goto_9

    .line 209
    :cond_8
    add-int/lit8 v5, v5, 0x1

    .line 210
    .line 211
    goto :goto_8

    .line 212
    :cond_9
    const/4 v6, 0x0

    .line 213
    :goto_9
    check-cast v6, Lp3/t;

    .line 214
    .line 215
    if-nez v6, :cond_a

    .line 216
    .line 217
    goto :goto_7

    .line 218
    :cond_a
    iget-wide v4, v6, Lp3/t;->a:J

    .line 219
    .line 220
    iput-wide v4, v9, Lkotlin/jvm/internal/e0;->d:J

    .line 221
    .line 222
    const/4 v15, 0x1

    .line 223
    goto :goto_c

    .line 224
    :cond_b
    const/4 v15, 0x1

    .line 225
    invoke-static {v14, v15}, Lp3/s;->h(Lp3/t;Z)J

    .line 226
    .line 227
    .line 228
    move-result-wide v4

    .line 229
    if-nez v8, :cond_c

    .line 230
    .line 231
    invoke-static {v4, v5}, Ld3/b;->d(J)F

    .line 232
    .line 233
    .line 234
    move-result v0

    .line 235
    goto :goto_b

    .line 236
    :cond_c
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 237
    .line 238
    if-ne v8, v0, :cond_d

    .line 239
    .line 240
    const-wide v6, 0xffffffffL

    .line 241
    .line 242
    .line 243
    .line 244
    .line 245
    and-long/2addr v4, v6

    .line 246
    :goto_a
    long-to-int v0, v4

    .line 247
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 248
    .line 249
    .line 250
    move-result v0

    .line 251
    goto :goto_b

    .line 252
    :cond_d
    const/16 v0, 0x20

    .line 253
    .line 254
    shr-long/2addr v4, v0

    .line 255
    goto :goto_a

    .line 256
    :goto_b
    const/4 v4, 0x0

    .line 257
    cmpg-float v0, v0, v4

    .line 258
    .line 259
    if-nez v0, :cond_e

    .line 260
    .line 261
    :goto_c
    move-object/from16 v7, p0

    .line 262
    .line 263
    move-object v0, v10

    .line 264
    move v6, v15

    .line 265
    move-object v10, v9

    .line 266
    goto/16 :goto_3

    .line 267
    .line 268
    :cond_e
    :goto_d
    if-nez v14, :cond_f

    .line 269
    .line 270
    :goto_e
    goto/16 :goto_1

    .line 271
    .line 272
    :cond_f
    invoke-virtual {v14}, Lp3/t;->b()Z

    .line 273
    .line 274
    .line 275
    move-result v0

    .line 276
    if-eqz v0, :cond_10

    .line 277
    .line 278
    goto :goto_e

    .line 279
    :cond_10
    invoke-static {v14}, Lp3/s;->d(Lp3/t;)Z

    .line 280
    .line 281
    .line 282
    move-result v0

    .line 283
    if-eqz v0, :cond_12

    .line 284
    .line 285
    move-object v5, v14

    .line 286
    :goto_f
    if-eqz v5, :cond_11

    .line 287
    .line 288
    move v4, v15

    .line 289
    goto :goto_10

    .line 290
    :cond_11
    const/4 v4, 0x0

    .line 291
    :goto_10
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    return-object v0

    .line 296
    :cond_12
    invoke-interface {v10, v14}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    iget-wide v4, v14, Lp3/t;->a:J

    .line 300
    .line 301
    move-object v7, v1

    .line 302
    move-object v1, v8

    .line 303
    move-object v0, v10

    .line 304
    move v6, v15

    .line 305
    move-wide v8, v4

    .line 306
    goto/16 :goto_2
.end method
