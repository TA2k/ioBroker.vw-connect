.class public final Ll2/x1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:Ljava/util/List;

.field public e:Ljava/util/List;

.field public f:Ljava/util/List;

.field public g:Landroidx/collection/r0;

.field public h:Landroidx/collection/r0;

.field public i:Landroidx/collection/r0;

.field public j:Ljava/util/Set;

.field public k:Landroidx/collection/r0;

.field public l:I

.field public synthetic m:Ll2/y0;

.field public final synthetic n:Ll2/y1;


# direct methods
.method public constructor <init>(Ll2/y1;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll2/x1;->n:Ll2/y1;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static final b(Ll2/y1;Ljava/util/List;Ljava/util/List;Ljava/util/List;Landroidx/collection/r0;Landroidx/collection/r0;Landroidx/collection/r0;Landroidx/collection/r0;)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    move-object/from16 v3, p5

    .line 8
    .line 9
    move-object/from16 v4, p7

    .line 10
    .line 11
    iget-object v5, v0, Ll2/y1;->c:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v5

    .line 14
    :try_start_0
    invoke-interface/range {p1 .. p1}, Ljava/util/List;->clear()V

    .line 15
    .line 16
    .line 17
    invoke-interface/range {p2 .. p2}, Ljava/util/List;->clear()V

    .line 18
    .line 19
    .line 20
    move-object v6, v1

    .line 21
    check-cast v6, Ljava/util/Collection;

    .line 22
    .line 23
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    const/4 v8, 0x0

    .line 28
    :goto_0
    if-ge v8, v6, :cond_0

    .line 29
    .line 30
    invoke-interface {v1, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v9

    .line 34
    check-cast v9, Ll2/a0;

    .line 35
    .line 36
    invoke-virtual {v9}, Ll2/a0;->a()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v9}, Ll2/y1;->G(Ll2/a0;)V

    .line 40
    .line 41
    .line 42
    add-int/lit8 v8, v8, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_0
    move-exception v0

    .line 46
    goto/16 :goto_7

    .line 47
    .line 48
    :cond_0
    invoke-interface {v1}, Ljava/util/List;->clear()V

    .line 49
    .line 50
    .line 51
    iget-object v1, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 52
    .line 53
    iget-object v6, v2, Landroidx/collection/r0;->a:[J

    .line 54
    .line 55
    array-length v8, v6

    .line 56
    add-int/lit8 v8, v8, -0x2

    .line 57
    .line 58
    const/16 v7, 0x8

    .line 59
    .line 60
    const-wide/16 p2, 0x80

    .line 61
    .line 62
    if-ltz v8, :cond_4

    .line 63
    .line 64
    const/4 v9, 0x0

    .line 65
    const-wide/16 v16, 0xff

    .line 66
    .line 67
    :goto_1
    aget-wide v11, v6, v9

    .line 68
    .line 69
    const/4 v10, 0x7

    .line 70
    const-wide v18, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    not-long v13, v11

    .line 76
    shl-long/2addr v13, v10

    .line 77
    and-long/2addr v13, v11

    .line 78
    and-long v13, v13, v18

    .line 79
    .line 80
    cmp-long v13, v13, v18

    .line 81
    .line 82
    if-eqz v13, :cond_3

    .line 83
    .line 84
    sub-int v13, v9, v8

    .line 85
    .line 86
    not-int v13, v13

    .line 87
    ushr-int/lit8 v13, v13, 0x1f

    .line 88
    .line 89
    rsub-int/lit8 v13, v13, 0x8

    .line 90
    .line 91
    const/4 v14, 0x0

    .line 92
    :goto_2
    if-ge v14, v13, :cond_2

    .line 93
    .line 94
    and-long v20, v11, v16

    .line 95
    .line 96
    cmp-long v15, v20, p2

    .line 97
    .line 98
    if-gez v15, :cond_1

    .line 99
    .line 100
    shl-int/lit8 v15, v9, 0x3

    .line 101
    .line 102
    add-int/2addr v15, v14

    .line 103
    aget-object v15, v1, v15

    .line 104
    .line 105
    check-cast v15, Ll2/a0;

    .line 106
    .line 107
    invoke-virtual {v15}, Ll2/a0;->a()V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v15}, Ll2/y1;->G(Ll2/a0;)V

    .line 111
    .line 112
    .line 113
    :cond_1
    shr-long/2addr v11, v7

    .line 114
    add-int/lit8 v14, v14, 0x1

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_2
    if-ne v13, v7, :cond_5

    .line 118
    .line 119
    :cond_3
    if-eq v9, v8, :cond_5

    .line 120
    .line 121
    add-int/lit8 v9, v9, 0x1

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_4
    const/4 v10, 0x7

    .line 125
    const-wide/16 v16, 0xff

    .line 126
    .line 127
    const-wide v18, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    :cond_5
    invoke-virtual {v2}, Landroidx/collection/r0;->b()V

    .line 133
    .line 134
    .line 135
    iget-object v1, v3, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 136
    .line 137
    iget-object v2, v3, Landroidx/collection/r0;->a:[J

    .line 138
    .line 139
    array-length v6, v2

    .line 140
    add-int/lit8 v6, v6, -0x2

    .line 141
    .line 142
    if-ltz v6, :cond_9

    .line 143
    .line 144
    const/4 v8, 0x0

    .line 145
    :goto_3
    aget-wide v11, v2, v8

    .line 146
    .line 147
    not-long v13, v11

    .line 148
    shl-long/2addr v13, v10

    .line 149
    and-long/2addr v13, v11

    .line 150
    and-long v13, v13, v18

    .line 151
    .line 152
    cmp-long v9, v13, v18

    .line 153
    .line 154
    if-eqz v9, :cond_8

    .line 155
    .line 156
    sub-int v9, v8, v6

    .line 157
    .line 158
    not-int v9, v9

    .line 159
    ushr-int/lit8 v9, v9, 0x1f

    .line 160
    .line 161
    rsub-int/lit8 v9, v9, 0x8

    .line 162
    .line 163
    const/4 v13, 0x0

    .line 164
    :goto_4
    if-ge v13, v9, :cond_7

    .line 165
    .line 166
    and-long v14, v11, v16

    .line 167
    .line 168
    cmp-long v14, v14, p2

    .line 169
    .line 170
    if-gez v14, :cond_6

    .line 171
    .line 172
    shl-int/lit8 v14, v8, 0x3

    .line 173
    .line 174
    add-int/2addr v14, v13

    .line 175
    aget-object v14, v1, v14

    .line 176
    .line 177
    check-cast v14, Ll2/a0;

    .line 178
    .line 179
    invoke-virtual {v14}, Ll2/a0;->g()V

    .line 180
    .line 181
    .line 182
    :cond_6
    shr-long/2addr v11, v7

    .line 183
    add-int/lit8 v13, v13, 0x1

    .line 184
    .line 185
    goto :goto_4

    .line 186
    :cond_7
    if-ne v9, v7, :cond_9

    .line 187
    .line 188
    :cond_8
    if-eq v8, v6, :cond_9

    .line 189
    .line 190
    add-int/lit8 v8, v8, 0x1

    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_9
    invoke-virtual {v3}, Landroidx/collection/r0;->b()V

    .line 194
    .line 195
    .line 196
    invoke-virtual/range {p6 .. p6}, Landroidx/collection/r0;->b()V

    .line 197
    .line 198
    .line 199
    iget-object v1, v4, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 200
    .line 201
    iget-object v2, v4, Landroidx/collection/r0;->a:[J

    .line 202
    .line 203
    array-length v3, v2

    .line 204
    add-int/lit8 v3, v3, -0x2

    .line 205
    .line 206
    if-ltz v3, :cond_d

    .line 207
    .line 208
    const/4 v6, 0x0

    .line 209
    :goto_5
    aget-wide v8, v2, v6

    .line 210
    .line 211
    not-long v11, v8

    .line 212
    shl-long/2addr v11, v10

    .line 213
    and-long/2addr v11, v8

    .line 214
    and-long v11, v11, v18

    .line 215
    .line 216
    cmp-long v11, v11, v18

    .line 217
    .line 218
    if-eqz v11, :cond_c

    .line 219
    .line 220
    sub-int v11, v6, v3

    .line 221
    .line 222
    not-int v11, v11

    .line 223
    ushr-int/lit8 v11, v11, 0x1f

    .line 224
    .line 225
    rsub-int/lit8 v11, v11, 0x8

    .line 226
    .line 227
    const/4 v12, 0x0

    .line 228
    :goto_6
    if-ge v12, v11, :cond_b

    .line 229
    .line 230
    and-long v13, v8, v16

    .line 231
    .line 232
    cmp-long v13, v13, p2

    .line 233
    .line 234
    if-gez v13, :cond_a

    .line 235
    .line 236
    shl-int/lit8 v13, v6, 0x3

    .line 237
    .line 238
    add-int/2addr v13, v12

    .line 239
    aget-object v13, v1, v13

    .line 240
    .line 241
    check-cast v13, Ll2/a0;

    .line 242
    .line 243
    invoke-virtual {v13}, Ll2/a0;->a()V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v0, v13}, Ll2/y1;->G(Ll2/a0;)V

    .line 247
    .line 248
    .line 249
    :cond_a
    shr-long/2addr v8, v7

    .line 250
    add-int/lit8 v12, v12, 0x1

    .line 251
    .line 252
    goto :goto_6

    .line 253
    :cond_b
    if-ne v11, v7, :cond_d

    .line 254
    .line 255
    :cond_c
    if-eq v6, v3, :cond_d

    .line 256
    .line 257
    add-int/lit8 v6, v6, 0x1

    .line 258
    .line 259
    goto :goto_5

    .line 260
    :cond_d
    invoke-virtual {v4}, Landroidx/collection/r0;->b()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 261
    .line 262
    .line 263
    monitor-exit v5

    .line 264
    return-void

    .line 265
    :goto_7
    monitor-exit v5

    .line 266
    throw v0
.end method

.method public static final d(Ljava/util/List;Ll2/y1;)V
    .locals 6

    .line 1
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Ll2/y1;->c:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object v1, p1, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x0

    .line 14
    :goto_0
    if-ge v3, v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    check-cast v4, Ll2/a1;

    .line 21
    .line 22
    move-object v5, p0

    .line 23
    check-cast v5, Ljava/util/Collection;

    .line 24
    .line 25
    invoke-interface {v5, v4}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    add-int/lit8 v3, v3, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    iget-object p0, p1, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    .line 37
    .line 38
    monitor-exit v0

    .line 39
    return-void

    .line 40
    :goto_1
    monitor-exit v0

    .line 41
    throw p0
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Ll2/y0;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance p1, Ll2/x1;

    .line 8
    .line 9
    iget-object p0, p0, Ll2/x1;->n:Ll2/y1;

    .line 10
    .line 11
    invoke-direct {p1, p0, p3}, Ll2/x1;-><init>(Ll2/y1;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    iput-object p2, p1, Ll2/x1;->m:Ll2/y0;

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ll2/x1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Ll2/x1;->l:I

    .line 6
    .line 7
    const/4 v4, 0x2

    .line 8
    const/4 v5, 0x1

    .line 9
    if-eqz v2, :cond_2

    .line 10
    .line 11
    if-eq v2, v5, :cond_1

    .line 12
    .line 13
    if-ne v2, v4, :cond_0

    .line 14
    .line 15
    iget-object v2, v0, Ll2/x1;->k:Landroidx/collection/r0;

    .line 16
    .line 17
    iget-object v6, v0, Ll2/x1;->j:Ljava/util/Set;

    .line 18
    .line 19
    check-cast v6, Ljava/util/Set;

    .line 20
    .line 21
    iget-object v7, v0, Ll2/x1;->i:Landroidx/collection/r0;

    .line 22
    .line 23
    iget-object v8, v0, Ll2/x1;->h:Landroidx/collection/r0;

    .line 24
    .line 25
    iget-object v9, v0, Ll2/x1;->g:Landroidx/collection/r0;

    .line 26
    .line 27
    iget-object v10, v0, Ll2/x1;->f:Ljava/util/List;

    .line 28
    .line 29
    check-cast v10, Ljava/util/List;

    .line 30
    .line 31
    iget-object v11, v0, Ll2/x1;->e:Ljava/util/List;

    .line 32
    .line 33
    check-cast v11, Ljava/util/List;

    .line 34
    .line 35
    iget-object v12, v0, Ll2/x1;->d:Ljava/util/List;

    .line 36
    .line 37
    check-cast v12, Ljava/util/List;

    .line 38
    .line 39
    iget-object v13, v0, Ll2/x1;->m:Ll2/y0;

    .line 40
    .line 41
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    move-object/from16 v27, v13

    .line 45
    .line 46
    move-object v13, v2

    .line 47
    move-object/from16 v2, v27

    .line 48
    .line 49
    goto/16 :goto_6

    .line 50
    .line 51
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_1
    iget-object v2, v0, Ll2/x1;->k:Landroidx/collection/r0;

    .line 60
    .line 61
    iget-object v6, v0, Ll2/x1;->j:Ljava/util/Set;

    .line 62
    .line 63
    check-cast v6, Ljava/util/Set;

    .line 64
    .line 65
    iget-object v7, v0, Ll2/x1;->i:Landroidx/collection/r0;

    .line 66
    .line 67
    iget-object v8, v0, Ll2/x1;->h:Landroidx/collection/r0;

    .line 68
    .line 69
    iget-object v9, v0, Ll2/x1;->g:Landroidx/collection/r0;

    .line 70
    .line 71
    iget-object v10, v0, Ll2/x1;->f:Ljava/util/List;

    .line 72
    .line 73
    check-cast v10, Ljava/util/List;

    .line 74
    .line 75
    iget-object v11, v0, Ll2/x1;->e:Ljava/util/List;

    .line 76
    .line 77
    check-cast v11, Ljava/util/List;

    .line 78
    .line 79
    iget-object v12, v0, Ll2/x1;->d:Ljava/util/List;

    .line 80
    .line 81
    check-cast v12, Ljava/util/List;

    .line 82
    .line 83
    iget-object v13, v0, Ll2/x1;->m:Ll2/y0;

    .line 84
    .line 85
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    move-object/from16 v19, v2

    .line 89
    .line 90
    move-object v2, v13

    .line 91
    :goto_0
    move-object/from16 v25, v6

    .line 92
    .line 93
    move-object/from16 v18, v7

    .line 94
    .line 95
    move-object/from16 v24, v8

    .line 96
    .line 97
    move-object/from16 v22, v9

    .line 98
    .line 99
    move-object/from16 v23, v10

    .line 100
    .line 101
    move-object/from16 v21, v11

    .line 102
    .line 103
    move-object/from16 v20, v12

    .line 104
    .line 105
    goto/16 :goto_4

    .line 106
    .line 107
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object v2, v0, Ll2/x1;->m:Ll2/y0;

    .line 111
    .line 112
    new-instance v6, Ljava/util/ArrayList;

    .line 113
    .line 114
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 115
    .line 116
    .line 117
    new-instance v7, Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 120
    .line 121
    .line 122
    new-instance v8, Ljava/util/ArrayList;

    .line 123
    .line 124
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 125
    .line 126
    .line 127
    sget-object v9, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 128
    .line 129
    new-instance v9, Landroidx/collection/r0;

    .line 130
    .line 131
    invoke-direct {v9}, Landroidx/collection/r0;-><init>()V

    .line 132
    .line 133
    .line 134
    new-instance v10, Landroidx/collection/r0;

    .line 135
    .line 136
    invoke-direct {v10}, Landroidx/collection/r0;-><init>()V

    .line 137
    .line 138
    .line 139
    new-instance v11, Landroidx/collection/r0;

    .line 140
    .line 141
    invoke-direct {v11}, Landroidx/collection/r0;-><init>()V

    .line 142
    .line 143
    .line 144
    new-instance v12, Ln2/d;

    .line 145
    .line 146
    invoke-direct {v12, v11}, Ln2/d;-><init>(Landroidx/collection/r0;)V

    .line 147
    .line 148
    .line 149
    new-instance v13, Landroidx/collection/r0;

    .line 150
    .line 151
    invoke-direct {v13}, Landroidx/collection/r0;-><init>()V

    .line 152
    .line 153
    .line 154
    move-object/from16 v27, v12

    .line 155
    .line 156
    move-object v12, v6

    .line 157
    move-object/from16 v6, v27

    .line 158
    .line 159
    move-object/from16 v27, v11

    .line 160
    .line 161
    move-object v11, v7

    .line 162
    move-object/from16 v7, v27

    .line 163
    .line 164
    move-object/from16 v27, v10

    .line 165
    .line 166
    move-object v10, v8

    .line 167
    move-object/from16 v8, v27

    .line 168
    .line 169
    :goto_1
    iget-object v14, v0, Ll2/x1;->n:Ll2/y1;

    .line 170
    .line 171
    iget-object v14, v14, Ll2/y1;->c:Ljava/lang/Object;

    .line 172
    .line 173
    monitor-enter v14

    .line 174
    monitor-exit v14

    .line 175
    iget-object v14, v0, Ll2/x1;->n:Ll2/y1;

    .line 176
    .line 177
    iput-object v2, v0, Ll2/x1;->m:Ll2/y0;

    .line 178
    .line 179
    move-object v15, v12

    .line 180
    check-cast v15, Ljava/util/List;

    .line 181
    .line 182
    iput-object v15, v0, Ll2/x1;->d:Ljava/util/List;

    .line 183
    .line 184
    move-object v15, v11

    .line 185
    check-cast v15, Ljava/util/List;

    .line 186
    .line 187
    iput-object v15, v0, Ll2/x1;->e:Ljava/util/List;

    .line 188
    .line 189
    move-object v15, v10

    .line 190
    check-cast v15, Ljava/util/List;

    .line 191
    .line 192
    iput-object v15, v0, Ll2/x1;->f:Ljava/util/List;

    .line 193
    .line 194
    iput-object v9, v0, Ll2/x1;->g:Landroidx/collection/r0;

    .line 195
    .line 196
    iput-object v8, v0, Ll2/x1;->h:Landroidx/collection/r0;

    .line 197
    .line 198
    iput-object v7, v0, Ll2/x1;->i:Landroidx/collection/r0;

    .line 199
    .line 200
    move-object v15, v6

    .line 201
    check-cast v15, Ljava/util/Set;

    .line 202
    .line 203
    iput-object v15, v0, Ll2/x1;->j:Ljava/util/Set;

    .line 204
    .line 205
    iput-object v13, v0, Ll2/x1;->k:Landroidx/collection/r0;

    .line 206
    .line 207
    iput v5, v0, Ll2/x1;->l:I

    .line 208
    .line 209
    invoke-virtual {v14}, Ll2/y1;->y()Z

    .line 210
    .line 211
    .line 212
    move-result v15

    .line 213
    if-nez v15, :cond_6

    .line 214
    .line 215
    new-instance v15, Lvy0/l;

    .line 216
    .line 217
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 218
    .line 219
    .line 220
    move-result-object v3

    .line 221
    invoke-direct {v15, v5, v3}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v15}, Lvy0/l;->q()V

    .line 225
    .line 226
    .line 227
    iget-object v3, v14, Ll2/y1;->c:Ljava/lang/Object;

    .line 228
    .line 229
    monitor-enter v3

    .line 230
    :try_start_0
    invoke-virtual {v14}, Ll2/y1;->y()Z

    .line 231
    .line 232
    .line 233
    move-result v16

    .line 234
    if-eqz v16, :cond_3

    .line 235
    .line 236
    move-object v14, v15

    .line 237
    goto :goto_2

    .line 238
    :cond_3
    iput-object v15, v14, Ll2/y1;->r:Lvy0/l;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 239
    .line 240
    const/4 v14, 0x0

    .line 241
    :goto_2
    monitor-exit v3

    .line 242
    if-eqz v14, :cond_4

    .line 243
    .line 244
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 245
    .line 246
    invoke-virtual {v14, v3}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    :cond_4
    invoke-virtual {v15}, Lvy0/l;->p()Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v3

    .line 253
    sget-object v14, Lqx0/a;->d:Lqx0/a;

    .line 254
    .line 255
    if-ne v3, v14, :cond_5

    .line 256
    .line 257
    goto :goto_3

    .line 258
    :cond_5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 259
    .line 260
    goto :goto_3

    .line 261
    :catchall_0
    move-exception v0

    .line 262
    monitor-exit v3

    .line 263
    throw v0

    .line 264
    :cond_6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 265
    .line 266
    :goto_3
    if-ne v3, v1, :cond_7

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :cond_7
    move-object/from16 v19, v13

    .line 270
    .line 271
    goto/16 :goto_0

    .line 272
    .line 273
    :goto_4
    iget-object v3, v0, Ll2/x1;->n:Ll2/y1;

    .line 274
    .line 275
    sget-object v6, Ll2/y1;->z:Lyy0/c2;

    .line 276
    .line 277
    invoke-virtual {v3}, Ll2/y1;->F()Z

    .line 278
    .line 279
    .line 280
    move-result v3

    .line 281
    if-eqz v3, :cond_c

    .line 282
    .line 283
    iget-object v3, v0, Ll2/x1;->n:Ll2/y1;

    .line 284
    .line 285
    new-instance v16, Lh2/b3;

    .line 286
    .line 287
    const/16 v26, 0x1

    .line 288
    .line 289
    move-object/from16 v17, v3

    .line 290
    .line 291
    invoke-direct/range {v16 .. v26}, Lh2/b3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 292
    .line 293
    .line 294
    move-object/from16 v3, v16

    .line 295
    .line 296
    move-object/from16 v7, v18

    .line 297
    .line 298
    move-object/from16 v13, v19

    .line 299
    .line 300
    move-object/from16 v9, v22

    .line 301
    .line 302
    move-object/from16 v8, v24

    .line 303
    .line 304
    iput-object v2, v0, Ll2/x1;->m:Ll2/y0;

    .line 305
    .line 306
    move-object/from16 v6, v20

    .line 307
    .line 308
    check-cast v6, Ljava/util/List;

    .line 309
    .line 310
    iput-object v6, v0, Ll2/x1;->d:Ljava/util/List;

    .line 311
    .line 312
    move-object/from16 v6, v21

    .line 313
    .line 314
    check-cast v6, Ljava/util/List;

    .line 315
    .line 316
    iput-object v6, v0, Ll2/x1;->e:Ljava/util/List;

    .line 317
    .line 318
    move-object/from16 v6, v23

    .line 319
    .line 320
    check-cast v6, Ljava/util/List;

    .line 321
    .line 322
    iput-object v6, v0, Ll2/x1;->f:Ljava/util/List;

    .line 323
    .line 324
    iput-object v9, v0, Ll2/x1;->g:Landroidx/collection/r0;

    .line 325
    .line 326
    iput-object v8, v0, Ll2/x1;->h:Landroidx/collection/r0;

    .line 327
    .line 328
    iput-object v7, v0, Ll2/x1;->i:Landroidx/collection/r0;

    .line 329
    .line 330
    move-object/from16 v6, v25

    .line 331
    .line 332
    check-cast v6, Ljava/util/Set;

    .line 333
    .line 334
    iput-object v6, v0, Ll2/x1;->j:Ljava/util/Set;

    .line 335
    .line 336
    iput-object v13, v0, Ll2/x1;->k:Landroidx/collection/r0;

    .line 337
    .line 338
    iput v4, v0, Ll2/x1;->l:I

    .line 339
    .line 340
    invoke-interface {v2, v3, v0}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v3

    .line 344
    if-ne v3, v1, :cond_8

    .line 345
    .line 346
    :goto_5
    return-object v1

    .line 347
    :cond_8
    move-object/from16 v12, v20

    .line 348
    .line 349
    move-object/from16 v11, v21

    .line 350
    .line 351
    move-object/from16 v10, v23

    .line 352
    .line 353
    move-object/from16 v6, v25

    .line 354
    .line 355
    :goto_6
    iget-object v3, v0, Ll2/x1;->n:Ll2/y1;

    .line 356
    .line 357
    iget-object v14, v3, Ll2/y1;->c:Ljava/lang/Object;

    .line 358
    .line 359
    monitor-enter v14

    .line 360
    :try_start_1
    iget-object v15, v3, Ll2/y1;->l:Landroidx/collection/q0;

    .line 361
    .line 362
    invoke-virtual {v15}, Landroidx/collection/q0;->j()Z

    .line 363
    .line 364
    .line 365
    move-result v15

    .line 366
    const/16 v16, 0x0

    .line 367
    .line 368
    if-eqz v15, :cond_a

    .line 369
    .line 370
    iget-object v15, v3, Ll2/y1;->l:Landroidx/collection/q0;

    .line 371
    .line 372
    invoke-static {v15}, Ln2/a;->b(Landroidx/collection/q0;)Landroidx/collection/l0;

    .line 373
    .line 374
    .line 375
    move-result-object v15

    .line 376
    iget-object v4, v3, Ll2/y1;->l:Landroidx/collection/q0;

    .line 377
    .line 378
    invoke-virtual {v4}, Landroidx/collection/q0;->a()V

    .line 379
    .line 380
    .line 381
    iget-object v4, v3, Ll2/y1;->m:Lvp/y1;

    .line 382
    .line 383
    iget-object v5, v4, Lvp/y1;->e:Ljava/lang/Object;

    .line 384
    .line 385
    check-cast v5, Landroidx/collection/q0;

    .line 386
    .line 387
    invoke-virtual {v5}, Landroidx/collection/q0;->a()V

    .line 388
    .line 389
    .line 390
    iget-object v4, v4, Lvp/y1;->f:Ljava/lang/Object;

    .line 391
    .line 392
    check-cast v4, Landroidx/collection/q0;

    .line 393
    .line 394
    invoke-virtual {v4}, Landroidx/collection/q0;->a()V

    .line 395
    .line 396
    .line 397
    iget-object v4, v3, Ll2/y1;->o:Landroidx/collection/q0;

    .line 398
    .line 399
    invoke-virtual {v4}, Landroidx/collection/q0;->a()V

    .line 400
    .line 401
    .line 402
    new-instance v4, Landroidx/collection/l0;

    .line 403
    .line 404
    iget v5, v15, Landroidx/collection/l0;->b:I

    .line 405
    .line 406
    invoke-direct {v4, v5}, Landroidx/collection/l0;-><init>(I)V

    .line 407
    .line 408
    .line 409
    iget-object v5, v15, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 410
    .line 411
    iget v15, v15, Landroidx/collection/l0;->b:I

    .line 412
    .line 413
    move/from16 v0, v16

    .line 414
    .line 415
    :goto_7
    if-ge v0, v15, :cond_9

    .line 416
    .line 417
    aget-object v19, v5, v0

    .line 418
    .line 419
    move/from16 v20, v0

    .line 420
    .line 421
    move-object/from16 v0, v19

    .line 422
    .line 423
    check-cast v0, Ll2/a1;

    .line 424
    .line 425
    move-object/from16 v19, v1

    .line 426
    .line 427
    iget-object v1, v3, Ll2/y1;->n:Landroidx/collection/q0;

    .line 428
    .line 429
    invoke-virtual {v1, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object v1

    .line 433
    move-object/from16 p1, v2

    .line 434
    .line 435
    new-instance v2, Llx0/l;

    .line 436
    .line 437
    invoke-direct {v2, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 438
    .line 439
    .line 440
    invoke-virtual {v4, v2}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 441
    .line 442
    .line 443
    add-int/lit8 v0, v20, 0x1

    .line 444
    .line 445
    move-object/from16 v2, p1

    .line 446
    .line 447
    move-object/from16 v1, v19

    .line 448
    .line 449
    goto :goto_7

    .line 450
    :catchall_1
    move-exception v0

    .line 451
    goto :goto_a

    .line 452
    :cond_9
    move-object/from16 v19, v1

    .line 453
    .line 454
    move-object/from16 p1, v2

    .line 455
    .line 456
    iget-object v0, v3, Ll2/y1;->n:Landroidx/collection/q0;

    .line 457
    .line 458
    invoke-virtual {v0}, Landroidx/collection/q0;->a()V

    .line 459
    .line 460
    .line 461
    goto :goto_8

    .line 462
    :cond_a
    move-object/from16 v19, v1

    .line 463
    .line 464
    move-object/from16 p1, v2

    .line 465
    .line 466
    sget-object v4, Landroidx/collection/w0;->b:Landroidx/collection/l0;

    .line 467
    .line 468
    const-string v0, "null cannot be cast to non-null type androidx.collection.ObjectList<E of androidx.collection.ObjectListKt.emptyObjectList>"

    .line 469
    .line 470
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 471
    .line 472
    .line 473
    :goto_8
    monitor-exit v14

    .line 474
    iget-object v0, v4, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 475
    .line 476
    iget v1, v4, Landroidx/collection/l0;->b:I

    .line 477
    .line 478
    move/from16 v2, v16

    .line 479
    .line 480
    :goto_9
    if-ge v2, v1, :cond_b

    .line 481
    .line 482
    aget-object v3, v0, v2

    .line 483
    .line 484
    check-cast v3, Llx0/l;

    .line 485
    .line 486
    iget-object v4, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v4, Ll2/a1;

    .line 489
    .line 490
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 491
    .line 492
    check-cast v3, Ll2/z0;

    .line 493
    .line 494
    add-int/lit8 v2, v2, 0x1

    .line 495
    .line 496
    goto :goto_9

    .line 497
    :cond_b
    const/4 v4, 0x2

    .line 498
    const/4 v5, 0x1

    .line 499
    move-object/from16 v0, p0

    .line 500
    .line 501
    move-object/from16 v2, p1

    .line 502
    .line 503
    move-object/from16 v1, v19

    .line 504
    .line 505
    goto/16 :goto_1

    .line 506
    .line 507
    :goto_a
    monitor-exit v14

    .line 508
    throw v0

    .line 509
    :cond_c
    move-object/from16 v7, v18

    .line 510
    .line 511
    move-object/from16 v13, v19

    .line 512
    .line 513
    move-object/from16 v9, v22

    .line 514
    .line 515
    move-object/from16 v8, v24

    .line 516
    .line 517
    move-object/from16 v0, p0

    .line 518
    .line 519
    move-object/from16 v12, v20

    .line 520
    .line 521
    move-object/from16 v11, v21

    .line 522
    .line 523
    move-object/from16 v10, v23

    .line 524
    .line 525
    move-object/from16 v6, v25

    .line 526
    .line 527
    goto/16 :goto_1
.end method
