.class public final Lz4/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li5/c;


# instance fields
.field public final a:Lh5/e;

.field public b:Ljava/util/Map;

.field public final c:Ljava/util/LinkedHashMap;

.field public final d:Ljava/util/LinkedHashMap;

.field public final e:Lz4/q;

.field public final f:[I

.field public final g:[I


# direct methods
.method public constructor <init>(Lt4/c;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lh5/e;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1, v1}, Lh5/d;-><init>(II)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v2, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 16
    .line 17
    new-instance v2, Lgw0/c;

    .line 18
    .line 19
    invoke-direct {v2, v0}, Lgw0/c;-><init>(Lh5/e;)V

    .line 20
    .line 21
    .line 22
    iput-object v2, v0, Lh5/e;->s0:Lgw0/c;

    .line 23
    .line 24
    new-instance v2, Li5/f;

    .line 25
    .line 26
    invoke-direct {v2, v0}, Li5/f;-><init>(Lh5/e;)V

    .line 27
    .line 28
    .line 29
    iput-object v2, v0, Lh5/e;->t0:Li5/f;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    iput-object v3, v0, Lh5/e;->v0:Li5/c;

    .line 33
    .line 34
    iput-boolean v1, v0, Lh5/e;->w0:Z

    .line 35
    .line 36
    new-instance v4, La5/c;

    .line 37
    .line 38
    invoke-direct {v4}, La5/c;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object v4, v0, Lh5/e;->x0:La5/c;

    .line 42
    .line 43
    iput v1, v0, Lh5/e;->A0:I

    .line 44
    .line 45
    iput v1, v0, Lh5/e;->B0:I

    .line 46
    .line 47
    const/4 v4, 0x4

    .line 48
    new-array v5, v4, [Lh5/b;

    .line 49
    .line 50
    iput-object v5, v0, Lh5/e;->C0:[Lh5/b;

    .line 51
    .line 52
    new-array v4, v4, [Lh5/b;

    .line 53
    .line 54
    iput-object v4, v0, Lh5/e;->D0:[Lh5/b;

    .line 55
    .line 56
    const/16 v4, 0x101

    .line 57
    .line 58
    iput v4, v0, Lh5/e;->E0:I

    .line 59
    .line 60
    iput-boolean v1, v0, Lh5/e;->F0:Z

    .line 61
    .line 62
    iput-boolean v1, v0, Lh5/e;->G0:Z

    .line 63
    .line 64
    iput-object v3, v0, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 65
    .line 66
    iput-object v3, v0, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 67
    .line 68
    iput-object v3, v0, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 69
    .line 70
    iput-object v3, v0, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 71
    .line 72
    new-instance v1, Ljava/util/HashSet;

    .line 73
    .line 74
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object v1, v0, Lh5/e;->L0:Ljava/util/HashSet;

    .line 78
    .line 79
    new-instance v1, Li5/b;

    .line 80
    .line 81
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 82
    .line 83
    .line 84
    iput-object v1, v0, Lh5/e;->M0:Li5/b;

    .line 85
    .line 86
    iput-object p0, v0, Lh5/e;->v0:Li5/c;

    .line 87
    .line 88
    iput-object p0, v2, Li5/f;->h:Ljava/lang/Object;

    .line 89
    .line 90
    iput-object v0, p0, Lz4/p;->a:Lh5/e;

    .line 91
    .line 92
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 93
    .line 94
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 95
    .line 96
    .line 97
    iput-object v0, p0, Lz4/p;->b:Ljava/util/Map;

    .line 98
    .line 99
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 100
    .line 101
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 102
    .line 103
    .line 104
    iput-object v0, p0, Lz4/p;->c:Ljava/util/LinkedHashMap;

    .line 105
    .line 106
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 107
    .line 108
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 109
    .line 110
    .line 111
    iput-object v0, p0, Lz4/p;->d:Ljava/util/LinkedHashMap;

    .line 112
    .line 113
    new-instance v0, Lz4/q;

    .line 114
    .line 115
    invoke-direct {v0, p1}, Lz4/q;-><init>(Lt4/c;)V

    .line 116
    .line 117
    .line 118
    iput-object v0, p0, Lz4/p;->e:Lz4/q;

    .line 119
    .line 120
    const/4 p1, 0x2

    .line 121
    new-array v0, p1, [I

    .line 122
    .line 123
    iput-object v0, p0, Lz4/p;->f:[I

    .line 124
    .line 125
    new-array p1, p1, [I

    .line 126
    .line 127
    iput-object p1, p0, Lz4/p;->g:[I

    .line 128
    .line 129
    return-void
.end method

.method public static d(IIIIZZI[I)V
    .locals 4

    .line 1
    invoke-static {p0}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v0, :cond_c

    .line 8
    .line 9
    if-eq v0, v2, :cond_b

    .line 10
    .line 11
    const/4 v3, 0x2

    .line 12
    if-eq v0, v3, :cond_5

    .line 13
    .line 14
    const/4 p1, 0x3

    .line 15
    if-ne v0, p1, :cond_0

    .line 16
    .line 17
    aput p6, p7, v1

    .line 18
    .line 19
    aput p6, p7, v2

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const/4 p2, 0x1

    .line 25
    if-eq p0, p2, :cond_4

    .line 26
    .line 27
    const/4 p2, 0x2

    .line 28
    if-eq p0, p2, :cond_3

    .line 29
    .line 30
    const/4 p2, 0x3

    .line 31
    if-eq p0, p2, :cond_2

    .line 32
    .line 33
    const/4 p2, 0x4

    .line 34
    if-eq p0, p2, :cond_1

    .line 35
    .line 36
    const-string p0, "null"

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const-string p0, "MATCH_PARENT"

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    const-string p0, "MATCH_CONSTRAINT"

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_3
    const-string p0, "WRAP_CONTENT"

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_4
    const-string p0, "FIXED"

    .line 49
    .line 50
    :goto_0
    const-string p2, " is not supported"

    .line 51
    .line 52
    invoke-virtual {p0, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p1

    .line 64
    :cond_5
    if-nez p5, :cond_8

    .line 65
    .line 66
    if-eq p3, v2, :cond_6

    .line 67
    .line 68
    if-ne p3, v3, :cond_7

    .line 69
    .line 70
    :cond_6
    if-eq p3, v3, :cond_8

    .line 71
    .line 72
    if-ne p2, v2, :cond_8

    .line 73
    .line 74
    if-eqz p4, :cond_7

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_7
    move p0, v1

    .line 78
    goto :goto_2

    .line 79
    :cond_8
    :goto_1
    move p0, v2

    .line 80
    :goto_2
    if-eqz p0, :cond_9

    .line 81
    .line 82
    move p2, p1

    .line 83
    goto :goto_3

    .line 84
    :cond_9
    move p2, v1

    .line 85
    :goto_3
    aput p2, p7, v1

    .line 86
    .line 87
    if-eqz p0, :cond_a

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_a
    move p1, p6

    .line 91
    :goto_4
    aput p1, p7, v2

    .line 92
    .line 93
    return-void

    .line 94
    :cond_b
    aput v1, p7, v1

    .line 95
    .line 96
    aput p6, p7, v2

    .line 97
    .line 98
    return-void

    .line 99
    :cond_c
    aput p1, p7, v1

    .line 100
    .line 101
    aput p1, p7, v2

    .line 102
    .line 103
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    return-void
.end method

.method public final b(Lh5/d;Li5/b;)V
    .locals 27

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
    const/4 v3, 0x0

    .line 8
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v4

    .line 12
    iget-object v5, v1, Lh5/d;->k:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v6, v0, Lz4/p;->c:Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-virtual {v6, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v7

    .line 20
    check-cast v7, [Ljava/lang/Integer;

    .line 21
    .line 22
    iget v8, v2, Li5/b;->a:I

    .line 23
    .line 24
    iget v9, v2, Li5/b;->c:I

    .line 25
    .line 26
    iget v10, v1, Lh5/d;->s:I

    .line 27
    .line 28
    iget v11, v2, Li5/b;->j:I

    .line 29
    .line 30
    const/4 v12, 0x1

    .line 31
    if-eqz v7, :cond_0

    .line 32
    .line 33
    aget-object v13, v7, v12

    .line 34
    .line 35
    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v13

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    move v13, v3

    .line 41
    :goto_0
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 42
    .line 43
    .line 44
    move-result v14

    .line 45
    if-ne v13, v14, :cond_1

    .line 46
    .line 47
    move v13, v12

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v13, v12

    .line 50
    move v12, v3

    .line 51
    :goto_1
    invoke-virtual {v1}, Lh5/d;->B()Z

    .line 52
    .line 53
    .line 54
    move-result v14

    .line 55
    iget-object v15, v0, Lz4/p;->e:Lz4/q;

    .line 56
    .line 57
    move/from16 v17, v14

    .line 58
    .line 59
    iget-wide v13, v15, Lz4/q;->l:J

    .line 60
    .line 61
    invoke-static {v13, v14}, Lt4/a;->h(J)I

    .line 62
    .line 63
    .line 64
    move-result v14

    .line 65
    move-object v13, v15

    .line 66
    iget-object v15, v0, Lz4/p;->f:[I

    .line 67
    .line 68
    move/from16 v18, v3

    .line 69
    .line 70
    move-object v3, v13

    .line 71
    move/from16 v13, v17

    .line 72
    .line 73
    const/16 v16, 0x1

    .line 74
    .line 75
    invoke-static/range {v8 .. v15}, Lz4/p;->d(IIIIZZI[I)V

    .line 76
    .line 77
    .line 78
    iget v8, v2, Li5/b;->b:I

    .line 79
    .line 80
    iget v9, v2, Li5/b;->d:I

    .line 81
    .line 82
    iget v10, v1, Lh5/d;->t:I

    .line 83
    .line 84
    iget v11, v2, Li5/b;->j:I

    .line 85
    .line 86
    if-eqz v7, :cond_2

    .line 87
    .line 88
    aget-object v7, v7, v18

    .line 89
    .line 90
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result v7

    .line 94
    goto :goto_2

    .line 95
    :cond_2
    move/from16 v7, v18

    .line 96
    .line 97
    :goto_2
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 98
    .line 99
    .line 100
    move-result v12

    .line 101
    if-ne v7, v12, :cond_3

    .line 102
    .line 103
    move/from16 v23, v16

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_3
    move/from16 v23, v18

    .line 107
    .line 108
    :goto_3
    invoke-virtual {v1}, Lh5/d;->C()Z

    .line 109
    .line 110
    .line 111
    move-result v24

    .line 112
    iget-wide v12, v3, Lz4/q;->l:J

    .line 113
    .line 114
    invoke-static {v12, v13}, Lt4/a;->g(J)I

    .line 115
    .line 116
    .line 117
    move-result v25

    .line 118
    iget-object v7, v0, Lz4/p;->g:[I

    .line 119
    .line 120
    move-object/from16 v26, v7

    .line 121
    .line 122
    move/from16 v19, v8

    .line 123
    .line 124
    move/from16 v20, v9

    .line 125
    .line 126
    move/from16 v21, v10

    .line 127
    .line 128
    move/from16 v22, v11

    .line 129
    .line 130
    invoke-static/range {v19 .. v26}, Lz4/p;->d(IIIIZZI[I)V

    .line 131
    .line 132
    .line 133
    iget-object v7, v0, Lz4/p;->f:[I

    .line 134
    .line 135
    aget v8, v7, v18

    .line 136
    .line 137
    aget v7, v7, v16

    .line 138
    .line 139
    iget-object v9, v0, Lz4/p;->g:[I

    .line 140
    .line 141
    aget v10, v9, v18

    .line 142
    .line 143
    aget v9, v9, v16

    .line 144
    .line 145
    invoke-static {v8, v7, v10, v9}, Lt4/b;->a(IIII)J

    .line 146
    .line 147
    .line 148
    move-result-wide v7

    .line 149
    iget v9, v2, Li5/b;->j:I

    .line 150
    .line 151
    const/4 v10, 0x3

    .line 152
    const/4 v11, 0x2

    .line 153
    move/from16 v13, v16

    .line 154
    .line 155
    if-eq v9, v13, :cond_5

    .line 156
    .line 157
    if-eq v9, v11, :cond_5

    .line 158
    .line 159
    iget v9, v2, Li5/b;->a:I

    .line 160
    .line 161
    if-ne v9, v10, :cond_5

    .line 162
    .line 163
    iget v9, v1, Lh5/d;->s:I

    .line 164
    .line 165
    if-nez v9, :cond_5

    .line 166
    .line 167
    iget v9, v2, Li5/b;->b:I

    .line 168
    .line 169
    if-ne v9, v10, :cond_5

    .line 170
    .line 171
    iget v9, v1, Lh5/d;->t:I

    .line 172
    .line 173
    if-eqz v9, :cond_4

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_4
    move/from16 v17, v11

    .line 177
    .line 178
    goto/16 :goto_c

    .line 179
    .line 180
    :cond_5
    :goto_4
    invoke-virtual {v0, v1, v7, v8}, Lz4/p;->c(Lh5/d;J)J

    .line 181
    .line 182
    .line 183
    move-result-wide v12

    .line 184
    move/from16 v9, v18

    .line 185
    .line 186
    iput-boolean v9, v1, Lh5/d;->g:Z

    .line 187
    .line 188
    const/16 v9, 0x20

    .line 189
    .line 190
    shr-long v14, v12, v9

    .line 191
    .line 192
    long-to-int v9, v14

    .line 193
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 194
    .line 195
    .line 196
    move-result-object v14

    .line 197
    iget v15, v1, Lh5/d;->v:I

    .line 198
    .line 199
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 200
    .line 201
    .line 202
    move-result-object v17

    .line 203
    const/16 v19, 0x0

    .line 204
    .line 205
    if-lez v15, :cond_6

    .line 206
    .line 207
    move-object/from16 v15, v17

    .line 208
    .line 209
    :goto_5
    move/from16 v17, v11

    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_6
    move-object/from16 v15, v19

    .line 213
    .line 214
    goto :goto_5

    .line 215
    :goto_6
    iget v11, v1, Lh5/d;->w:I

    .line 216
    .line 217
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 218
    .line 219
    .line 220
    move-result-object v20

    .line 221
    if-lez v11, :cond_7

    .line 222
    .line 223
    move-object/from16 v11, v20

    .line 224
    .line 225
    goto :goto_7

    .line 226
    :cond_7
    move-object/from16 v11, v19

    .line 227
    .line 228
    :goto_7
    invoke-static {v14, v15, v11}, Lkp/r9;->j(Ljava/lang/Comparable;Ljava/lang/Comparable;Ljava/lang/Comparable;)Ljava/lang/Comparable;

    .line 229
    .line 230
    .line 231
    move-result-object v11

    .line 232
    check-cast v11, Ljava/lang/Number;

    .line 233
    .line 234
    invoke-virtual {v11}, Ljava/lang/Number;->intValue()I

    .line 235
    .line 236
    .line 237
    move-result v11

    .line 238
    const-wide v14, 0xffffffffL

    .line 239
    .line 240
    .line 241
    .line 242
    .line 243
    and-long/2addr v12, v14

    .line 244
    long-to-int v12, v12

    .line 245
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 246
    .line 247
    .line 248
    move-result-object v13

    .line 249
    iget v14, v1, Lh5/d;->y:I

    .line 250
    .line 251
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 252
    .line 253
    .line 254
    move-result-object v15

    .line 255
    if-lez v14, :cond_8

    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_8
    move-object/from16 v15, v19

    .line 259
    .line 260
    :goto_8
    iget v14, v1, Lh5/d;->z:I

    .line 261
    .line 262
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 263
    .line 264
    .line 265
    move-result-object v20

    .line 266
    if-lez v14, :cond_9

    .line 267
    .line 268
    move-object/from16 v14, v20

    .line 269
    .line 270
    goto :goto_9

    .line 271
    :cond_9
    move-object/from16 v14, v19

    .line 272
    .line 273
    :goto_9
    invoke-static {v13, v15, v14}, Lkp/r9;->j(Ljava/lang/Comparable;Ljava/lang/Comparable;Ljava/lang/Comparable;)Ljava/lang/Comparable;

    .line 274
    .line 275
    .line 276
    move-result-object v13

    .line 277
    check-cast v13, Ljava/lang/Number;

    .line 278
    .line 279
    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    .line 280
    .line 281
    .line 282
    move-result v13

    .line 283
    if-eq v11, v9, :cond_a

    .line 284
    .line 285
    invoke-static {v7, v8}, Lt4/a;->i(J)I

    .line 286
    .line 287
    .line 288
    move-result v9

    .line 289
    invoke-static {v7, v8}, Lt4/a;->g(J)I

    .line 290
    .line 291
    .line 292
    move-result v7

    .line 293
    invoke-static {v11, v11, v9, v7}, Lt4/b;->a(IIII)J

    .line 294
    .line 295
    .line 296
    move-result-wide v7

    .line 297
    const/4 v9, 0x1

    .line 298
    goto :goto_a

    .line 299
    :cond_a
    const/4 v9, 0x0

    .line 300
    :goto_a
    if-eq v13, v12, :cond_b

    .line 301
    .line 302
    invoke-static {v7, v8}, Lt4/a;->j(J)I

    .line 303
    .line 304
    .line 305
    move-result v9

    .line 306
    invoke-static {v7, v8}, Lt4/a;->h(J)I

    .line 307
    .line 308
    .line 309
    move-result v7

    .line 310
    invoke-static {v9, v7, v13, v13}, Lt4/b;->a(IIII)J

    .line 311
    .line 312
    .line 313
    move-result-wide v7

    .line 314
    const/4 v12, 0x1

    .line 315
    goto :goto_b

    .line 316
    :cond_b
    move v12, v9

    .line 317
    :goto_b
    if-eqz v12, :cond_c

    .line 318
    .line 319
    invoke-virtual {v0, v1, v7, v8}, Lz4/p;->c(Lh5/d;J)J

    .line 320
    .line 321
    .line 322
    const/4 v9, 0x0

    .line 323
    iput-boolean v9, v1, Lh5/d;->g:Z

    .line 324
    .line 325
    :cond_c
    :goto_c
    iget-object v0, v0, Lz4/p;->b:Ljava/util/Map;

    .line 326
    .line 327
    iget-object v7, v1, Lh5/d;->g0:Ljava/lang/Object;

    .line 328
    .line 329
    invoke-interface {v0, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    move-result-object v0

    .line 333
    check-cast v0, Lt3/e1;

    .line 334
    .line 335
    if-eqz v0, :cond_d

    .line 336
    .line 337
    iget v7, v0, Lt3/e1;->d:I

    .line 338
    .line 339
    goto :goto_d

    .line 340
    :cond_d
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 341
    .line 342
    .line 343
    move-result v7

    .line 344
    :goto_d
    iput v7, v2, Li5/b;->e:I

    .line 345
    .line 346
    if-eqz v0, :cond_e

    .line 347
    .line 348
    iget v7, v0, Lt3/e1;->e:I

    .line 349
    .line 350
    goto :goto_e

    .line 351
    :cond_e
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 352
    .line 353
    .line 354
    move-result v7

    .line 355
    :goto_e
    iput v7, v2, Li5/b;->f:I

    .line 356
    .line 357
    const/high16 v7, -0x80000000

    .line 358
    .line 359
    if-eqz v0, :cond_12

    .line 360
    .line 361
    iget-object v8, v3, Lz4/q;->i:Ljava/util/ArrayList;

    .line 362
    .line 363
    iget-boolean v9, v3, Lz4/q;->j:Z

    .line 364
    .line 365
    if-eqz v9, :cond_11

    .line 366
    .line 367
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 368
    .line 369
    .line 370
    iget-object v9, v3, Lz4/q;->h:Ljava/util/ArrayList;

    .line 371
    .line 372
    invoke-virtual {v9}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 373
    .line 374
    .line 375
    move-result-object v9

    .line 376
    :cond_f
    :goto_f
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 377
    .line 378
    .line 379
    move-result v11

    .line 380
    if-eqz v11, :cond_10

    .line 381
    .line 382
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v11

    .line 386
    iget-object v12, v3, Lz4/q;->c:Ljava/util/HashMap;

    .line 387
    .line 388
    invoke-virtual {v12, v11}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v11

    .line 392
    check-cast v11, Le5/i;

    .line 393
    .line 394
    invoke-interface {v11}, Le5/i;->b()Lh5/d;

    .line 395
    .line 396
    .line 397
    move-result-object v11

    .line 398
    if-eqz v11, :cond_f

    .line 399
    .line 400
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 401
    .line 402
    .line 403
    goto :goto_f

    .line 404
    :cond_10
    const/4 v11, 0x0

    .line 405
    iput-boolean v11, v3, Lz4/q;->j:Z

    .line 406
    .line 407
    :cond_11
    invoke-virtual {v8, v1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-result v1

    .line 411
    if-eqz v1, :cond_12

    .line 412
    .line 413
    sget-object v1, Lt3/d;->a:Lt3/o;

    .line 414
    .line 415
    invoke-virtual {v0, v1}, Lt3/e1;->a0(Lt3/a;)I

    .line 416
    .line 417
    .line 418
    move-result v0

    .line 419
    goto :goto_10

    .line 420
    :cond_12
    move v0, v7

    .line 421
    :goto_10
    if-eq v0, v7, :cond_13

    .line 422
    .line 423
    const/4 v12, 0x1

    .line 424
    goto :goto_11

    .line 425
    :cond_13
    const/4 v12, 0x0

    .line 426
    :goto_11
    iput-boolean v12, v2, Li5/b;->h:Z

    .line 427
    .line 428
    iput v0, v2, Li5/b;->g:I

    .line 429
    .line 430
    invoke-virtual {v6, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v0

    .line 434
    if-nez v0, :cond_14

    .line 435
    .line 436
    new-array v0, v10, [Ljava/lang/Integer;

    .line 437
    .line 438
    const/16 v18, 0x0

    .line 439
    .line 440
    aput-object v4, v0, v18

    .line 441
    .line 442
    const/16 v16, 0x1

    .line 443
    .line 444
    aput-object v4, v0, v16

    .line 445
    .line 446
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    aput-object v1, v0, v17

    .line 451
    .line 452
    invoke-interface {v6, v5, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    goto :goto_12

    .line 456
    :cond_14
    const/16 v18, 0x0

    .line 457
    .line 458
    :goto_12
    check-cast v0, [Ljava/lang/Integer;

    .line 459
    .line 460
    iget v1, v2, Li5/b;->e:I

    .line 461
    .line 462
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    aput-object v1, v0, v18

    .line 467
    .line 468
    iget v1, v2, Li5/b;->f:I

    .line 469
    .line 470
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 471
    .line 472
    .line 473
    move-result-object v1

    .line 474
    const/16 v16, 0x1

    .line 475
    .line 476
    aput-object v1, v0, v16

    .line 477
    .line 478
    iget v1, v2, Li5/b;->g:I

    .line 479
    .line 480
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 481
    .line 482
    .line 483
    move-result-object v1

    .line 484
    aput-object v1, v0, v17

    .line 485
    .line 486
    iget v0, v2, Li5/b;->e:I

    .line 487
    .line 488
    iget v1, v2, Li5/b;->c:I

    .line 489
    .line 490
    if-ne v0, v1, :cond_16

    .line 491
    .line 492
    iget v0, v2, Li5/b;->f:I

    .line 493
    .line 494
    iget v1, v2, Li5/b;->d:I

    .line 495
    .line 496
    if-eq v0, v1, :cond_15

    .line 497
    .line 498
    goto :goto_13

    .line 499
    :cond_15
    move/from16 v3, v18

    .line 500
    .line 501
    goto :goto_14

    .line 502
    :cond_16
    :goto_13
    move/from16 v3, v16

    .line 503
    .line 504
    :goto_14
    iput-boolean v3, v2, Li5/b;->i:Z

    .line 505
    .line 506
    return-void
.end method

.method public final c(Lh5/d;J)J
    .locals 4

    .line 1
    iget-object v0, p1, Lh5/d;->g0:Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v1, p1, Lh5/d;->k:Ljava/lang/String;

    .line 4
    .line 5
    instance-of v2, p1, Lh5/k;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_4

    .line 9
    .line 10
    invoke-static {p2, p3}, Lt4/a;->f(J)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    const/high16 v0, -0x80000000

    .line 15
    .line 16
    const/high16 v1, 0x40000000    # 2.0f

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    move p0, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-static {p2, p3}, Lt4/a;->d(J)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    move p0, v0

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    move p0, v3

    .line 31
    :goto_0
    invoke-static {p2, p3}, Lt4/a;->e(J)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    move v3, v1

    .line 38
    goto :goto_1

    .line 39
    :cond_2
    invoke-static {p2, p3}, Lt4/a;->c(J)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_3

    .line 44
    .line 45
    move v3, v0

    .line 46
    :cond_3
    :goto_1
    check-cast p1, Lh5/k;

    .line 47
    .line 48
    invoke-static {p2, p3}, Lt4/a;->h(J)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-static {p2, p3}, Lt4/a;->g(J)I

    .line 53
    .line 54
    .line 55
    move-result p2

    .line 56
    invoke-virtual {p1, p0, v0, v3, p2}, Lh5/k;->Y(IIII)V

    .line 57
    .line 58
    .line 59
    iget p0, p1, Lh5/k;->A0:I

    .line 60
    .line 61
    iget p1, p1, Lh5/k;->B0:I

    .line 62
    .line 63
    invoke-static {p0, p1}, Landroidx/collection/n;->a(II)J

    .line 64
    .line 65
    .line 66
    move-result-wide p0

    .line 67
    return-wide p0

    .line 68
    :cond_4
    instance-of p1, v0, Lt3/p0;

    .line 69
    .line 70
    if-eqz p1, :cond_5

    .line 71
    .line 72
    move-object p1, v0

    .line 73
    check-cast p1, Lt3/p0;

    .line 74
    .line 75
    invoke-interface {p1, p2, p3}, Lt3/p0;->L(J)Lt3/e1;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    iget-object p0, p0, Lz4/p;->b:Ljava/util/Map;

    .line 80
    .line 81
    invoke-interface {p0, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    iget p0, p1, Lt3/e1;->d:I

    .line 85
    .line 86
    iget p1, p1, Lt3/e1;->e:I

    .line 87
    .line 88
    invoke-static {p0, p1}, Landroidx/collection/n;->a(II)J

    .line 89
    .line 90
    .line 91
    move-result-wide p0

    .line 92
    return-wide p0

    .line 93
    :cond_5
    new-instance p0, Ljava/lang/StringBuilder;

    .line 94
    .line 95
    const-string p1, "Nothing to measure for widget: "

    .line 96
    .line 97
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    const-string p1, "CCL"

    .line 108
    .line 109
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 110
    .line 111
    .line 112
    invoke-static {v3, v3}, Landroidx/collection/n;->a(II)J

    .line 113
    .line 114
    .line 115
    move-result-wide p0

    .line 116
    return-wide p0
.end method

.method public final e(Lt3/d1;Ljava/util/List;Ljava/util/Map;)V
    .locals 12

    .line 1
    iput-object p3, p0, Lz4/p;->b:Ljava/util/Map;

    .line 2
    .line 3
    iget-object p3, p0, Lz4/p;->d:Ljava/util/LinkedHashMap;

    .line 4
    .line 5
    invoke-interface {p3}, Ljava/util/Map;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const-string v1, "null"

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    if-eqz v0, :cond_5

    .line 14
    .line 15
    iget-object v0, p0, Lz4/p;->a:Lh5/e;

    .line 16
    .line 17
    iget-object v0, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    move v5, v3

    .line 24
    :goto_0
    if-ge v5, v4, :cond_5

    .line 25
    .line 26
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    check-cast v6, Lh5/d;

    .line 31
    .line 32
    iget-object v7, v6, Lh5/d;->g0:Ljava/lang/Object;

    .line 33
    .line 34
    instance-of v8, v7, Lt3/p0;

    .line 35
    .line 36
    if-eqz v8, :cond_4

    .line 37
    .line 38
    new-instance v8, Le5/l;

    .line 39
    .line 40
    iget-object v6, v6, Lh5/d;->j:Le5/l;

    .line 41
    .line 42
    iget-object v9, v6, Le5/l;->a:Lh5/d;

    .line 43
    .line 44
    if-eqz v9, :cond_0

    .line 45
    .line 46
    invoke-virtual {v9}, Lh5/d;->s()I

    .line 47
    .line 48
    .line 49
    move-result v10

    .line 50
    iput v10, v6, Le5/l;->b:I

    .line 51
    .line 52
    invoke-virtual {v9}, Lh5/d;->t()I

    .line 53
    .line 54
    .line 55
    move-result v10

    .line 56
    iput v10, v6, Le5/l;->c:I

    .line 57
    .line 58
    invoke-virtual {v9}, Lh5/d;->s()I

    .line 59
    .line 60
    .line 61
    invoke-virtual {v9}, Lh5/d;->t()I

    .line 62
    .line 63
    .line 64
    iget-object v9, v9, Lh5/d;->j:Le5/l;

    .line 65
    .line 66
    invoke-virtual {v6, v9}, Le5/l;->a(Le5/l;)V

    .line 67
    .line 68
    .line 69
    :cond_0
    invoke-direct {v8, v6}, Le5/l;-><init>(Le5/l;)V

    .line 70
    .line 71
    .line 72
    check-cast v7, Lt3/p0;

    .line 73
    .line 74
    invoke-static {v7}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v6

    .line 78
    if-nez v6, :cond_1

    .line 79
    .line 80
    invoke-interface {v7}, Lt3/p0;->l()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-object v6, v2

    .line 84
    :cond_1
    if-eqz v6, :cond_2

    .line 85
    .line 86
    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    if-nez v6, :cond_3

    .line 91
    .line 92
    :cond_2
    move-object v6, v1

    .line 93
    :cond_3
    invoke-interface {p3, v6, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    :cond_4
    add-int/lit8 v5, v5, 0x1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_5
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    :goto_1
    if-ge v3, v0, :cond_e

    .line 104
    .line 105
    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    check-cast v4, Lt3/p0;

    .line 110
    .line 111
    invoke-static {v4}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    if-nez v5, :cond_6

    .line 116
    .line 117
    invoke-interface {v4}, Lt3/p0;->l()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-object v5, v2

    .line 121
    :cond_6
    if-eqz v5, :cond_7

    .line 122
    .line 123
    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    if-nez v5, :cond_8

    .line 128
    .line 129
    :cond_7
    move-object v5, v1

    .line 130
    :cond_8
    invoke-virtual {p3, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    check-cast v5, Le5/l;

    .line 135
    .line 136
    if-nez v5, :cond_9

    .line 137
    .line 138
    :goto_2
    move-object v6, p1

    .line 139
    goto/16 :goto_5

    .line 140
    .line 141
    :cond_9
    iget-object v6, p0, Lz4/p;->b:Ljava/util/Map;

    .line 142
    .line 143
    invoke-interface {v6, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v4

    .line 147
    move-object v7, v4

    .line 148
    check-cast v7, Lt3/e1;

    .line 149
    .line 150
    if-nez v7, :cond_a

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_a
    iget v4, v5, Le5/l;->o:I

    .line 154
    .line 155
    const/16 v6, 0x8

    .line 156
    .line 157
    if-ne v4, v6, :cond_b

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_b
    iget v4, v5, Le5/l;->f:F

    .line 161
    .line 162
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 163
    .line 164
    .line 165
    move-result v4

    .line 166
    const-wide/16 v8, 0x0

    .line 167
    .line 168
    if-eqz v4, :cond_c

    .line 169
    .line 170
    iget v4, v5, Le5/l;->g:F

    .line 171
    .line 172
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 173
    .line 174
    .line 175
    move-result v4

    .line 176
    if-eqz v4, :cond_c

    .line 177
    .line 178
    iget v4, v5, Le5/l;->h:F

    .line 179
    .line 180
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    if-eqz v4, :cond_c

    .line 185
    .line 186
    iget v4, v5, Le5/l;->i:F

    .line 187
    .line 188
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    if-eqz v4, :cond_c

    .line 193
    .line 194
    iget v4, v5, Le5/l;->j:F

    .line 195
    .line 196
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    if-eqz v4, :cond_c

    .line 201
    .line 202
    iget v4, v5, Le5/l;->k:F

    .line 203
    .line 204
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 205
    .line 206
    .line 207
    move-result v4

    .line 208
    if-eqz v4, :cond_c

    .line 209
    .line 210
    iget v4, v5, Le5/l;->l:F

    .line 211
    .line 212
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    if-eqz v4, :cond_c

    .line 217
    .line 218
    iget v4, v5, Le5/l;->m:F

    .line 219
    .line 220
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 221
    .line 222
    .line 223
    move-result v4

    .line 224
    if-eqz v4, :cond_c

    .line 225
    .line 226
    iget v4, v5, Le5/l;->n:F

    .line 227
    .line 228
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 229
    .line 230
    .line 231
    move-result v4

    .line 232
    if-eqz v4, :cond_c

    .line 233
    .line 234
    iget v4, v5, Le5/l;->b:I

    .line 235
    .line 236
    long-to-int v6, v8

    .line 237
    sub-int/2addr v4, v6

    .line 238
    iget v5, v5, Le5/l;->c:I

    .line 239
    .line 240
    sub-int/2addr v5, v6

    .line 241
    invoke-static {v4, v5}, Lkp/d9;->a(II)J

    .line 242
    .line 243
    .line 244
    move-result-wide v4

    .line 245
    invoke-static {p1, v7, v4, v5}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 246
    .line 247
    .line 248
    goto :goto_2

    .line 249
    :cond_c
    new-instance v11, Lw3/a0;

    .line 250
    .line 251
    const/16 v4, 0xa

    .line 252
    .line 253
    invoke-direct {v11, v5, v4}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 254
    .line 255
    .line 256
    iget v4, v5, Le5/l;->b:I

    .line 257
    .line 258
    long-to-int v6, v8

    .line 259
    sub-int v8, v4, v6

    .line 260
    .line 261
    iget v4, v5, Le5/l;->c:I

    .line 262
    .line 263
    sub-int v9, v4, v6

    .line 264
    .line 265
    iget v4, v5, Le5/l;->k:F

    .line 266
    .line 267
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 268
    .line 269
    .line 270
    move-result v4

    .line 271
    if-eqz v4, :cond_d

    .line 272
    .line 273
    const/4 v4, 0x0

    .line 274
    :goto_3
    move-object v6, p1

    .line 275
    move v10, v4

    .line 276
    goto :goto_4

    .line 277
    :cond_d
    iget v4, v5, Le5/l;->k:F

    .line 278
    .line 279
    goto :goto_3

    .line 280
    :goto_4
    invoke-virtual/range {v6 .. v11}, Lt3/d1;->w(Lt3/e1;IIFLay0/k;)V

    .line 281
    .line 282
    .line 283
    :goto_5
    add-int/lit8 v3, v3, 0x1

    .line 284
    .line 285
    move-object p1, v6

    .line 286
    goto/16 :goto_1

    .line 287
    .line 288
    :cond_e
    return-void
.end method

.method public final f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    move-object/from16 v2, p5

    .line 6
    .line 7
    move-object/from16 v3, p6

    .line 8
    .line 9
    iput-object v3, v0, Lz4/p;->b:Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    if-eqz v3, :cond_0

    .line 16
    .line 17
    invoke-static/range {p1 .. p2}, Lt4/a;->j(J)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-static/range {p1 .. p2}, Lt4/a;->i(J)I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    invoke-static {v0, v1}, Lkp/f9;->a(II)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    return-wide v0

    .line 30
    :cond_0
    invoke-static/range {p1 .. p2}, Lt4/a;->f(J)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    sget-object v4, Le5/g;->i:Ljava/lang/String;

    .line 35
    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    invoke-static/range {p1 .. p2}, Lt4/a;->h(J)I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    invoke-static {v3}, Le5/g;->b(I)Le5/g;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    new-instance v3, Le5/g;

    .line 48
    .line 49
    invoke-direct {v3, v4}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-static/range {p1 .. p2}, Lt4/a;->j(J)I

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    if-ltz v5, :cond_2

    .line 57
    .line 58
    iput v5, v3, Le5/g;->a:I

    .line 59
    .line 60
    :cond_2
    :goto_0
    iget-object v5, v0, Lz4/p;->e:Lz4/q;

    .line 61
    .line 62
    iget-object v6, v5, Lz4/q;->f:Le5/b;

    .line 63
    .line 64
    iget-object v7, v5, Lz4/q;->d:Ljava/util/HashMap;

    .line 65
    .line 66
    iget-object v8, v5, Lz4/q;->c:Ljava/util/HashMap;

    .line 67
    .line 68
    iget-object v9, v5, Lz4/q;->f:Le5/b;

    .line 69
    .line 70
    iput-object v3, v6, Le5/b;->d0:Le5/g;

    .line 71
    .line 72
    invoke-static/range {p1 .. p2}, Lt4/a;->e(J)Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    if-eqz v3, :cond_3

    .line 77
    .line 78
    invoke-static/range {p1 .. p2}, Lt4/a;->g(J)I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    invoke-static {v3}, Le5/g;->b(I)Le5/g;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    goto :goto_1

    .line 87
    :cond_3
    new-instance v3, Le5/g;

    .line 88
    .line 89
    invoke-direct {v3, v4}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-static/range {p1 .. p2}, Lt4/a;->i(J)I

    .line 93
    .line 94
    .line 95
    move-result v4

    .line 96
    if-ltz v4, :cond_4

    .line 97
    .line 98
    iput v4, v3, Le5/g;->a:I

    .line 99
    .line 100
    :cond_4
    :goto_1
    iput-object v3, v9, Le5/b;->e0:Le5/g;

    .line 101
    .line 102
    iget-object v3, v9, Le5/b;->d0:Le5/g;

    .line 103
    .line 104
    iget-object v10, v0, Lz4/p;->a:Lh5/e;

    .line 105
    .line 106
    const/4 v4, 0x0

    .line 107
    invoke-virtual {v3, v10, v4}, Le5/g;->a(Lh5/d;I)V

    .line 108
    .line 109
    .line 110
    iget-object v3, v9, Le5/b;->e0:Le5/g;

    .line 111
    .line 112
    const/4 v6, 0x1

    .line 113
    invoke-virtual {v3, v10, v6}, Le5/g;->a(Lh5/d;I)V

    .line 114
    .line 115
    .line 116
    move-wide/from16 v11, p1

    .line 117
    .line 118
    iput-wide v11, v5, Lz4/q;->l:J

    .line 119
    .line 120
    sget-object v3, Lt4/m;->e:Lt4/m;

    .line 121
    .line 122
    move-object/from16 v13, p3

    .line 123
    .line 124
    if-ne v13, v3, :cond_5

    .line 125
    .line 126
    move v3, v6

    .line 127
    goto :goto_2

    .line 128
    :cond_5
    move v3, v4

    .line 129
    :goto_2
    xor-int/2addr v3, v6

    .line 130
    iput-boolean v3, v5, Lz4/q;->b:Z

    .line 131
    .line 132
    iget-object v3, v0, Lz4/p;->b:Ljava/util/Map;

    .line 133
    .line 134
    invoke-interface {v3}, Ljava/util/Map;->clear()V

    .line 135
    .line 136
    .line 137
    iget-object v3, v0, Lz4/p;->c:Ljava/util/LinkedHashMap;

    .line 138
    .line 139
    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->clear()V

    .line 140
    .line 141
    .line 142
    iget-object v0, v0, Lz4/p;->d:Ljava/util/LinkedHashMap;

    .line 143
    .line 144
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->clear()V

    .line 145
    .line 146
    .line 147
    iget-object v0, v1, Lz4/m;->i:Ljava/util/ArrayList;

    .line 148
    .line 149
    iget-boolean v3, v1, Lz4/m;->g:Z

    .line 150
    .line 151
    if-nez v3, :cond_a

    .line 152
    .line 153
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 154
    .line 155
    .line 156
    move-result v3

    .line 157
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 158
    .line 159
    .line 160
    move-result v14

    .line 161
    if-eq v3, v14, :cond_6

    .line 162
    .line 163
    goto :goto_5

    .line 164
    :cond_6
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 165
    .line 166
    .line 167
    move-result v3

    .line 168
    move v14, v4

    .line 169
    :goto_3
    if-ge v14, v3, :cond_9

    .line 170
    .line 171
    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v15

    .line 175
    check-cast v15, Lt3/p0;

    .line 176
    .line 177
    invoke-interface {v15}, Lt3/p0;->l()Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v15

    .line 181
    instance-of v13, v15, Lz4/i;

    .line 182
    .line 183
    if-eqz v13, :cond_7

    .line 184
    .line 185
    check-cast v15, Lz4/i;

    .line 186
    .line 187
    goto :goto_4

    .line 188
    :cond_7
    const/4 v15, 0x0

    .line 189
    :goto_4
    invoke-virtual {v0, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v13

    .line 193
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v13

    .line 197
    if-nez v13, :cond_8

    .line 198
    .line 199
    goto :goto_5

    .line 200
    :cond_8
    add-int/lit8 v14, v14, 0x1

    .line 201
    .line 202
    goto :goto_3

    .line 203
    :cond_9
    invoke-static {v5, v2}, Li0/d;->b(Lz4/q;Ljava/util/List;)V

    .line 204
    .line 205
    .line 206
    goto/16 :goto_f

    .line 207
    .line 208
    :cond_a
    :goto_5
    invoke-virtual {v8}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 217
    .line 218
    .line 219
    move-result v3

    .line 220
    if-eqz v3, :cond_b

    .line 221
    .line 222
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    invoke-virtual {v8, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    check-cast v3, Le5/i;

    .line 231
    .line 232
    invoke-interface {v3}, Le5/i;->b()Lh5/d;

    .line 233
    .line 234
    .line 235
    move-result-object v3

    .line 236
    invoke-virtual {v3}, Lh5/d;->D()V

    .line 237
    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_b
    invoke-virtual {v8}, Ljava/util/HashMap;->clear()V

    .line 241
    .line 242
    .line 243
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    invoke-virtual {v8, v0, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    invoke-virtual {v7}, Ljava/util/HashMap;->clear()V

    .line 251
    .line 252
    .line 253
    iget-object v0, v5, Lz4/q;->e:Ljava/util/HashMap;

    .line 254
    .line 255
    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    .line 256
    .line 257
    .line 258
    iget-object v0, v5, Lz4/q;->h:Ljava/util/ArrayList;

    .line 259
    .line 260
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 261
    .line 262
    .line 263
    iput-boolean v6, v5, Lz4/q;->j:Z

    .line 264
    .line 265
    iget-object v0, v1, Lz4/m;->i:Ljava/util/ArrayList;

    .line 266
    .line 267
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 268
    .line 269
    .line 270
    iget-object v0, v1, Lz4/m;->f:Lv2/r;

    .line 271
    .line 272
    iget-object v3, v1, Lz4/m;->h:Lz4/l;

    .line 273
    .line 274
    new-instance v13, Ltv/j;

    .line 275
    .line 276
    const/4 v14, 0x2

    .line 277
    invoke-direct {v13, v2, v1, v5, v14}, Ltv/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 278
    .line 279
    .line 280
    sget-object v14, Llx0/b0;->a:Llx0/b0;

    .line 281
    .line 282
    invoke-virtual {v0, v14, v3, v13}, Lv2/r;->d(Ljava/lang/Object;Lay0/k;Lay0/a;)V

    .line 283
    .line 284
    .line 285
    iput-boolean v4, v1, Lz4/m;->g:Z

    .line 286
    .line 287
    invoke-static {v5, v2}, Li0/d;->b(Lz4/q;Ljava/util/List;)V

    .line 288
    .line 289
    .line 290
    iget-object v0, v10, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 291
    .line 292
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 293
    .line 294
    .line 295
    iget-object v0, v9, Le5/b;->d0:Le5/g;

    .line 296
    .line 297
    invoke-virtual {v0, v10, v4}, Le5/g;->a(Lh5/d;I)V

    .line 298
    .line 299
    .line 300
    iget-object v0, v9, Le5/b;->e0:Le5/g;

    .line 301
    .line 302
    invoke-virtual {v0, v10, v6}, Le5/g;->a(Lh5/d;I)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v7}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    :cond_c
    :goto_7
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 314
    .line 315
    .line 316
    move-result v1

    .line 317
    if-eqz v1, :cond_e

    .line 318
    .line 319
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v1

    .line 323
    invoke-virtual {v7, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v2

    .line 327
    check-cast v2, Le5/h;

    .line 328
    .line 329
    invoke-virtual {v2}, Le5/h;->s()Lh5/i;

    .line 330
    .line 331
    .line 332
    move-result-object v2

    .line 333
    if-eqz v2, :cond_c

    .line 334
    .line 335
    invoke-virtual {v8, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v3

    .line 339
    check-cast v3, Le5/i;

    .line 340
    .line 341
    if-nez v3, :cond_d

    .line 342
    .line 343
    invoke-virtual {v5, v1}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 344
    .line 345
    .line 346
    move-result-object v3

    .line 347
    :cond_d
    invoke-interface {v3, v2}, Le5/i;->a(Lh5/d;)V

    .line 348
    .line 349
    .line 350
    goto :goto_7

    .line 351
    :cond_e
    invoke-virtual {v8}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    :cond_f
    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 360
    .line 361
    .line 362
    move-result v1

    .line 363
    if-eqz v1, :cond_11

    .line 364
    .line 365
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    invoke-virtual {v8, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    check-cast v2, Le5/i;

    .line 374
    .line 375
    if-eq v2, v9, :cond_f

    .line 376
    .line 377
    invoke-interface {v2}, Le5/i;->c()Lf5/d;

    .line 378
    .line 379
    .line 380
    move-result-object v3

    .line 381
    instance-of v3, v3, Le5/h;

    .line 382
    .line 383
    if-eqz v3, :cond_f

    .line 384
    .line 385
    invoke-interface {v2}, Le5/i;->c()Lf5/d;

    .line 386
    .line 387
    .line 388
    move-result-object v2

    .line 389
    check-cast v2, Le5/h;

    .line 390
    .line 391
    invoke-virtual {v2}, Le5/h;->s()Lh5/i;

    .line 392
    .line 393
    .line 394
    move-result-object v2

    .line 395
    if-eqz v2, :cond_f

    .line 396
    .line 397
    invoke-virtual {v8, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v3

    .line 401
    check-cast v3, Le5/i;

    .line 402
    .line 403
    if-nez v3, :cond_10

    .line 404
    .line 405
    invoke-virtual {v5, v1}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 406
    .line 407
    .line 408
    move-result-object v3

    .line 409
    :cond_10
    invoke-interface {v3, v2}, Le5/i;->a(Lh5/d;)V

    .line 410
    .line 411
    .line 412
    goto :goto_8

    .line 413
    :cond_11
    invoke-virtual {v8}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 418
    .line 419
    .line 420
    move-result-object v0

    .line 421
    :goto_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 422
    .line 423
    .line 424
    move-result v1

    .line 425
    if-eqz v1, :cond_14

    .line 426
    .line 427
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    invoke-virtual {v8, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v1

    .line 435
    check-cast v1, Le5/i;

    .line 436
    .line 437
    if-eq v1, v9, :cond_13

    .line 438
    .line 439
    invoke-interface {v1}, Le5/i;->b()Lh5/d;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    invoke-interface {v1}, Le5/i;->getKey()Ljava/lang/Object;

    .line 444
    .line 445
    .line 446
    move-result-object v3

    .line 447
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object v3

    .line 451
    iput-object v3, v2, Lh5/d;->i0:Ljava/lang/String;

    .line 452
    .line 453
    const/4 v3, 0x0

    .line 454
    iput-object v3, v2, Lh5/d;->U:Lh5/e;

    .line 455
    .line 456
    invoke-interface {v1}, Le5/i;->c()Lf5/d;

    .line 457
    .line 458
    .line 459
    move-result-object v4

    .line 460
    instance-of v4, v4, Lf5/g;

    .line 461
    .line 462
    if-eqz v4, :cond_12

    .line 463
    .line 464
    invoke-interface {v1}, Le5/i;->apply()V

    .line 465
    .line 466
    .line 467
    :cond_12
    invoke-virtual {v10, v2}, Lh5/e;->V(Lh5/d;)V

    .line 468
    .line 469
    .line 470
    goto :goto_9

    .line 471
    :cond_13
    const/4 v3, 0x0

    .line 472
    invoke-interface {v1, v10}, Le5/i;->a(Lh5/d;)V

    .line 473
    .line 474
    .line 475
    goto :goto_9

    .line 476
    :cond_14
    invoke-virtual {v7}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    :goto_a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 485
    .line 486
    .line 487
    move-result v1

    .line 488
    if-eqz v1, :cond_17

    .line 489
    .line 490
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v1

    .line 494
    invoke-virtual {v7, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v1

    .line 498
    check-cast v1, Le5/h;

    .line 499
    .line 500
    invoke-virtual {v1}, Le5/h;->s()Lh5/i;

    .line 501
    .line 502
    .line 503
    move-result-object v2

    .line 504
    if-eqz v2, :cond_16

    .line 505
    .line 506
    iget-object v2, v1, Le5/h;->m0:Ljava/util/ArrayList;

    .line 507
    .line 508
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 509
    .line 510
    .line 511
    move-result-object v2

    .line 512
    :goto_b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 513
    .line 514
    .line 515
    move-result v3

    .line 516
    if-eqz v3, :cond_15

    .line 517
    .line 518
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v3

    .line 522
    invoke-virtual {v8, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 523
    .line 524
    .line 525
    move-result-object v3

    .line 526
    check-cast v3, Le5/i;

    .line 527
    .line 528
    invoke-virtual {v1}, Le5/h;->s()Lh5/i;

    .line 529
    .line 530
    .line 531
    move-result-object v4

    .line 532
    invoke-interface {v3}, Le5/i;->b()Lh5/d;

    .line 533
    .line 534
    .line 535
    move-result-object v3

    .line 536
    invoke-virtual {v4, v3}, Lh5/i;->V(Lh5/d;)V

    .line 537
    .line 538
    .line 539
    goto :goto_b

    .line 540
    :cond_15
    invoke-virtual {v1}, Le5/h;->apply()V

    .line 541
    .line 542
    .line 543
    goto :goto_a

    .line 544
    :cond_16
    invoke-virtual {v1}, Le5/h;->apply()V

    .line 545
    .line 546
    .line 547
    goto :goto_a

    .line 548
    :cond_17
    invoke-virtual {v8}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 549
    .line 550
    .line 551
    move-result-object v0

    .line 552
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 553
    .line 554
    .line 555
    move-result-object v0

    .line 556
    :cond_18
    :goto_c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 557
    .line 558
    .line 559
    move-result v1

    .line 560
    if-eqz v1, :cond_1c

    .line 561
    .line 562
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v1

    .line 566
    invoke-virtual {v8, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    move-result-object v1

    .line 570
    check-cast v1, Le5/i;

    .line 571
    .line 572
    if-eq v1, v9, :cond_18

    .line 573
    .line 574
    invoke-interface {v1}, Le5/i;->c()Lf5/d;

    .line 575
    .line 576
    .line 577
    move-result-object v2

    .line 578
    instance-of v2, v2, Le5/h;

    .line 579
    .line 580
    if-eqz v2, :cond_18

    .line 581
    .line 582
    invoke-interface {v1}, Le5/i;->c()Lf5/d;

    .line 583
    .line 584
    .line 585
    move-result-object v2

    .line 586
    check-cast v2, Le5/h;

    .line 587
    .line 588
    invoke-virtual {v2}, Le5/h;->s()Lh5/i;

    .line 589
    .line 590
    .line 591
    move-result-object v3

    .line 592
    if-eqz v3, :cond_18

    .line 593
    .line 594
    iget-object v2, v2, Le5/h;->m0:Ljava/util/ArrayList;

    .line 595
    .line 596
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 597
    .line 598
    .line 599
    move-result-object v2

    .line 600
    :goto_d
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 601
    .line 602
    .line 603
    move-result v4

    .line 604
    if-eqz v4, :cond_1b

    .line 605
    .line 606
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    move-result-object v4

    .line 610
    invoke-virtual {v8, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 611
    .line 612
    .line 613
    move-result-object v5

    .line 614
    check-cast v5, Le5/i;

    .line 615
    .line 616
    if-eqz v5, :cond_19

    .line 617
    .line 618
    invoke-interface {v5}, Le5/i;->b()Lh5/d;

    .line 619
    .line 620
    .line 621
    move-result-object v4

    .line 622
    invoke-virtual {v3, v4}, Lh5/i;->V(Lh5/d;)V

    .line 623
    .line 624
    .line 625
    goto :goto_d

    .line 626
    :cond_19
    instance-of v5, v4, Le5/i;

    .line 627
    .line 628
    if-eqz v5, :cond_1a

    .line 629
    .line 630
    check-cast v4, Le5/i;

    .line 631
    .line 632
    invoke-interface {v4}, Le5/i;->b()Lh5/d;

    .line 633
    .line 634
    .line 635
    move-result-object v4

    .line 636
    invoke-virtual {v3, v4}, Lh5/i;->V(Lh5/d;)V

    .line 637
    .line 638
    .line 639
    goto :goto_d

    .line 640
    :cond_1a
    sget-object v5, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 641
    .line 642
    new-instance v6, Ljava/lang/StringBuilder;

    .line 643
    .line 644
    const-string v7, "couldn\'t find reference for "

    .line 645
    .line 646
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 647
    .line 648
    .line 649
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 650
    .line 651
    .line 652
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 653
    .line 654
    .line 655
    move-result-object v4

    .line 656
    invoke-virtual {v5, v4}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 657
    .line 658
    .line 659
    goto :goto_d

    .line 660
    :cond_1b
    invoke-interface {v1}, Le5/i;->apply()V

    .line 661
    .line 662
    .line 663
    goto :goto_c

    .line 664
    :cond_1c
    invoke-virtual {v8}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 665
    .line 666
    .line 667
    move-result-object v0

    .line 668
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 669
    .line 670
    .line 671
    move-result-object v0

    .line 672
    :cond_1d
    :goto_e
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 673
    .line 674
    .line 675
    move-result v1

    .line 676
    if-eqz v1, :cond_1e

    .line 677
    .line 678
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    invoke-virtual {v8, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    move-result-object v2

    .line 686
    check-cast v2, Le5/i;

    .line 687
    .line 688
    invoke-interface {v2}, Le5/i;->apply()V

    .line 689
    .line 690
    .line 691
    invoke-interface {v2}, Le5/i;->b()Lh5/d;

    .line 692
    .line 693
    .line 694
    move-result-object v2

    .line 695
    if-eqz v2, :cond_1d

    .line 696
    .line 697
    if-eqz v1, :cond_1d

    .line 698
    .line 699
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 700
    .line 701
    .line 702
    move-result-object v1

    .line 703
    iput-object v1, v2, Lh5/d;->k:Ljava/lang/String;

    .line 704
    .line 705
    goto :goto_e

    .line 706
    :cond_1e
    :goto_f
    invoke-static {v11, v12}, Lt4/a;->h(J)I

    .line 707
    .line 708
    .line 709
    move-result v0

    .line 710
    invoke-virtual {v10, v0}, Lh5/d;->S(I)V

    .line 711
    .line 712
    .line 713
    invoke-static {v11, v12}, Lt4/a;->g(J)I

    .line 714
    .line 715
    .line 716
    move-result v0

    .line 717
    invoke-virtual {v10, v0}, Lh5/d;->N(I)V

    .line 718
    .line 719
    .line 720
    iget-object v0, v10, Lh5/e;->s0:Lgw0/c;

    .line 721
    .line 722
    invoke-virtual {v0, v10}, Lgw0/c;->D(Lh5/e;)V

    .line 723
    .line 724
    .line 725
    const/16 v0, 0x101

    .line 726
    .line 727
    iput v0, v10, Lh5/e;->E0:I

    .line 728
    .line 729
    const/16 v0, 0x200

    .line 730
    .line 731
    invoke-virtual {v10, v0}, Lh5/e;->c0(I)Z

    .line 732
    .line 733
    .line 734
    move-result v0

    .line 735
    sput-boolean v0, La5/c;->q:Z

    .line 736
    .line 737
    iget v11, v10, Lh5/e;->E0:I

    .line 738
    .line 739
    const/16 v16, 0x0

    .line 740
    .line 741
    const/16 v17, 0x0

    .line 742
    .line 743
    const/4 v12, 0x0

    .line 744
    const/4 v13, 0x0

    .line 745
    const/4 v14, 0x0

    .line 746
    const/4 v15, 0x0

    .line 747
    invoke-virtual/range {v10 .. v17}, Lh5/e;->a0(IIIIIII)V

    .line 748
    .line 749
    .line 750
    invoke-virtual {v10}, Lh5/d;->r()I

    .line 751
    .line 752
    .line 753
    move-result v0

    .line 754
    invoke-virtual {v10}, Lh5/d;->l()I

    .line 755
    .line 756
    .line 757
    move-result v1

    .line 758
    invoke-static {v0, v1}, Lkp/f9;->a(II)J

    .line 759
    .line 760
    .line 761
    move-result-wide v0

    .line 762
    return-wide v0
.end method
