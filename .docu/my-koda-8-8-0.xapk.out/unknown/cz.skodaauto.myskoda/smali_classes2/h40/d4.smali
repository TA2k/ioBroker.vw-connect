.class public final Lh40/d4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:I

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/util/List;

.field public final f:Ljava/util/List;

.field public final g:Ljava/util/List;

.field public final h:Ljava/util/List;

.field public final i:Lh40/b4;

.field public final j:Lh40/a4;

.field public final k:Ljava/util/List;

.field public final l:Z

.field public final m:Ljava/lang/String;

.field public final n:Z

.field public final o:Z

.field public final p:Lql0/g;

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z


# direct methods
.method public constructor <init>(IZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lh40/b4;Lh40/a4;Ljava/util/List;ZLjava/lang/String;ZZLql0/g;ZZZZ)V
    .locals 1

    const-string v0, "activeRewards"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "availableRewards"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lh40/d4;->a:I

    .line 3
    iput-boolean p2, p0, Lh40/d4;->b:Z

    .line 4
    iput-boolean p3, p0, Lh40/d4;->c:Z

    .line 5
    iput-boolean p4, p0, Lh40/d4;->d:Z

    .line 6
    iput-object p5, p0, Lh40/d4;->e:Ljava/util/List;

    .line 7
    iput-object p6, p0, Lh40/d4;->f:Ljava/util/List;

    .line 8
    iput-object p7, p0, Lh40/d4;->g:Ljava/util/List;

    .line 9
    iput-object p8, p0, Lh40/d4;->h:Ljava/util/List;

    .line 10
    iput-object p9, p0, Lh40/d4;->i:Lh40/b4;

    .line 11
    iput-object p10, p0, Lh40/d4;->j:Lh40/a4;

    .line 12
    iput-object p11, p0, Lh40/d4;->k:Ljava/util/List;

    .line 13
    iput-boolean p12, p0, Lh40/d4;->l:Z

    .line 14
    iput-object p13, p0, Lh40/d4;->m:Ljava/lang/String;

    .line 15
    iput-boolean p14, p0, Lh40/d4;->n:Z

    move/from16 p1, p15

    .line 16
    iput-boolean p1, p0, Lh40/d4;->o:Z

    move-object/from16 p1, p16

    .line 17
    iput-object p1, p0, Lh40/d4;->p:Lql0/g;

    move/from16 p1, p17

    .line 18
    iput-boolean p1, p0, Lh40/d4;->q:Z

    move/from16 p1, p18

    .line 19
    iput-boolean p1, p0, Lh40/d4;->r:Z

    move/from16 p1, p19

    .line 20
    iput-boolean p1, p0, Lh40/d4;->s:Z

    move/from16 p1, p20

    .line 21
    iput-boolean p1, p0, Lh40/d4;->t:Z

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/util/List;I)V
    .locals 24

    and-int/lit8 v0, p3, 0x2

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eqz v0, :cond_0

    move v5, v2

    goto :goto_0

    :cond_0
    move v5, v1

    :goto_0
    and-int/lit8 v0, p3, 0x8

    if-eqz v0, :cond_1

    move v7, v2

    goto :goto_1

    :cond_1
    move v7, v1

    :goto_1
    and-int/lit8 v0, p3, 0x10

    .line 22
    sget-object v9, Lmx0/s;->d:Lmx0/s;

    if-eqz v0, :cond_2

    move-object v8, v9

    goto :goto_2

    :cond_2
    move-object/from16 v8, p1

    :goto_2
    and-int/lit8 v0, p3, 0x40

    if-eqz v0, :cond_3

    move-object v10, v9

    goto :goto_3

    :cond_3
    move-object/from16 v10, p2

    .line 23
    :goto_3
    sget-object v12, Lh40/b4;->e:Lh40/b4;

    .line 24
    sget-object v13, Lh40/a4;->e:Lh40/a4;

    .line 25
    sget-object v0, Lh40/b4;->h:Lsx0/b;

    .line 26
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v14

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object v11, v9

    move-object/from16 v3, p0

    .line 27
    invoke-direct/range {v3 .. v23}, Lh40/d4;-><init>(IZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lh40/b4;Lh40/a4;Ljava/util/List;ZLjava/lang/String;ZZLql0/g;ZZZZ)V

    return-void
.end method

.method public static a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p20

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget v2, v0, Lh40/d4;->a:I

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move/from16 v2, p1

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    iget-boolean v3, v0, Lh40/d4;->b:Z

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move/from16 v3, p2

    .line 22
    .line 23
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 24
    .line 25
    if-eqz v4, :cond_2

    .line 26
    .line 27
    iget-boolean v4, v0, Lh40/d4;->c:Z

    .line 28
    .line 29
    goto :goto_2

    .line 30
    :cond_2
    move/from16 v4, p3

    .line 31
    .line 32
    :goto_2
    and-int/lit8 v5, v1, 0x8

    .line 33
    .line 34
    if-eqz v5, :cond_3

    .line 35
    .line 36
    iget-boolean v5, v0, Lh40/d4;->d:Z

    .line 37
    .line 38
    goto :goto_3

    .line 39
    :cond_3
    move/from16 v5, p4

    .line 40
    .line 41
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 42
    .line 43
    if-eqz v6, :cond_4

    .line 44
    .line 45
    iget-object v6, v0, Lh40/d4;->e:Ljava/util/List;

    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move-object/from16 v6, p5

    .line 49
    .line 50
    :goto_4
    and-int/lit8 v7, v1, 0x20

    .line 51
    .line 52
    if-eqz v7, :cond_5

    .line 53
    .line 54
    iget-object v7, v0, Lh40/d4;->f:Ljava/util/List;

    .line 55
    .line 56
    goto :goto_5

    .line 57
    :cond_5
    move-object/from16 v7, p6

    .line 58
    .line 59
    :goto_5
    and-int/lit8 v8, v1, 0x40

    .line 60
    .line 61
    if-eqz v8, :cond_6

    .line 62
    .line 63
    iget-object v8, v0, Lh40/d4;->g:Ljava/util/List;

    .line 64
    .line 65
    goto :goto_6

    .line 66
    :cond_6
    move-object/from16 v8, p7

    .line 67
    .line 68
    :goto_6
    and-int/lit16 v9, v1, 0x80

    .line 69
    .line 70
    if-eqz v9, :cond_7

    .line 71
    .line 72
    iget-object v9, v0, Lh40/d4;->h:Ljava/util/List;

    .line 73
    .line 74
    goto :goto_7

    .line 75
    :cond_7
    move-object/from16 v9, p8

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 78
    .line 79
    if-eqz v10, :cond_8

    .line 80
    .line 81
    iget-object v10, v0, Lh40/d4;->i:Lh40/b4;

    .line 82
    .line 83
    goto :goto_8

    .line 84
    :cond_8
    move-object/from16 v10, p9

    .line 85
    .line 86
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 87
    .line 88
    if-eqz v11, :cond_9

    .line 89
    .line 90
    iget-object v11, v0, Lh40/d4;->j:Lh40/a4;

    .line 91
    .line 92
    goto :goto_9

    .line 93
    :cond_9
    move-object/from16 v11, p10

    .line 94
    .line 95
    :goto_9
    iget-object v12, v0, Lh40/d4;->k:Ljava/util/List;

    .line 96
    .line 97
    and-int/lit16 v13, v1, 0x800

    .line 98
    .line 99
    if-eqz v13, :cond_a

    .line 100
    .line 101
    iget-boolean v13, v0, Lh40/d4;->l:Z

    .line 102
    .line 103
    goto :goto_a

    .line 104
    :cond_a
    move/from16 v13, p11

    .line 105
    .line 106
    :goto_a
    and-int/lit16 v14, v1, 0x1000

    .line 107
    .line 108
    if-eqz v14, :cond_b

    .line 109
    .line 110
    iget-object v14, v0, Lh40/d4;->m:Ljava/lang/String;

    .line 111
    .line 112
    goto :goto_b

    .line 113
    :cond_b
    move-object/from16 v14, p12

    .line 114
    .line 115
    :goto_b
    and-int/lit16 v15, v1, 0x2000

    .line 116
    .line 117
    if-eqz v15, :cond_c

    .line 118
    .line 119
    iget-boolean v15, v0, Lh40/d4;->n:Z

    .line 120
    .line 121
    goto :goto_c

    .line 122
    :cond_c
    move/from16 v15, p13

    .line 123
    .line 124
    :goto_c
    move/from16 p1, v2

    .line 125
    .line 126
    and-int/lit16 v2, v1, 0x4000

    .line 127
    .line 128
    if-eqz v2, :cond_d

    .line 129
    .line 130
    iget-boolean v2, v0, Lh40/d4;->o:Z

    .line 131
    .line 132
    goto :goto_d

    .line 133
    :cond_d
    move/from16 v2, p14

    .line 134
    .line 135
    :goto_d
    const v16, 0x8000

    .line 136
    .line 137
    .line 138
    and-int v16, v1, v16

    .line 139
    .line 140
    if-eqz v16, :cond_e

    .line 141
    .line 142
    iget-object v1, v0, Lh40/d4;->p:Lql0/g;

    .line 143
    .line 144
    goto :goto_e

    .line 145
    :cond_e
    move-object/from16 v1, p15

    .line 146
    .line 147
    :goto_e
    const/high16 v16, 0x10000

    .line 148
    .line 149
    and-int v16, p20, v16

    .line 150
    .line 151
    move-object/from16 p2, v1

    .line 152
    .line 153
    if-eqz v16, :cond_f

    .line 154
    .line 155
    iget-boolean v1, v0, Lh40/d4;->q:Z

    .line 156
    .line 157
    goto :goto_f

    .line 158
    :cond_f
    move/from16 v1, p16

    .line 159
    .line 160
    :goto_f
    const/high16 v16, 0x20000

    .line 161
    .line 162
    and-int v16, p20, v16

    .line 163
    .line 164
    move/from16 p3, v1

    .line 165
    .line 166
    if-eqz v16, :cond_10

    .line 167
    .line 168
    iget-boolean v1, v0, Lh40/d4;->r:Z

    .line 169
    .line 170
    goto :goto_10

    .line 171
    :cond_10
    move/from16 v1, p17

    .line 172
    .line 173
    :goto_10
    const/high16 v16, 0x40000

    .line 174
    .line 175
    and-int v16, p20, v16

    .line 176
    .line 177
    move/from16 p4, v1

    .line 178
    .line 179
    if-eqz v16, :cond_11

    .line 180
    .line 181
    iget-boolean v1, v0, Lh40/d4;->s:Z

    .line 182
    .line 183
    goto :goto_11

    .line 184
    :cond_11
    move/from16 v1, p18

    .line 185
    .line 186
    :goto_11
    const/high16 v16, 0x80000

    .line 187
    .line 188
    and-int v16, p20, v16

    .line 189
    .line 190
    move/from16 p5, v1

    .line 191
    .line 192
    if-eqz v16, :cond_12

    .line 193
    .line 194
    iget-boolean v1, v0, Lh40/d4;->t:Z

    .line 195
    .line 196
    goto :goto_12

    .line 197
    :cond_12
    move/from16 v1, p19

    .line 198
    .line 199
    :goto_12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 200
    .line 201
    .line 202
    const-string v0, "activeRewards"

    .line 203
    .line 204
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    const-string v0, "redeemedRewards"

    .line 208
    .line 209
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    const-string v0, "availableRewards"

    .line 213
    .line 214
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    const-string v0, "gifts"

    .line 218
    .line 219
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    const-string v0, "giftTypeFilter"

    .line 223
    .line 224
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    const-string v0, "giftStatusFilter"

    .line 228
    .line 229
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    const-string v0, "typeFilters"

    .line 233
    .line 234
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    new-instance v0, Lh40/d4;

    .line 238
    .line 239
    move-object/from16 p16, p2

    .line 240
    .line 241
    move/from16 p17, p3

    .line 242
    .line 243
    move/from16 p18, p4

    .line 244
    .line 245
    move/from16 p19, p5

    .line 246
    .line 247
    move-object/from16 p0, v0

    .line 248
    .line 249
    move/from16 p20, v1

    .line 250
    .line 251
    move/from16 p15, v2

    .line 252
    .line 253
    move/from16 p2, v3

    .line 254
    .line 255
    move/from16 p3, v4

    .line 256
    .line 257
    move/from16 p4, v5

    .line 258
    .line 259
    move-object/from16 p5, v6

    .line 260
    .line 261
    move-object/from16 p6, v7

    .line 262
    .line 263
    move-object/from16 p7, v8

    .line 264
    .line 265
    move-object/from16 p8, v9

    .line 266
    .line 267
    move-object/from16 p9, v10

    .line 268
    .line 269
    move-object/from16 p10, v11

    .line 270
    .line 271
    move-object/from16 p11, v12

    .line 272
    .line 273
    move/from16 p12, v13

    .line 274
    .line 275
    move-object/from16 p13, v14

    .line 276
    .line 277
    move/from16 p14, v15

    .line 278
    .line 279
    invoke-direct/range {p0 .. p20}, Lh40/d4;-><init>(IZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lh40/b4;Lh40/a4;Ljava/util/List;ZLjava/lang/String;ZZLql0/g;ZZZZ)V

    .line 280
    .line 281
    .line 282
    return-object v0
.end method


# virtual methods
.method public final b()Ljava/util/ArrayList;
    .locals 4

    .line 1
    iget-object p0, p0, Lh40/d4;->h:Ljava/util/List;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/Iterable;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    move-object v2, v1

    .line 25
    check-cast v2, Lh40/c0;

    .line 26
    .line 27
    instance-of v3, v2, Lh40/x;

    .line 28
    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    instance-of v2, v2, Lh40/y;

    .line 32
    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    :cond_1
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    return-object v0
.end method

.method public final c()Ljava/util/ArrayList;
    .locals 4

    .line 1
    iget-object p0, p0, Lh40/d4;->h:Ljava/util/List;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/Iterable;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    move-object v2, v1

    .line 25
    check-cast v2, Lh40/c0;

    .line 26
    .line 27
    instance-of v3, v2, Lh40/a0;

    .line 28
    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    instance-of v2, v2, Lh40/b0;

    .line 32
    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    :cond_1
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    return-object v0
.end method

.method public final d()Ljava/util/List;
    .locals 4

    .line 1
    iget-object v0, p0, Lh40/d4;->i:Lh40/b4;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lh40/d4;->j:Lh40/a4;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    const/4 v3, 0x2

    .line 11
    if-eqz v0, :cond_11

    .line 12
    .line 13
    if-eq v0, v2, :cond_a

    .line 14
    .line 15
    if-ne v0, v3, :cond_9

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_6

    .line 22
    .line 23
    if-eq v0, v2, :cond_3

    .line 24
    .line 25
    if-ne v0, v3, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0}, Lh40/d4;->c()Ljava/util/ArrayList;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    new-instance v0, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    instance-of v2, v1, Lh40/b0;

    .line 51
    .line 52
    if-eqz v2, :cond_0

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    return-object v0

    .line 59
    :cond_2
    new-instance p0, La8/r0;

    .line 60
    .line 61
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_3
    invoke-virtual {p0}, Lh40/d4;->e()Ljava/util/ArrayList;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    new-instance v0, Ljava/util/ArrayList;

    .line 70
    .line 71
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    :cond_4
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_5

    .line 83
    .line 84
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    instance-of v2, v1, Lh40/z;

    .line 89
    .line 90
    if-eqz v2, :cond_4

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_5
    return-object v0

    .line 97
    :cond_6
    invoke-virtual {p0}, Lh40/d4;->b()Ljava/util/ArrayList;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    new-instance v0, Ljava/util/ArrayList;

    .line 102
    .line 103
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    :cond_7
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-eqz v1, :cond_8

    .line 115
    .line 116
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    instance-of v2, v1, Lh40/y;

    .line 121
    .line 122
    if-eqz v2, :cond_7

    .line 123
    .line 124
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_8
    return-object v0

    .line 129
    :cond_9
    new-instance p0, La8/r0;

    .line 130
    .line 131
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :cond_a
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    if-eqz v0, :cond_e

    .line 140
    .line 141
    if-eq v0, v3, :cond_b

    .line 142
    .line 143
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_b
    iget-object p0, p0, Lh40/d4;->f:Ljava/util/List;

    .line 147
    .line 148
    check-cast p0, Ljava/lang/Iterable;

    .line 149
    .line 150
    new-instance v0, Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 153
    .line 154
    .line 155
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    :cond_c
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    if-eqz v1, :cond_d

    .line 164
    .line 165
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v1

    .line 169
    instance-of v2, v1, Lh40/a0;

    .line 170
    .line 171
    if-eqz v2, :cond_c

    .line 172
    .line 173
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    goto :goto_3

    .line 177
    :cond_d
    return-object v0

    .line 178
    :cond_e
    iget-object p0, p0, Lh40/d4;->g:Ljava/util/List;

    .line 179
    .line 180
    check-cast p0, Ljava/lang/Iterable;

    .line 181
    .line 182
    new-instance v0, Ljava/util/ArrayList;

    .line 183
    .line 184
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 185
    .line 186
    .line 187
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    :cond_f
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    if-eqz v1, :cond_10

    .line 196
    .line 197
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    instance-of v2, v1, Lh40/x;

    .line 202
    .line 203
    if-eqz v2, :cond_f

    .line 204
    .line 205
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    goto :goto_4

    .line 209
    :cond_10
    return-object v0

    .line 210
    :cond_11
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 211
    .line 212
    .line 213
    move-result v0

    .line 214
    if-eqz v0, :cond_14

    .line 215
    .line 216
    if-eq v0, v2, :cond_13

    .line 217
    .line 218
    if-ne v0, v3, :cond_12

    .line 219
    .line 220
    invoke-virtual {p0}, Lh40/d4;->c()Ljava/util/ArrayList;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    return-object p0

    .line 225
    :cond_12
    new-instance p0, La8/r0;

    .line 226
    .line 227
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 228
    .line 229
    .line 230
    throw p0

    .line 231
    :cond_13
    invoke-virtual {p0}, Lh40/d4;->e()Ljava/util/ArrayList;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    return-object p0

    .line 236
    :cond_14
    invoke-virtual {p0}, Lh40/d4;->b()Ljava/util/ArrayList;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    return-object p0
.end method

.method public final e()Ljava/util/ArrayList;
    .locals 3

    .line 1
    iget-object p0, p0, Lh40/d4;->h:Ljava/util/List;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/Iterable;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    move-object v2, v1

    .line 25
    check-cast v2, Lh40/c0;

    .line 26
    .line 27
    instance-of v2, v2, Lh40/z;

    .line 28
    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lh40/d4;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lh40/d4;

    .line 12
    .line 13
    iget v1, p0, Lh40/d4;->a:I

    .line 14
    .line 15
    iget v3, p1, Lh40/d4;->a:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lh40/d4;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lh40/d4;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lh40/d4;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lh40/d4;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lh40/d4;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lh40/d4;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lh40/d4;->e:Ljava/util/List;

    .line 42
    .line 43
    iget-object v3, p1, Lh40/d4;->e:Ljava/util/List;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object v1, p0, Lh40/d4;->f:Ljava/util/List;

    .line 53
    .line 54
    iget-object v3, p1, Lh40/d4;->f:Ljava/util/List;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Lh40/d4;->g:Ljava/util/List;

    .line 64
    .line 65
    iget-object v3, p1, Lh40/d4;->g:Ljava/util/List;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Lh40/d4;->h:Ljava/util/List;

    .line 75
    .line 76
    iget-object v3, p1, Lh40/d4;->h:Ljava/util/List;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object v1, p0, Lh40/d4;->i:Lh40/b4;

    .line 86
    .line 87
    iget-object v3, p1, Lh40/d4;->i:Lh40/b4;

    .line 88
    .line 89
    if-eq v1, v3, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-object v1, p0, Lh40/d4;->j:Lh40/a4;

    .line 93
    .line 94
    iget-object v3, p1, Lh40/d4;->j:Lh40/a4;

    .line 95
    .line 96
    if-eq v1, v3, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-object v1, p0, Lh40/d4;->k:Ljava/util/List;

    .line 100
    .line 101
    iget-object v3, p1, Lh40/d4;->k:Ljava/util/List;

    .line 102
    .line 103
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    if-nez v1, :cond_c

    .line 108
    .line 109
    return v2

    .line 110
    :cond_c
    iget-boolean v1, p0, Lh40/d4;->l:Z

    .line 111
    .line 112
    iget-boolean v3, p1, Lh40/d4;->l:Z

    .line 113
    .line 114
    if-eq v1, v3, :cond_d

    .line 115
    .line 116
    return v2

    .line 117
    :cond_d
    iget-object v1, p0, Lh40/d4;->m:Ljava/lang/String;

    .line 118
    .line 119
    iget-object v3, p1, Lh40/d4;->m:Ljava/lang/String;

    .line 120
    .line 121
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    if-nez v1, :cond_e

    .line 126
    .line 127
    return v2

    .line 128
    :cond_e
    iget-boolean v1, p0, Lh40/d4;->n:Z

    .line 129
    .line 130
    iget-boolean v3, p1, Lh40/d4;->n:Z

    .line 131
    .line 132
    if-eq v1, v3, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-boolean v1, p0, Lh40/d4;->o:Z

    .line 136
    .line 137
    iget-boolean v3, p1, Lh40/d4;->o:Z

    .line 138
    .line 139
    if-eq v1, v3, :cond_10

    .line 140
    .line 141
    return v2

    .line 142
    :cond_10
    iget-object v1, p0, Lh40/d4;->p:Lql0/g;

    .line 143
    .line 144
    iget-object v3, p1, Lh40/d4;->p:Lql0/g;

    .line 145
    .line 146
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    if-nez v1, :cond_11

    .line 151
    .line 152
    return v2

    .line 153
    :cond_11
    iget-boolean v1, p0, Lh40/d4;->q:Z

    .line 154
    .line 155
    iget-boolean v3, p1, Lh40/d4;->q:Z

    .line 156
    .line 157
    if-eq v1, v3, :cond_12

    .line 158
    .line 159
    return v2

    .line 160
    :cond_12
    iget-boolean v1, p0, Lh40/d4;->r:Z

    .line 161
    .line 162
    iget-boolean v3, p1, Lh40/d4;->r:Z

    .line 163
    .line 164
    if-eq v1, v3, :cond_13

    .line 165
    .line 166
    return v2

    .line 167
    :cond_13
    iget-boolean v1, p0, Lh40/d4;->s:Z

    .line 168
    .line 169
    iget-boolean v3, p1, Lh40/d4;->s:Z

    .line 170
    .line 171
    if-eq v1, v3, :cond_14

    .line 172
    .line 173
    return v2

    .line 174
    :cond_14
    iget-boolean p0, p0, Lh40/d4;->t:Z

    .line 175
    .line 176
    iget-boolean p1, p1, Lh40/d4;->t:Z

    .line 177
    .line 178
    if-eq p0, p1, :cond_15

    .line 179
    .line 180
    return v2

    .line 181
    :cond_15
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lh40/d4;->a:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Lh40/d4;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lh40/d4;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lh40/d4;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lh40/d4;->e:Ljava/util/List;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lh40/d4;->f:Ljava/util/List;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lh40/d4;->g:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lh40/d4;->h:Ljava/util/List;

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Lh40/d4;->i:Lh40/b4;

    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    add-int/2addr v2, v0

    .line 59
    mul-int/2addr v2, v1

    .line 60
    iget-object v0, p0, Lh40/d4;->j:Lh40/a4;

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    add-int/2addr v0, v2

    .line 67
    mul-int/2addr v0, v1

    .line 68
    iget-object v2, p0, Lh40/d4;->k:Ljava/util/List;

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-boolean v2, p0, Lh40/d4;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    const/4 v2, 0x0

    .line 81
    iget-object v3, p0, Lh40/d4;->m:Ljava/lang/String;

    .line 82
    .line 83
    if-nez v3, :cond_0

    .line 84
    .line 85
    move v3, v2

    .line 86
    goto :goto_0

    .line 87
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    :goto_0
    add-int/2addr v0, v3

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-boolean v3, p0, Lh40/d4;->n:Z

    .line 94
    .line 95
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    iget-boolean v3, p0, Lh40/d4;->o:Z

    .line 100
    .line 101
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    iget-object v3, p0, Lh40/d4;->p:Lql0/g;

    .line 106
    .line 107
    if-nez v3, :cond_1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_1
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    :goto_1
    add-int/2addr v0, v2

    .line 115
    mul-int/2addr v0, v1

    .line 116
    iget-boolean v2, p0, Lh40/d4;->q:Z

    .line 117
    .line 118
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    iget-boolean v2, p0, Lh40/d4;->r:Z

    .line 123
    .line 124
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    iget-boolean v2, p0, Lh40/d4;->s:Z

    .line 129
    .line 130
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    iget-boolean p0, p0, Lh40/d4;->t:Z

    .line 135
    .line 136
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    add-int/2addr p0, v0

    .line 141
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(accountPointBalance="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lh40/d4;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isLoading="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lh40/d4;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isRefreshing="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isDataUnavailable="

    .line 29
    .line 30
    const-string v2, ", activeRewards="

    .line 31
    .line 32
    iget-boolean v3, p0, Lh40/d4;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lh40/d4;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", redeemedRewards="

    .line 40
    .line 41
    const-string v2, ", availableRewards="

    .line 42
    .line 43
    iget-object v3, p0, Lh40/d4;->e:Ljava/util/List;

    .line 44
    .line 45
    iget-object v4, p0, Lh40/d4;->f:Ljava/util/List;

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, ", gifts="

    .line 51
    .line 52
    const-string v2, ", giftTypeFilter="

    .line 53
    .line 54
    iget-object v3, p0, Lh40/d4;->g:Ljava/util/List;

    .line 55
    .line 56
    iget-object v4, p0, Lh40/d4;->h:Ljava/util/List;

    .line 57
    .line 58
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, p0, Lh40/d4;->i:Lh40/b4;

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", giftStatusFilter="

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Lh40/d4;->j:Lh40/a4;

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v1, ", typeFilters="

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", isMarkAsUsedDialogVisible="

    .line 82
    .line 83
    const-string v2, ", selectedRewardId="

    .line 84
    .line 85
    iget-object v3, p0, Lh40/d4;->k:Ljava/util/List;

    .line 86
    .line 87
    iget-boolean v4, p0, Lh40/d4;->l:Z

    .line 88
    .line 89
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v1, ", isDialogLoading="

    .line 93
    .line 94
    const-string v2, ", isForceRefreshing="

    .line 95
    .line 96
    iget-object v3, p0, Lh40/d4;->m:Ljava/lang/String;

    .line 97
    .line 98
    iget-boolean v4, p0, Lh40/d4;->n:Z

    .line 99
    .line 100
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 101
    .line 102
    .line 103
    iget-boolean v1, p0, Lh40/d4;->o:Z

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v1, ", error="

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    iget-object v1, p0, Lh40/d4;->p:Lql0/g;

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    const-string v1, ", isVoucherApplyDisabledDialogVisible="

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", isVoucherApplyConfirmationDialogVisible="

    .line 124
    .line 125
    const-string v2, ", isVoucherApplyNoCarDialogVisible="

    .line 126
    .line 127
    iget-boolean v3, p0, Lh40/d4;->q:Z

    .line 128
    .line 129
    iget-boolean v4, p0, Lh40/d4;->r:Z

    .line 130
    .line 131
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-string v1, ", isVoucherApplyIncompatibleCarDialogVisible="

    .line 135
    .line 136
    const-string v2, ")"

    .line 137
    .line 138
    iget-boolean v3, p0, Lh40/d4;->s:Z

    .line 139
    .line 140
    iget-boolean p0, p0, Lh40/d4;->t:Z

    .line 141
    .line 142
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    return-object p0
.end method
