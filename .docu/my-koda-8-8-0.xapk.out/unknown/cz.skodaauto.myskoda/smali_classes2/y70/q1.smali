.class public final Ly70/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Z

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/util/List;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Z

.field public final n:Ly70/p1;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:Z

.field public final v:Z


# direct methods
.method public constructor <init>(Lql0/g;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLy70/p1;Ljava/lang/String;Ljava/lang/String;ZZZZ)V
    .locals 1

    .line 1
    const-string v0, "serviceId"

    .line 2
    .line 3
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serviceName"

    .line 7
    .line 8
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "openingHours"

    .line 12
    .line 13
    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Ly70/q1;->a:Lql0/g;

    .line 20
    .line 21
    iput-boolean p2, p0, Ly70/q1;->b:Z

    .line 22
    .line 23
    iput-boolean p3, p0, Ly70/q1;->c:Z

    .line 24
    .line 25
    iput-object p4, p0, Ly70/q1;->d:Ljava/lang/String;

    .line 26
    .line 27
    iput-object p5, p0, Ly70/q1;->e:Ljava/lang/String;

    .line 28
    .line 29
    iput-object p6, p0, Ly70/q1;->f:Ljava/lang/String;

    .line 30
    .line 31
    iput-object p7, p0, Ly70/q1;->g:Ljava/lang/String;

    .line 32
    .line 33
    iput-object p8, p0, Ly70/q1;->h:Ljava/lang/String;

    .line 34
    .line 35
    iput-object p9, p0, Ly70/q1;->i:Ljava/util/List;

    .line 36
    .line 37
    iput-object p10, p0, Ly70/q1;->j:Ljava/lang/String;

    .line 38
    .line 39
    iput-object p11, p0, Ly70/q1;->k:Ljava/lang/String;

    .line 40
    .line 41
    iput-object p12, p0, Ly70/q1;->l:Ljava/lang/String;

    .line 42
    .line 43
    iput-boolean p13, p0, Ly70/q1;->m:Z

    .line 44
    .line 45
    iput-object p14, p0, Ly70/q1;->n:Ly70/p1;

    .line 46
    .line 47
    move-object/from16 p1, p15

    .line 48
    .line 49
    iput-object p1, p0, Ly70/q1;->o:Ljava/lang/String;

    .line 50
    .line 51
    move-object/from16 p1, p16

    .line 52
    .line 53
    iput-object p1, p0, Ly70/q1;->p:Ljava/lang/String;

    .line 54
    .line 55
    move/from16 p1, p17

    .line 56
    .line 57
    iput-boolean p1, p0, Ly70/q1;->q:Z

    .line 58
    .line 59
    move/from16 p1, p18

    .line 60
    .line 61
    iput-boolean p1, p0, Ly70/q1;->r:Z

    .line 62
    .line 63
    move/from16 p1, p19

    .line 64
    .line 65
    iput-boolean p1, p0, Ly70/q1;->s:Z

    .line 66
    .line 67
    move/from16 p1, p20

    .line 68
    .line 69
    iput-boolean p1, p0, Ly70/q1;->t:Z

    .line 70
    .line 71
    invoke-static/range {p4 .. p5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    iput-boolean p1, p0, Ly70/q1;->u:Z

    .line 76
    .line 77
    check-cast p9, Ljava/util/Collection;

    .line 78
    .line 79
    invoke-interface {p9}, Ljava/util/Collection;->isEmpty()Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    xor-int/lit8 p1, p1, 0x1

    .line 84
    .line 85
    iput-boolean p1, p0, Ly70/q1;->v:Z

    .line 86
    .line 87
    return-void
.end method

.method public static a(Ly70/q1;Lql0/g;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLy70/p1;Ljava/lang/String;Ljava/lang/String;ZZZZI)Ly70/q1;
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
    iget-object v2, v0, Ly70/q1;->a:Lql0/g;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object/from16 v2, p1

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    iget-boolean v3, v0, Ly70/q1;->b:Z

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    const/4 v3, 0x1

    .line 22
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 23
    .line 24
    if-eqz v4, :cond_2

    .line 25
    .line 26
    iget-boolean v4, v0, Ly70/q1;->c:Z

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move/from16 v4, p2

    .line 30
    .line 31
    :goto_2
    and-int/lit8 v5, v1, 0x8

    .line 32
    .line 33
    if-eqz v5, :cond_3

    .line 34
    .line 35
    iget-object v5, v0, Ly70/q1;->d:Ljava/lang/String;

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_3
    move-object/from16 v5, p3

    .line 39
    .line 40
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 41
    .line 42
    if-eqz v6, :cond_4

    .line 43
    .line 44
    iget-object v6, v0, Ly70/q1;->e:Ljava/lang/String;

    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_4
    move-object/from16 v6, p4

    .line 48
    .line 49
    :goto_4
    and-int/lit8 v7, v1, 0x20

    .line 50
    .line 51
    if-eqz v7, :cond_5

    .line 52
    .line 53
    iget-object v7, v0, Ly70/q1;->f:Ljava/lang/String;

    .line 54
    .line 55
    goto :goto_5

    .line 56
    :cond_5
    move-object/from16 v7, p5

    .line 57
    .line 58
    :goto_5
    and-int/lit8 v8, v1, 0x40

    .line 59
    .line 60
    if-eqz v8, :cond_6

    .line 61
    .line 62
    iget-object v8, v0, Ly70/q1;->g:Ljava/lang/String;

    .line 63
    .line 64
    goto :goto_6

    .line 65
    :cond_6
    move-object/from16 v8, p6

    .line 66
    .line 67
    :goto_6
    and-int/lit16 v9, v1, 0x80

    .line 68
    .line 69
    if-eqz v9, :cond_7

    .line 70
    .line 71
    iget-object v9, v0, Ly70/q1;->h:Ljava/lang/String;

    .line 72
    .line 73
    goto :goto_7

    .line 74
    :cond_7
    move-object/from16 v9, p7

    .line 75
    .line 76
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 77
    .line 78
    if-eqz v10, :cond_8

    .line 79
    .line 80
    iget-object v10, v0, Ly70/q1;->i:Ljava/util/List;

    .line 81
    .line 82
    goto :goto_8

    .line 83
    :cond_8
    move-object/from16 v10, p8

    .line 84
    .line 85
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 86
    .line 87
    if-eqz v11, :cond_9

    .line 88
    .line 89
    iget-object v11, v0, Ly70/q1;->j:Ljava/lang/String;

    .line 90
    .line 91
    goto :goto_9

    .line 92
    :cond_9
    move-object/from16 v11, p9

    .line 93
    .line 94
    :goto_9
    and-int/lit16 v12, v1, 0x400

    .line 95
    .line 96
    if-eqz v12, :cond_a

    .line 97
    .line 98
    iget-object v12, v0, Ly70/q1;->k:Ljava/lang/String;

    .line 99
    .line 100
    goto :goto_a

    .line 101
    :cond_a
    move-object/from16 v12, p10

    .line 102
    .line 103
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 104
    .line 105
    if-eqz v13, :cond_b

    .line 106
    .line 107
    iget-object v13, v0, Ly70/q1;->l:Ljava/lang/String;

    .line 108
    .line 109
    goto :goto_b

    .line 110
    :cond_b
    move-object/from16 v13, p11

    .line 111
    .line 112
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 113
    .line 114
    if-eqz v14, :cond_c

    .line 115
    .line 116
    iget-boolean v14, v0, Ly70/q1;->m:Z

    .line 117
    .line 118
    goto :goto_c

    .line 119
    :cond_c
    move/from16 v14, p12

    .line 120
    .line 121
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 122
    .line 123
    if-eqz v15, :cond_d

    .line 124
    .line 125
    iget-object v15, v0, Ly70/q1;->n:Ly70/p1;

    .line 126
    .line 127
    goto :goto_d

    .line 128
    :cond_d
    move-object/from16 v15, p13

    .line 129
    .line 130
    :goto_d
    move-object/from16 p1, v2

    .line 131
    .line 132
    and-int/lit16 v2, v1, 0x4000

    .line 133
    .line 134
    if-eqz v2, :cond_e

    .line 135
    .line 136
    iget-object v2, v0, Ly70/q1;->o:Ljava/lang/String;

    .line 137
    .line 138
    goto :goto_e

    .line 139
    :cond_e
    move-object/from16 v2, p14

    .line 140
    .line 141
    :goto_e
    const v16, 0x8000

    .line 142
    .line 143
    .line 144
    and-int v16, v1, v16

    .line 145
    .line 146
    if-eqz v16, :cond_f

    .line 147
    .line 148
    iget-object v1, v0, Ly70/q1;->p:Ljava/lang/String;

    .line 149
    .line 150
    goto :goto_f

    .line 151
    :cond_f
    move-object/from16 v1, p15

    .line 152
    .line 153
    :goto_f
    const/high16 v16, 0x10000

    .line 154
    .line 155
    and-int v16, p20, v16

    .line 156
    .line 157
    move-object/from16 p2, v1

    .line 158
    .line 159
    if-eqz v16, :cond_10

    .line 160
    .line 161
    iget-boolean v1, v0, Ly70/q1;->q:Z

    .line 162
    .line 163
    goto :goto_10

    .line 164
    :cond_10
    move/from16 v1, p16

    .line 165
    .line 166
    :goto_10
    const/high16 v16, 0x20000

    .line 167
    .line 168
    and-int v16, p20, v16

    .line 169
    .line 170
    move/from16 p3, v1

    .line 171
    .line 172
    if-eqz v16, :cond_11

    .line 173
    .line 174
    iget-boolean v1, v0, Ly70/q1;->r:Z

    .line 175
    .line 176
    goto :goto_11

    .line 177
    :cond_11
    move/from16 v1, p17

    .line 178
    .line 179
    :goto_11
    const/high16 v16, 0x40000

    .line 180
    .line 181
    and-int v16, p20, v16

    .line 182
    .line 183
    move/from16 p4, v1

    .line 184
    .line 185
    if-eqz v16, :cond_12

    .line 186
    .line 187
    iget-boolean v1, v0, Ly70/q1;->s:Z

    .line 188
    .line 189
    goto :goto_12

    .line 190
    :cond_12
    move/from16 v1, p18

    .line 191
    .line 192
    :goto_12
    const/high16 v16, 0x80000

    .line 193
    .line 194
    and-int v16, p20, v16

    .line 195
    .line 196
    move/from16 p5, v1

    .line 197
    .line 198
    if-eqz v16, :cond_13

    .line 199
    .line 200
    iget-boolean v1, v0, Ly70/q1;->t:Z

    .line 201
    .line 202
    goto :goto_13

    .line 203
    :cond_13
    move/from16 v1, p19

    .line 204
    .line 205
    :goto_13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    const-string v0, "serviceId"

    .line 209
    .line 210
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    const-string v0, "serviceName"

    .line 214
    .line 215
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    const-string v0, "openingHours"

    .line 219
    .line 220
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    new-instance v0, Ly70/q1;

    .line 224
    .line 225
    move-object/from16 p16, p2

    .line 226
    .line 227
    move/from16 p17, p3

    .line 228
    .line 229
    move/from16 p18, p4

    .line 230
    .line 231
    move/from16 p19, p5

    .line 232
    .line 233
    move-object/from16 p0, v0

    .line 234
    .line 235
    move/from16 p20, v1

    .line 236
    .line 237
    move-object/from16 p15, v2

    .line 238
    .line 239
    move/from16 p2, v3

    .line 240
    .line 241
    move/from16 p3, v4

    .line 242
    .line 243
    move-object/from16 p4, v5

    .line 244
    .line 245
    move-object/from16 p5, v6

    .line 246
    .line 247
    move-object/from16 p6, v7

    .line 248
    .line 249
    move-object/from16 p7, v8

    .line 250
    .line 251
    move-object/from16 p8, v9

    .line 252
    .line 253
    move-object/from16 p9, v10

    .line 254
    .line 255
    move-object/from16 p10, v11

    .line 256
    .line 257
    move-object/from16 p11, v12

    .line 258
    .line 259
    move-object/from16 p12, v13

    .line 260
    .line 261
    move/from16 p13, v14

    .line 262
    .line 263
    move-object/from16 p14, v15

    .line 264
    .line 265
    invoke-direct/range {p0 .. p20}, Ly70/q1;-><init>(Lql0/g;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLy70/p1;Ljava/lang/String;Ljava/lang/String;ZZZZ)V

    .line 266
    .line 267
    .line 268
    return-object v0
.end method


# virtual methods
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
    instance-of v1, p1, Ly70/q1;

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
    check-cast p1, Ly70/q1;

    .line 12
    .line 13
    iget-object v1, p0, Ly70/q1;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Ly70/q1;->a:Lql0/g;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-boolean v1, p0, Ly70/q1;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Ly70/q1;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Ly70/q1;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Ly70/q1;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Ly70/q1;->d:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v3, p1, Ly70/q1;->d:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Ly70/q1;->e:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v3, p1, Ly70/q1;->e:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Ly70/q1;->f:Ljava/lang/String;

    .line 61
    .line 62
    iget-object v3, p1, Ly70/q1;->f:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object v1, p0, Ly70/q1;->g:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v3, p1, Ly70/q1;->g:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-nez v1, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Ly70/q1;->h:Ljava/lang/String;

    .line 83
    .line 84
    iget-object v3, p1, Ly70/q1;->h:Ljava/lang/String;

    .line 85
    .line 86
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-nez v1, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-object v1, p0, Ly70/q1;->i:Ljava/util/List;

    .line 94
    .line 95
    iget-object v3, p1, Ly70/q1;->i:Ljava/util/List;

    .line 96
    .line 97
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-object v1, p0, Ly70/q1;->j:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v3, p1, Ly70/q1;->j:Ljava/lang/String;

    .line 107
    .line 108
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_b

    .line 113
    .line 114
    return v2

    .line 115
    :cond_b
    iget-object v1, p0, Ly70/q1;->k:Ljava/lang/String;

    .line 116
    .line 117
    iget-object v3, p1, Ly70/q1;->k:Ljava/lang/String;

    .line 118
    .line 119
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    if-nez v1, :cond_c

    .line 124
    .line 125
    return v2

    .line 126
    :cond_c
    iget-object v1, p0, Ly70/q1;->l:Ljava/lang/String;

    .line 127
    .line 128
    iget-object v3, p1, Ly70/q1;->l:Ljava/lang/String;

    .line 129
    .line 130
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-nez v1, :cond_d

    .line 135
    .line 136
    return v2

    .line 137
    :cond_d
    iget-boolean v1, p0, Ly70/q1;->m:Z

    .line 138
    .line 139
    iget-boolean v3, p1, Ly70/q1;->m:Z

    .line 140
    .line 141
    if-eq v1, v3, :cond_e

    .line 142
    .line 143
    return v2

    .line 144
    :cond_e
    iget-object v1, p0, Ly70/q1;->n:Ly70/p1;

    .line 145
    .line 146
    iget-object v3, p1, Ly70/q1;->n:Ly70/p1;

    .line 147
    .line 148
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-nez v1, :cond_f

    .line 153
    .line 154
    return v2

    .line 155
    :cond_f
    iget-object v1, p0, Ly70/q1;->o:Ljava/lang/String;

    .line 156
    .line 157
    iget-object v3, p1, Ly70/q1;->o:Ljava/lang/String;

    .line 158
    .line 159
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    if-nez v1, :cond_10

    .line 164
    .line 165
    return v2

    .line 166
    :cond_10
    iget-object v1, p0, Ly70/q1;->p:Ljava/lang/String;

    .line 167
    .line 168
    iget-object v3, p1, Ly70/q1;->p:Ljava/lang/String;

    .line 169
    .line 170
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-nez v1, :cond_11

    .line 175
    .line 176
    return v2

    .line 177
    :cond_11
    iget-boolean v1, p0, Ly70/q1;->q:Z

    .line 178
    .line 179
    iget-boolean v3, p1, Ly70/q1;->q:Z

    .line 180
    .line 181
    if-eq v1, v3, :cond_12

    .line 182
    .line 183
    return v2

    .line 184
    :cond_12
    iget-boolean v1, p0, Ly70/q1;->r:Z

    .line 185
    .line 186
    iget-boolean v3, p1, Ly70/q1;->r:Z

    .line 187
    .line 188
    if-eq v1, v3, :cond_13

    .line 189
    .line 190
    return v2

    .line 191
    :cond_13
    iget-boolean v1, p0, Ly70/q1;->s:Z

    .line 192
    .line 193
    iget-boolean v3, p1, Ly70/q1;->s:Z

    .line 194
    .line 195
    if-eq v1, v3, :cond_14

    .line 196
    .line 197
    return v2

    .line 198
    :cond_14
    iget-boolean p0, p0, Ly70/q1;->t:Z

    .line 199
    .line 200
    iget-boolean p1, p1, Ly70/q1;->t:Z

    .line 201
    .line 202
    if-eq p0, p1, :cond_15

    .line 203
    .line 204
    return v2

    .line 205
    :cond_15
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ly70/q1;->a:Lql0/g;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Lql0/g;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-boolean v3, p0, Ly70/q1;->b:Z

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-boolean v3, p0, Ly70/q1;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-object v3, p0, Ly70/q1;->d:Ljava/lang/String;

    .line 28
    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    move v3, v0

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    :goto_1
    add-int/2addr v1, v3

    .line 38
    mul-int/2addr v1, v2

    .line 39
    iget-object v3, p0, Ly70/q1;->e:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iget-object v3, p0, Ly70/q1;->f:Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    iget-object v3, p0, Ly70/q1;->g:Ljava/lang/String;

    .line 52
    .line 53
    if-nez v3, :cond_2

    .line 54
    .line 55
    move v3, v0

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    :goto_2
    add-int/2addr v1, v3

    .line 62
    mul-int/2addr v1, v2

    .line 63
    iget-object v3, p0, Ly70/q1;->h:Ljava/lang/String;

    .line 64
    .line 65
    if-nez v3, :cond_3

    .line 66
    .line 67
    move v3, v0

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    :goto_3
    add-int/2addr v1, v3

    .line 74
    mul-int/2addr v1, v2

    .line 75
    iget-object v3, p0, Ly70/q1;->i:Ljava/util/List;

    .line 76
    .line 77
    invoke-static {v1, v2, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    iget-object v3, p0, Ly70/q1;->j:Ljava/lang/String;

    .line 82
    .line 83
    if-nez v3, :cond_4

    .line 84
    .line 85
    move v3, v0

    .line 86
    goto :goto_4

    .line 87
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    :goto_4
    add-int/2addr v1, v3

    .line 92
    mul-int/2addr v1, v2

    .line 93
    iget-object v3, p0, Ly70/q1;->k:Ljava/lang/String;

    .line 94
    .line 95
    if-nez v3, :cond_5

    .line 96
    .line 97
    move v3, v0

    .line 98
    goto :goto_5

    .line 99
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    :goto_5
    add-int/2addr v1, v3

    .line 104
    mul-int/2addr v1, v2

    .line 105
    iget-object v3, p0, Ly70/q1;->l:Ljava/lang/String;

    .line 106
    .line 107
    if-nez v3, :cond_6

    .line 108
    .line 109
    move v3, v0

    .line 110
    goto :goto_6

    .line 111
    :cond_6
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    :goto_6
    add-int/2addr v1, v3

    .line 116
    mul-int/2addr v1, v2

    .line 117
    iget-boolean v3, p0, Ly70/q1;->m:Z

    .line 118
    .line 119
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    iget-object v3, p0, Ly70/q1;->n:Ly70/p1;

    .line 124
    .line 125
    if-nez v3, :cond_7

    .line 126
    .line 127
    move v3, v0

    .line 128
    goto :goto_7

    .line 129
    :cond_7
    invoke-virtual {v3}, Ly70/p1;->hashCode()I

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    :goto_7
    add-int/2addr v1, v3

    .line 134
    mul-int/2addr v1, v2

    .line 135
    iget-object v3, p0, Ly70/q1;->o:Ljava/lang/String;

    .line 136
    .line 137
    if-nez v3, :cond_8

    .line 138
    .line 139
    move v3, v0

    .line 140
    goto :goto_8

    .line 141
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    :goto_8
    add-int/2addr v1, v3

    .line 146
    mul-int/2addr v1, v2

    .line 147
    iget-object v3, p0, Ly70/q1;->p:Ljava/lang/String;

    .line 148
    .line 149
    if-nez v3, :cond_9

    .line 150
    .line 151
    goto :goto_9

    .line 152
    :cond_9
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    :goto_9
    add-int/2addr v1, v0

    .line 157
    mul-int/2addr v1, v2

    .line 158
    iget-boolean v0, p0, Ly70/q1;->q:Z

    .line 159
    .line 160
    invoke-static {v1, v2, v0}, La7/g0;->e(IIZ)I

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    iget-boolean v1, p0, Ly70/q1;->r:Z

    .line 165
    .line 166
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    iget-boolean v1, p0, Ly70/q1;->s:Z

    .line 171
    .line 172
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    iget-boolean p0, p0, Ly70/q1;->t:Z

    .line 177
    .line 178
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    add-int/2addr p0, v0

    .line 183
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isFatalError="

    .line 2
    .line 3
    const-string v1, ", isLoading="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Ly70/q1;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Ly70/q1;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", servicePartnerId="

    .line 16
    .line 17
    const-string v2, ", serviceId="

    .line 18
    .line 19
    iget-object v3, p0, Ly70/q1;->d:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Ly70/q1;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", serviceName="

    .line 27
    .line 28
    const-string v2, ", servicePartnerCountryCode="

    .line 29
    .line 30
    iget-object v3, p0, Ly70/q1;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Ly70/q1;->f:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", address="

    .line 38
    .line 39
    const-string v2, ", openingHours="

    .line 40
    .line 41
    iget-object v3, p0, Ly70/q1;->g:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v4, p0, Ly70/q1;->h:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Ly70/q1;->i:Ljava/util/List;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", phone="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Ly70/q1;->j:Ljava/lang/String;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", website="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ", email="

    .line 69
    .line 70
    const-string v2, ", isSelectServiceDialogVisible="

    .line 71
    .line 72
    iget-object v3, p0, Ly70/q1;->k:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v4, p0, Ly70/q1;->l:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-boolean v1, p0, Ly70/q1;->m:Z

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", marketSpecificState="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object v1, p0, Ly70/q1;->n:Ly70/p1;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v1, ", userCountryCode="

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ", userCountryCodeAlpha3="

    .line 100
    .line 101
    const-string v2, ", shouldGoBackOnServiceSelection="

    .line 102
    .line 103
    iget-object v3, p0, Ly70/q1;->o:Ljava/lang/String;

    .line 104
    .line 105
    iget-object v4, p0, Ly70/q1;->p:Ljava/lang/String;

    .line 106
    .line 107
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    const-string v1, ", isRequestBookingButtonEnabled="

    .line 111
    .line 112
    const-string v2, ", isRemovePartnerButtonEnabled="

    .line 113
    .line 114
    iget-boolean v3, p0, Ly70/q1;->q:Z

    .line 115
    .line 116
    iget-boolean v4, p0, Ly70/q1;->r:Z

    .line 117
    .line 118
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 119
    .line 120
    .line 121
    const-string v1, ", isAdmEnabled="

    .line 122
    .line 123
    const-string v2, ")"

    .line 124
    .line 125
    iget-boolean v3, p0, Ly70/q1;->s:Z

    .line 126
    .line 127
    iget-boolean p0, p0, Ly70/q1;->t:Z

    .line 128
    .line 129
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    return-object p0
.end method
