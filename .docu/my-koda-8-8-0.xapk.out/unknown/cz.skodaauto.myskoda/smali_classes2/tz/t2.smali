.class public final Ltz/t2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Ljava/lang/String;

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Lrd0/d0;

.field public final k:Z

.field public final l:Z

.field public final m:Z

.field public final n:Z

.field public final o:Z

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Ljava/lang/String;

.field public final u:Z

.field public final v:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZI)V
    .locals 23

    const/high16 v0, 0x80000

    and-int v0, p3, v0

    .line 25
    const-string v3, ""

    if-eqz v0, :cond_0

    move-object/from16 v21, v3

    goto :goto_0

    :cond_0
    move-object/from16 v21, p1

    :goto_0
    const/high16 v0, 0x100000

    and-int v0, p3, v0

    if-eqz v0, :cond_1

    const/4 v0, 0x0

    move/from16 v22, v0

    goto :goto_1

    :cond_1
    move/from16 v22, p2

    :goto_1
    const/4 v2, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object v7, v3

    move-object/from16 v1, p0

    invoke-direct/range {v1 .. v22}, Ltz/t2;-><init>(ZLjava/lang/String;ZZZLjava/lang/String;ZZZLrd0/d0;ZZZZZZZZZLjava/lang/String;Z)V

    return-void
.end method

.method public constructor <init>(ZLjava/lang/String;ZZZLjava/lang/String;ZZZLrd0/d0;ZZZZZZZZZLjava/lang/String;Z)V
    .locals 2

    move-object/from16 v0, p20

    .line 1
    const-string v1, "plugAndCharge"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltz/t2;->a:Z

    .line 4
    iput-object p2, p0, Ltz/t2;->b:Ljava/lang/String;

    .line 5
    iput-boolean p3, p0, Ltz/t2;->c:Z

    .line 6
    iput-boolean p4, p0, Ltz/t2;->d:Z

    .line 7
    iput-boolean p5, p0, Ltz/t2;->e:Z

    .line 8
    iput-object p6, p0, Ltz/t2;->f:Ljava/lang/String;

    .line 9
    iput-boolean p7, p0, Ltz/t2;->g:Z

    .line 10
    iput-boolean p8, p0, Ltz/t2;->h:Z

    .line 11
    iput-boolean p9, p0, Ltz/t2;->i:Z

    .line 12
    iput-object p10, p0, Ltz/t2;->j:Lrd0/d0;

    .line 13
    iput-boolean p11, p0, Ltz/t2;->k:Z

    .line 14
    iput-boolean p12, p0, Ltz/t2;->l:Z

    .line 15
    iput-boolean p13, p0, Ltz/t2;->m:Z

    move/from16 p1, p14

    .line 16
    iput-boolean p1, p0, Ltz/t2;->n:Z

    move/from16 p1, p15

    .line 17
    iput-boolean p1, p0, Ltz/t2;->o:Z

    move/from16 p1, p16

    .line 18
    iput-boolean p1, p0, Ltz/t2;->p:Z

    move/from16 p1, p17

    .line 19
    iput-boolean p1, p0, Ltz/t2;->q:Z

    move/from16 p1, p18

    .line 20
    iput-boolean p1, p0, Ltz/t2;->r:Z

    move/from16 p1, p19

    .line 21
    iput-boolean p1, p0, Ltz/t2;->s:Z

    .line 22
    iput-object v0, p0, Ltz/t2;->t:Ljava/lang/String;

    move/from16 p1, p21

    .line 23
    iput-boolean p1, p0, Ltz/t2;->u:Z

    if-nez p10, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    .line 24
    :goto_0
    iput-boolean p1, p0, Ltz/t2;->v:Z

    return-void
.end method

.method public static a(Ltz/t2;ZLjava/lang/String;ZZZLjava/lang/String;ZZZLrd0/d0;ZZZZZZZZZLjava/lang/String;I)Ltz/t2;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p21

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-boolean v2, v0, Ltz/t2;->a:Z

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
    iget-object v3, v0, Ltz/t2;->b:Ljava/lang/String;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object/from16 v3, p2

    .line 22
    .line 23
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 24
    .line 25
    if-eqz v4, :cond_2

    .line 26
    .line 27
    iget-boolean v4, v0, Ltz/t2;->c:Z

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
    iget-boolean v5, v0, Ltz/t2;->d:Z

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
    iget-boolean v6, v0, Ltz/t2;->e:Z

    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move/from16 v6, p5

    .line 49
    .line 50
    :goto_4
    and-int/lit8 v7, v1, 0x20

    .line 51
    .line 52
    if-eqz v7, :cond_5

    .line 53
    .line 54
    iget-object v7, v0, Ltz/t2;->f:Ljava/lang/String;

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
    iget-boolean v8, v0, Ltz/t2;->g:Z

    .line 64
    .line 65
    goto :goto_6

    .line 66
    :cond_6
    move/from16 v8, p7

    .line 67
    .line 68
    :goto_6
    and-int/lit16 v9, v1, 0x80

    .line 69
    .line 70
    if-eqz v9, :cond_7

    .line 71
    .line 72
    iget-boolean v9, v0, Ltz/t2;->h:Z

    .line 73
    .line 74
    goto :goto_7

    .line 75
    :cond_7
    move/from16 v9, p8

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 78
    .line 79
    if-eqz v10, :cond_8

    .line 80
    .line 81
    iget-boolean v10, v0, Ltz/t2;->i:Z

    .line 82
    .line 83
    goto :goto_8

    .line 84
    :cond_8
    move/from16 v10, p9

    .line 85
    .line 86
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 87
    .line 88
    if-eqz v11, :cond_9

    .line 89
    .line 90
    iget-object v11, v0, Ltz/t2;->j:Lrd0/d0;

    .line 91
    .line 92
    goto :goto_9

    .line 93
    :cond_9
    move-object/from16 v11, p10

    .line 94
    .line 95
    :goto_9
    and-int/lit16 v12, v1, 0x400

    .line 96
    .line 97
    if-eqz v12, :cond_a

    .line 98
    .line 99
    iget-boolean v12, v0, Ltz/t2;->k:Z

    .line 100
    .line 101
    goto :goto_a

    .line 102
    :cond_a
    move/from16 v12, p11

    .line 103
    .line 104
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 105
    .line 106
    if-eqz v13, :cond_b

    .line 107
    .line 108
    iget-boolean v13, v0, Ltz/t2;->l:Z

    .line 109
    .line 110
    goto :goto_b

    .line 111
    :cond_b
    move/from16 v13, p12

    .line 112
    .line 113
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 114
    .line 115
    if-eqz v14, :cond_c

    .line 116
    .line 117
    iget-boolean v14, v0, Ltz/t2;->m:Z

    .line 118
    .line 119
    goto :goto_c

    .line 120
    :cond_c
    move/from16 v14, p13

    .line 121
    .line 122
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 123
    .line 124
    if-eqz v15, :cond_d

    .line 125
    .line 126
    iget-boolean v15, v0, Ltz/t2;->n:Z

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move/from16 v15, p14

    .line 130
    .line 131
    :goto_d
    move/from16 p1, v2

    .line 132
    .line 133
    and-int/lit16 v2, v1, 0x4000

    .line 134
    .line 135
    if-eqz v2, :cond_e

    .line 136
    .line 137
    iget-boolean v2, v0, Ltz/t2;->o:Z

    .line 138
    .line 139
    goto :goto_e

    .line 140
    :cond_e
    move/from16 v2, p15

    .line 141
    .line 142
    :goto_e
    const v16, 0x8000

    .line 143
    .line 144
    .line 145
    and-int v16, v1, v16

    .line 146
    .line 147
    if-eqz v16, :cond_f

    .line 148
    .line 149
    iget-boolean v1, v0, Ltz/t2;->p:Z

    .line 150
    .line 151
    goto :goto_f

    .line 152
    :cond_f
    move/from16 v1, p16

    .line 153
    .line 154
    :goto_f
    const/high16 v16, 0x10000

    .line 155
    .line 156
    and-int v16, p21, v16

    .line 157
    .line 158
    move/from16 p16, v1

    .line 159
    .line 160
    if-eqz v16, :cond_10

    .line 161
    .line 162
    iget-boolean v1, v0, Ltz/t2;->q:Z

    .line 163
    .line 164
    goto :goto_10

    .line 165
    :cond_10
    move/from16 v1, p17

    .line 166
    .line 167
    :goto_10
    const/high16 v16, 0x20000

    .line 168
    .line 169
    and-int v16, p21, v16

    .line 170
    .line 171
    move/from16 p17, v1

    .line 172
    .line 173
    if-eqz v16, :cond_11

    .line 174
    .line 175
    iget-boolean v1, v0, Ltz/t2;->r:Z

    .line 176
    .line 177
    goto :goto_11

    .line 178
    :cond_11
    move/from16 v1, p18

    .line 179
    .line 180
    :goto_11
    const/high16 v16, 0x40000

    .line 181
    .line 182
    and-int v16, p21, v16

    .line 183
    .line 184
    move/from16 p18, v1

    .line 185
    .line 186
    if-eqz v16, :cond_12

    .line 187
    .line 188
    iget-boolean v1, v0, Ltz/t2;->s:Z

    .line 189
    .line 190
    goto :goto_12

    .line 191
    :cond_12
    move/from16 v1, p19

    .line 192
    .line 193
    :goto_12
    const/high16 v16, 0x80000

    .line 194
    .line 195
    and-int v16, p21, v16

    .line 196
    .line 197
    move/from16 p19, v1

    .line 198
    .line 199
    if-eqz v16, :cond_13

    .line 200
    .line 201
    iget-object v1, v0, Ltz/t2;->t:Ljava/lang/String;

    .line 202
    .line 203
    goto :goto_13

    .line 204
    :cond_13
    move-object/from16 v1, p20

    .line 205
    .line 206
    :goto_13
    const/high16 v16, 0x100000

    .line 207
    .line 208
    and-int v16, p21, v16

    .line 209
    .line 210
    move/from16 p15, v2

    .line 211
    .line 212
    if-eqz v16, :cond_14

    .line 213
    .line 214
    iget-boolean v2, v0, Ltz/t2;->u:Z

    .line 215
    .line 216
    goto :goto_14

    .line 217
    :cond_14
    const/4 v2, 0x1

    .line 218
    :goto_14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    const-string v0, "batteryCareModeText"

    .line 222
    .line 223
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string v0, "chargeLimit"

    .line 227
    .line 228
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    const-string v0, "plugAndCharge"

    .line 232
    .line 233
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    new-instance v0, Ltz/t2;

    .line 237
    .line 238
    move-object/from16 p0, v0

    .line 239
    .line 240
    move-object/from16 p20, v1

    .line 241
    .line 242
    move/from16 p21, v2

    .line 243
    .line 244
    move-object/from16 p2, v3

    .line 245
    .line 246
    move/from16 p3, v4

    .line 247
    .line 248
    move/from16 p4, v5

    .line 249
    .line 250
    move/from16 p5, v6

    .line 251
    .line 252
    move-object/from16 p6, v7

    .line 253
    .line 254
    move/from16 p7, v8

    .line 255
    .line 256
    move/from16 p8, v9

    .line 257
    .line 258
    move/from16 p9, v10

    .line 259
    .line 260
    move-object/from16 p10, v11

    .line 261
    .line 262
    move/from16 p11, v12

    .line 263
    .line 264
    move/from16 p12, v13

    .line 265
    .line 266
    move/from16 p13, v14

    .line 267
    .line 268
    move/from16 p14, v15

    .line 269
    .line 270
    invoke-direct/range {p0 .. p21}, Ltz/t2;-><init>(ZLjava/lang/String;ZZZLjava/lang/String;ZZZLrd0/d0;ZZZZZZZZZLjava/lang/String;Z)V

    .line 271
    .line 272
    .line 273
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
    instance-of v1, p1, Ltz/t2;

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
    check-cast p1, Ltz/t2;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltz/t2;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltz/t2;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Ltz/t2;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Ltz/t2;->b:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Ltz/t2;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Ltz/t2;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Ltz/t2;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Ltz/t2;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Ltz/t2;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Ltz/t2;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object v1, p0, Ltz/t2;->f:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v3, p1, Ltz/t2;->f:Ljava/lang/String;

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
    iget-boolean v1, p0, Ltz/t2;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Ltz/t2;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-boolean v1, p0, Ltz/t2;->h:Z

    .line 71
    .line 72
    iget-boolean v3, p1, Ltz/t2;->h:Z

    .line 73
    .line 74
    if-eq v1, v3, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-boolean v1, p0, Ltz/t2;->i:Z

    .line 78
    .line 79
    iget-boolean v3, p1, Ltz/t2;->i:Z

    .line 80
    .line 81
    if-eq v1, v3, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-object v1, p0, Ltz/t2;->j:Lrd0/d0;

    .line 85
    .line 86
    iget-object v3, p1, Ltz/t2;->j:Lrd0/d0;

    .line 87
    .line 88
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-nez v1, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-boolean v1, p0, Ltz/t2;->k:Z

    .line 96
    .line 97
    iget-boolean v3, p1, Ltz/t2;->k:Z

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget-boolean v1, p0, Ltz/t2;->l:Z

    .line 103
    .line 104
    iget-boolean v3, p1, Ltz/t2;->l:Z

    .line 105
    .line 106
    if-eq v1, v3, :cond_d

    .line 107
    .line 108
    return v2

    .line 109
    :cond_d
    iget-boolean v1, p0, Ltz/t2;->m:Z

    .line 110
    .line 111
    iget-boolean v3, p1, Ltz/t2;->m:Z

    .line 112
    .line 113
    if-eq v1, v3, :cond_e

    .line 114
    .line 115
    return v2

    .line 116
    :cond_e
    iget-boolean v1, p0, Ltz/t2;->n:Z

    .line 117
    .line 118
    iget-boolean v3, p1, Ltz/t2;->n:Z

    .line 119
    .line 120
    if-eq v1, v3, :cond_f

    .line 121
    .line 122
    return v2

    .line 123
    :cond_f
    iget-boolean v1, p0, Ltz/t2;->o:Z

    .line 124
    .line 125
    iget-boolean v3, p1, Ltz/t2;->o:Z

    .line 126
    .line 127
    if-eq v1, v3, :cond_10

    .line 128
    .line 129
    return v2

    .line 130
    :cond_10
    iget-boolean v1, p0, Ltz/t2;->p:Z

    .line 131
    .line 132
    iget-boolean v3, p1, Ltz/t2;->p:Z

    .line 133
    .line 134
    if-eq v1, v3, :cond_11

    .line 135
    .line 136
    return v2

    .line 137
    :cond_11
    iget-boolean v1, p0, Ltz/t2;->q:Z

    .line 138
    .line 139
    iget-boolean v3, p1, Ltz/t2;->q:Z

    .line 140
    .line 141
    if-eq v1, v3, :cond_12

    .line 142
    .line 143
    return v2

    .line 144
    :cond_12
    iget-boolean v1, p0, Ltz/t2;->r:Z

    .line 145
    .line 146
    iget-boolean v3, p1, Ltz/t2;->r:Z

    .line 147
    .line 148
    if-eq v1, v3, :cond_13

    .line 149
    .line 150
    return v2

    .line 151
    :cond_13
    iget-boolean v1, p0, Ltz/t2;->s:Z

    .line 152
    .line 153
    iget-boolean v3, p1, Ltz/t2;->s:Z

    .line 154
    .line 155
    if-eq v1, v3, :cond_14

    .line 156
    .line 157
    return v2

    .line 158
    :cond_14
    iget-object v1, p0, Ltz/t2;->t:Ljava/lang/String;

    .line 159
    .line 160
    iget-object v3, p1, Ltz/t2;->t:Ljava/lang/String;

    .line 161
    .line 162
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    if-nez v1, :cond_15

    .line 167
    .line 168
    return v2

    .line 169
    :cond_15
    iget-boolean p0, p0, Ltz/t2;->u:Z

    .line 170
    .line 171
    iget-boolean p1, p1, Ltz/t2;->u:Z

    .line 172
    .line 173
    if-eq p0, p1, :cond_16

    .line 174
    .line 175
    return v2

    .line 176
    :cond_16
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltz/t2;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-object v2, p0, Ltz/t2;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltz/t2;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ltz/t2;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Ltz/t2;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Ltz/t2;->f:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Ltz/t2;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Ltz/t2;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Ltz/t2;->i:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object v2, p0, Ltz/t2;->j:Lrd0/d0;

    .line 59
    .line 60
    if-nez v2, :cond_0

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    goto :goto_0

    .line 64
    :cond_0
    iget v2, v2, Lrd0/d0;->a:I

    .line 65
    .line 66
    invoke-static {v2}, Ljava/lang/Integer;->hashCode(I)I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    :goto_0
    add-int/2addr v0, v2

    .line 71
    mul-int/2addr v0, v1

    .line 72
    iget-boolean v2, p0, Ltz/t2;->k:Z

    .line 73
    .line 74
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-boolean v2, p0, Ltz/t2;->l:Z

    .line 79
    .line 80
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    iget-boolean v2, p0, Ltz/t2;->m:Z

    .line 85
    .line 86
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    iget-boolean v2, p0, Ltz/t2;->n:Z

    .line 91
    .line 92
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    iget-boolean v2, p0, Ltz/t2;->o:Z

    .line 97
    .line 98
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    iget-boolean v2, p0, Ltz/t2;->p:Z

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    iget-boolean v2, p0, Ltz/t2;->q:Z

    .line 109
    .line 110
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    iget-boolean v2, p0, Ltz/t2;->r:Z

    .line 115
    .line 116
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    iget-boolean v2, p0, Ltz/t2;->s:Z

    .line 121
    .line 122
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    iget-object v2, p0, Ltz/t2;->t:Ljava/lang/String;

    .line 127
    .line 128
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    iget-boolean p0, p0, Ltz/t2;->u:Z

    .line 133
    .line 134
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    add-int/2addr p0, v0

    .line 139
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", batteryCareModeText="

    .line 2
    .line 3
    const-string v1, ", isBatteryCareModeLoading="

    .line 4
    .line 5
    const-string v2, "ChargeSettingsSection(isBatteryCareMode="

    .line 6
    .line 7
    iget-object v3, p0, Ltz/t2;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Ltz/t2;->a:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v3, v1, v4}, La7/g0;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isBatteryCareModeEnabled="

    .line 16
    .line 17
    const-string v2, ", isBatteryCareModeVisible="

    .line 18
    .line 19
    iget-boolean v3, p0, Ltz/t2;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Ltz/t2;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", chargeLimit="

    .line 27
    .line 28
    const-string v2, ", isChargeLimitVisible="

    .line 29
    .line 30
    iget-object v3, p0, Ltz/t2;->f:Ljava/lang/String;

    .line 31
    .line 32
    iget-boolean v4, p0, Ltz/t2;->e:Z

    .line 33
    .line 34
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", isChargeLimitLoading="

    .line 38
    .line 39
    const-string v2, ", isChargeLimitEnabled="

    .line 40
    .line 41
    iget-boolean v3, p0, Ltz/t2;->g:Z

    .line 42
    .line 43
    iget-boolean v4, p0, Ltz/t2;->h:Z

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Ltz/t2;->i:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", maxChargeCurrent="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Ltz/t2;->j:Lrd0/d0;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", isMaxChargeCurrentLoading="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ", isMaxChargeCurrentBottomSheetVisible="

    .line 69
    .line 70
    const-string v2, ", isCableLock="

    .line 71
    .line 72
    iget-boolean v3, p0, Ltz/t2;->k:Z

    .line 73
    .line 74
    iget-boolean v4, p0, Ltz/t2;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-string v1, ", isCableLockLoading="

    .line 80
    .line 81
    const-string v2, ", isCableLockEnabled="

    .line 82
    .line 83
    iget-boolean v3, p0, Ltz/t2;->m:Z

    .line 84
    .line 85
    iget-boolean v4, p0, Ltz/t2;->n:Z

    .line 86
    .line 87
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string v1, ", isCableLockVisible="

    .line 91
    .line 92
    const-string v2, ", isReducedCurrent="

    .line 93
    .line 94
    iget-boolean v3, p0, Ltz/t2;->o:Z

    .line 95
    .line 96
    iget-boolean v4, p0, Ltz/t2;->p:Z

    .line 97
    .line 98
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string v1, ", isReducedCurrentLoading="

    .line 102
    .line 103
    const-string v2, ", isReducedCurrentEnabled="

    .line 104
    .line 105
    iget-boolean v3, p0, Ltz/t2;->q:Z

    .line 106
    .line 107
    iget-boolean v4, p0, Ltz/t2;->r:Z

    .line 108
    .line 109
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string v1, ", plugAndCharge="

    .line 113
    .line 114
    const-string v2, ", isPlugAndChargeVisible="

    .line 115
    .line 116
    iget-object v3, p0, Ltz/t2;->t:Ljava/lang/String;

    .line 117
    .line 118
    iget-boolean v4, p0, Ltz/t2;->s:Z

    .line 119
    .line 120
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 121
    .line 122
    .line 123
    const-string v1, ")"

    .line 124
    .line 125
    iget-boolean p0, p0, Ltz/t2;->u:Z

    .line 126
    .line 127
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0
.end method
