.class public final Ltz/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ltz/g;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:Z

.field public final e:Llf0/i;

.field public final f:Ltz/h;

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Lqr0/l;

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z


# direct methods
.method public constructor <init>(Ltz/g;Ljava/lang/String;ZZLlf0/i;Ltz/h;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/l;ZZZZZ)V
    .locals 1

    const-string v0, "chargingState"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewMode"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltz/i;->a:Ltz/g;

    .line 3
    iput-object p2, p0, Ltz/i;->b:Ljava/lang/String;

    .line 4
    iput-boolean p3, p0, Ltz/i;->c:Z

    .line 5
    iput-boolean p4, p0, Ltz/i;->d:Z

    .line 6
    iput-object p5, p0, Ltz/i;->e:Llf0/i;

    .line 7
    iput-object p6, p0, Ltz/i;->f:Ltz/h;

    .line 8
    iput-boolean p7, p0, Ltz/i;->g:Z

    .line 9
    iput-boolean p8, p0, Ltz/i;->h:Z

    .line 10
    iput-boolean p9, p0, Ltz/i;->i:Z

    .line 11
    iput-boolean p10, p0, Ltz/i;->j:Z

    .line 12
    iput-object p11, p0, Ltz/i;->k:Ljava/lang/String;

    .line 13
    iput-object p12, p0, Ltz/i;->l:Ljava/lang/String;

    .line 14
    iput-object p13, p0, Ltz/i;->m:Ljava/lang/String;

    .line 15
    iput-object p14, p0, Ltz/i;->n:Ljava/lang/String;

    move-object/from16 p1, p15

    .line 16
    iput-object p1, p0, Ltz/i;->o:Lqr0/l;

    move/from16 p1, p16

    .line 17
    iput-boolean p1, p0, Ltz/i;->p:Z

    move/from16 p1, p17

    .line 18
    iput-boolean p1, p0, Ltz/i;->q:Z

    move/from16 p1, p18

    .line 19
    iput-boolean p1, p0, Ltz/i;->r:Z

    move/from16 p1, p19

    .line 20
    iput-boolean p1, p0, Ltz/i;->s:Z

    move/from16 p1, p20

    .line 21
    iput-boolean p1, p0, Ltz/i;->t:Z

    return-void
.end method

.method public synthetic constructor <init>(Ltz/g;Llf0/i;Ltz/h;ZI)V
    .locals 23

    and-int/lit8 v0, p5, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move-object v3, v1

    goto :goto_0

    :cond_0
    move-object/from16 v3, p1

    :goto_0
    and-int/lit8 v0, p5, 0x4

    const/4 v2, 0x1

    const/4 v4, 0x0

    if-eqz v0, :cond_1

    move v5, v4

    goto :goto_1

    :cond_1
    move v5, v2

    :goto_1
    and-int/lit8 v0, p5, 0x8

    if-eqz v0, :cond_2

    move v6, v2

    goto :goto_2

    :cond_2
    move v6, v4

    :goto_2
    and-int/lit8 v0, p5, 0x10

    if-eqz v0, :cond_3

    .line 22
    sget-object v0, Llf0/i;->j:Llf0/i;

    move-object v7, v0

    goto :goto_3

    :cond_3
    move-object/from16 v7, p2

    :goto_3
    and-int/lit8 v0, p5, 0x20

    if-eqz v0, :cond_4

    move-object v8, v1

    goto :goto_4

    :cond_4
    move-object/from16 v8, p3

    :goto_4
    const/high16 v0, 0x10000

    and-int v0, p5, v0

    if-eqz v0, :cond_5

    move/from16 v19, v4

    goto :goto_5

    :cond_5
    move/from16 v19, p4

    :goto_5
    const/16 v21, 0x0

    const/16 v22, 0x0

    .line 23
    const-string v4, ""

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

    const/16 v20, 0x0

    move-object/from16 v2, p0

    invoke-direct/range {v2 .. v22}, Ltz/i;-><init>(Ltz/g;Ljava/lang/String;ZZLlf0/i;Ltz/h;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/l;ZZZZZ)V

    return-void
.end method

.method public static a(Ltz/i;Ltz/g;Ljava/lang/String;ZZLlf0/i;Ltz/h;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/l;ZZZZZI)Ltz/i;
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
    iget-object v2, v0, Ltz/i;->a:Ltz/g;

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
    iget-object v3, v0, Ltz/i;->b:Ljava/lang/String;

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
    iget-boolean v4, v0, Ltz/i;->c:Z

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
    iget-boolean v5, v0, Ltz/i;->d:Z

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
    iget-object v6, v0, Ltz/i;->e:Llf0/i;

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
    iget-object v7, v0, Ltz/i;->f:Ltz/h;

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
    iget-boolean v8, v0, Ltz/i;->g:Z

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
    iget-boolean v9, v0, Ltz/i;->h:Z

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
    iget-boolean v10, v0, Ltz/i;->i:Z

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
    iget-boolean v11, v0, Ltz/i;->j:Z

    .line 91
    .line 92
    goto :goto_9

    .line 93
    :cond_9
    move/from16 v11, p10

    .line 94
    .line 95
    :goto_9
    and-int/lit16 v12, v1, 0x400

    .line 96
    .line 97
    if-eqz v12, :cond_a

    .line 98
    .line 99
    iget-object v12, v0, Ltz/i;->k:Ljava/lang/String;

    .line 100
    .line 101
    goto :goto_a

    .line 102
    :cond_a
    move-object/from16 v12, p11

    .line 103
    .line 104
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 105
    .line 106
    if-eqz v13, :cond_b

    .line 107
    .line 108
    iget-object v13, v0, Ltz/i;->l:Ljava/lang/String;

    .line 109
    .line 110
    goto :goto_b

    .line 111
    :cond_b
    move-object/from16 v13, p12

    .line 112
    .line 113
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 114
    .line 115
    if-eqz v14, :cond_c

    .line 116
    .line 117
    iget-object v14, v0, Ltz/i;->m:Ljava/lang/String;

    .line 118
    .line 119
    goto :goto_c

    .line 120
    :cond_c
    move-object/from16 v14, p13

    .line 121
    .line 122
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 123
    .line 124
    if-eqz v15, :cond_d

    .line 125
    .line 126
    iget-object v15, v0, Ltz/i;->n:Ljava/lang/String;

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move-object/from16 v15, p14

    .line 130
    .line 131
    :goto_d
    move-object/from16 p1, v2

    .line 132
    .line 133
    and-int/lit16 v2, v1, 0x4000

    .line 134
    .line 135
    if-eqz v2, :cond_e

    .line 136
    .line 137
    iget-object v2, v0, Ltz/i;->o:Lqr0/l;

    .line 138
    .line 139
    goto :goto_e

    .line 140
    :cond_e
    move-object/from16 v2, p15

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
    iget-boolean v1, v0, Ltz/i;->p:Z

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
    iget-boolean v1, v0, Ltz/i;->q:Z

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
    iget-boolean v1, v0, Ltz/i;->r:Z

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
    iget-boolean v1, v0, Ltz/i;->s:Z

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
    iget-boolean v1, v0, Ltz/i;->t:Z

    .line 202
    .line 203
    goto :goto_13

    .line 204
    :cond_13
    move/from16 v1, p20

    .line 205
    .line 206
    :goto_13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 207
    .line 208
    .line 209
    const-string v0, "chargingState"

    .line 210
    .line 211
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    const-string v0, "viewMode"

    .line 215
    .line 216
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    new-instance v0, Ltz/i;

    .line 220
    .line 221
    move-object/from16 p0, v0

    .line 222
    .line 223
    move/from16 p20, v1

    .line 224
    .line 225
    move-object/from16 p15, v2

    .line 226
    .line 227
    move-object/from16 p2, v3

    .line 228
    .line 229
    move/from16 p3, v4

    .line 230
    .line 231
    move/from16 p4, v5

    .line 232
    .line 233
    move-object/from16 p5, v6

    .line 234
    .line 235
    move-object/from16 p6, v7

    .line 236
    .line 237
    move/from16 p7, v8

    .line 238
    .line 239
    move/from16 p8, v9

    .line 240
    .line 241
    move/from16 p9, v10

    .line 242
    .line 243
    move/from16 p10, v11

    .line 244
    .line 245
    move-object/from16 p11, v12

    .line 246
    .line 247
    move-object/from16 p12, v13

    .line 248
    .line 249
    move-object/from16 p13, v14

    .line 250
    .line 251
    move-object/from16 p14, v15

    .line 252
    .line 253
    invoke-direct/range {p0 .. p20}, Ltz/i;-><init>(Ltz/g;Ljava/lang/String;ZZLlf0/i;Ltz/h;ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/l;ZZZZZ)V

    .line 254
    .line 255
    .line 256
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
    instance-of v1, p1, Ltz/i;

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
    check-cast p1, Ltz/i;

    .line 12
    .line 13
    iget-object v1, p0, Ltz/i;->a:Ltz/g;

    .line 14
    .line 15
    iget-object v3, p1, Ltz/i;->a:Ltz/g;

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
    iget-object v1, p0, Ltz/i;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ltz/i;->b:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-boolean v1, p0, Ltz/i;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Ltz/i;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-boolean v1, p0, Ltz/i;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Ltz/i;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Ltz/i;->e:Llf0/i;

    .line 50
    .line 51
    iget-object v3, p1, Ltz/i;->e:Llf0/i;

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Ltz/i;->f:Ltz/h;

    .line 57
    .line 58
    iget-object v3, p1, Ltz/i;->f:Ltz/h;

    .line 59
    .line 60
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-nez v1, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Ltz/i;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Ltz/i;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean v1, p0, Ltz/i;->h:Z

    .line 75
    .line 76
    iget-boolean v3, p1, Ltz/i;->h:Z

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-boolean v1, p0, Ltz/i;->i:Z

    .line 82
    .line 83
    iget-boolean v3, p1, Ltz/i;->i:Z

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-boolean v1, p0, Ltz/i;->j:Z

    .line 89
    .line 90
    iget-boolean v3, p1, Ltz/i;->j:Z

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-object v1, p0, Ltz/i;->k:Ljava/lang/String;

    .line 96
    .line 97
    iget-object v3, p1, Ltz/i;->k:Ljava/lang/String;

    .line 98
    .line 99
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-nez v1, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    iget-object v1, p0, Ltz/i;->l:Ljava/lang/String;

    .line 107
    .line 108
    iget-object v3, p1, Ltz/i;->l:Ljava/lang/String;

    .line 109
    .line 110
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-nez v1, :cond_d

    .line 115
    .line 116
    return v2

    .line 117
    :cond_d
    iget-object v1, p0, Ltz/i;->m:Ljava/lang/String;

    .line 118
    .line 119
    iget-object v3, p1, Ltz/i;->m:Ljava/lang/String;

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
    iget-object v1, p0, Ltz/i;->n:Ljava/lang/String;

    .line 129
    .line 130
    iget-object v3, p1, Ltz/i;->n:Ljava/lang/String;

    .line 131
    .line 132
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    if-nez v1, :cond_f

    .line 137
    .line 138
    return v2

    .line 139
    :cond_f
    iget-object v1, p0, Ltz/i;->o:Lqr0/l;

    .line 140
    .line 141
    iget-object v3, p1, Ltz/i;->o:Lqr0/l;

    .line 142
    .line 143
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v1

    .line 147
    if-nez v1, :cond_10

    .line 148
    .line 149
    return v2

    .line 150
    :cond_10
    iget-boolean v1, p0, Ltz/i;->p:Z

    .line 151
    .line 152
    iget-boolean v3, p1, Ltz/i;->p:Z

    .line 153
    .line 154
    if-eq v1, v3, :cond_11

    .line 155
    .line 156
    return v2

    .line 157
    :cond_11
    iget-boolean v1, p0, Ltz/i;->q:Z

    .line 158
    .line 159
    iget-boolean v3, p1, Ltz/i;->q:Z

    .line 160
    .line 161
    if-eq v1, v3, :cond_12

    .line 162
    .line 163
    return v2

    .line 164
    :cond_12
    iget-boolean v1, p0, Ltz/i;->r:Z

    .line 165
    .line 166
    iget-boolean v3, p1, Ltz/i;->r:Z

    .line 167
    .line 168
    if-eq v1, v3, :cond_13

    .line 169
    .line 170
    return v2

    .line 171
    :cond_13
    iget-boolean v1, p0, Ltz/i;->s:Z

    .line 172
    .line 173
    iget-boolean v3, p1, Ltz/i;->s:Z

    .line 174
    .line 175
    if-eq v1, v3, :cond_14

    .line 176
    .line 177
    return v2

    .line 178
    :cond_14
    iget-boolean p0, p0, Ltz/i;->t:Z

    .line 179
    .line 180
    iget-boolean p1, p1, Ltz/i;->t:Z

    .line 181
    .line 182
    if-eq p0, p1, :cond_15

    .line 183
    .line 184
    return v2

    .line 185
    :cond_15
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ltz/i;->a:Ltz/g;

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
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

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
    iget-object v3, p0, Ltz/i;->b:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-boolean v3, p0, Ltz/i;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-boolean v3, p0, Ltz/i;->d:Z

    .line 28
    .line 29
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-object v3, p0, Ltz/i;->e:Llf0/i;

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    add-int/2addr v3, v1

    .line 40
    mul-int/2addr v3, v2

    .line 41
    iget-object v1, p0, Ltz/i;->f:Ltz/h;

    .line 42
    .line 43
    if-nez v1, :cond_1

    .line 44
    .line 45
    move v1, v0

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {v1}, Ltz/h;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    :goto_1
    add-int/2addr v3, v1

    .line 52
    mul-int/2addr v3, v2

    .line 53
    iget-boolean v1, p0, Ltz/i;->g:Z

    .line 54
    .line 55
    invoke-static {v3, v2, v1}, La7/g0;->e(IIZ)I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    iget-boolean v3, p0, Ltz/i;->h:Z

    .line 60
    .line 61
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    iget-boolean v3, p0, Ltz/i;->i:Z

    .line 66
    .line 67
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget-boolean v3, p0, Ltz/i;->j:Z

    .line 72
    .line 73
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    iget-object v3, p0, Ltz/i;->k:Ljava/lang/String;

    .line 78
    .line 79
    if-nez v3, :cond_2

    .line 80
    .line 81
    move v3, v0

    .line 82
    goto :goto_2

    .line 83
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    :goto_2
    add-int/2addr v1, v3

    .line 88
    mul-int/2addr v1, v2

    .line 89
    iget-object v3, p0, Ltz/i;->l:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v3, :cond_3

    .line 92
    .line 93
    move v3, v0

    .line 94
    goto :goto_3

    .line 95
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    :goto_3
    add-int/2addr v1, v3

    .line 100
    mul-int/2addr v1, v2

    .line 101
    iget-object v3, p0, Ltz/i;->m:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v3, :cond_4

    .line 104
    .line 105
    move v3, v0

    .line 106
    goto :goto_4

    .line 107
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_4
    add-int/2addr v1, v3

    .line 112
    mul-int/2addr v1, v2

    .line 113
    iget-object v3, p0, Ltz/i;->n:Ljava/lang/String;

    .line 114
    .line 115
    if-nez v3, :cond_5

    .line 116
    .line 117
    move v3, v0

    .line 118
    goto :goto_5

    .line 119
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    :goto_5
    add-int/2addr v1, v3

    .line 124
    mul-int/2addr v1, v2

    .line 125
    iget-object v3, p0, Ltz/i;->o:Lqr0/l;

    .line 126
    .line 127
    if-nez v3, :cond_6

    .line 128
    .line 129
    goto :goto_6

    .line 130
    :cond_6
    iget v0, v3, Lqr0/l;->d:I

    .line 131
    .line 132
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    :goto_6
    add-int/2addr v1, v0

    .line 137
    mul-int/2addr v1, v2

    .line 138
    iget-boolean v0, p0, Ltz/i;->p:Z

    .line 139
    .line 140
    invoke-static {v1, v2, v0}, La7/g0;->e(IIZ)I

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    iget-boolean v1, p0, Ltz/i;->q:Z

    .line 145
    .line 146
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    iget-boolean v1, p0, Ltz/i;->r:Z

    .line 151
    .line 152
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    iget-boolean v1, p0, Ltz/i;->s:Z

    .line 157
    .line 158
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    iget-boolean p0, p0, Ltz/i;->t:Z

    .line 163
    .line 164
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 165
    .line 166
    .line 167
    move-result p0

    .line 168
    add-int/2addr p0, v0

    .line 169
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(battery="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ltz/i;->a:Ltz/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", chargingState="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ltz/i;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isCharging="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isLoading="

    .line 29
    .line 30
    const-string v2, ", viewMode="

    .line 31
    .line 32
    iget-boolean v3, p0, Ltz/i;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Ltz/i;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Ltz/i;->e:Llf0/i;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", chargingDetail="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Ltz/i;->f:Ltz/h;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", isNotifySilentLoading="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", isSilentLoading="

    .line 60
    .line 61
    const-string v2, ", isInBiDiMode="

    .line 62
    .line 63
    iget-boolean v3, p0, Ltz/i;->g:Z

    .line 64
    .line 65
    iget-boolean v4, p0, Ltz/i;->h:Z

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v1, ", isDischarging="

    .line 71
    .line 72
    const-string v2, ", batteryChargingRange="

    .line 73
    .line 74
    iget-boolean v3, p0, Ltz/i;->i:Z

    .line 75
    .line 76
    iget-boolean v4, p0, Ltz/i;->j:Z

    .line 77
    .line 78
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string v1, ", readyAt="

    .line 82
    .line 83
    const-string v2, ", chargingProfileName="

    .line 84
    .line 85
    iget-object v3, p0, Ltz/i;->k:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v4, p0, Ltz/i;->l:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v1, ", preferredChargeMode="

    .line 93
    .line 94
    const-string v2, ", minBatteryChargedState="

    .line 95
    .line 96
    iget-object v3, p0, Ltz/i;->m:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v4, p0, Ltz/i;->n:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget-object v1, p0, Ltz/i;->o:Lqr0/l;

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v1, ", carIsInSavedLocation="

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    iget-boolean v1, p0, Ltz/i;->p:Z

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    const-string v1, ", isBiDiChargingFeatureEnabled="

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", isChargingProfilesVisible="

    .line 124
    .line 125
    const-string v2, ", shouldShowMinLimitStrip="

    .line 126
    .line 127
    iget-boolean v3, p0, Ltz/i;->q:Z

    .line 128
    .line 129
    iget-boolean v4, p0, Ltz/i;->r:Z

    .line 130
    .line 131
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-string v1, ", shouldShowBasicChargingInfo="

    .line 135
    .line 136
    const-string v2, ")"

    .line 137
    .line 138
    iget-boolean v3, p0, Ltz/i;->s:Z

    .line 139
    .line 140
    iget-boolean p0, p0, Ltz/i;->t:Z

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
