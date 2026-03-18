.class public final Luu0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/List;

.field public final c:Luu0/q;

.field public final d:Z

.field public final e:Z

.field public final f:Ljava/lang/String;

.field public final g:Lss0/n;

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Lss0/m;

.field public final l:Z

.field public final m:Lhp0/e;

.field public final n:Z

.field public final o:Z

.field public final p:Z

.field public final q:Ljava/time/OffsetDateTime;

.field public final r:Lra0/c;

.field public final s:Z

.field public final t:Z

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z

.field public final z:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZ)V
    .locals 7

    .line 1
    move v0, p8

    .line 2
    move/from16 v1, p9

    .line 3
    .line 4
    move-object/from16 v2, p11

    .line 5
    .line 6
    move/from16 v3, p12

    .line 7
    .line 8
    move/from16 v4, p16

    .line 9
    .line 10
    move-object/from16 v5, p18

    .line 11
    .line 12
    const-string v6, "vehicleName"

    .line 13
    .line 14
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v6, "deliveredVehicleFeatures"

    .line 18
    .line 19
    invoke-static {p2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v6, "vehicleConnectionStatus"

    .line 23
    .line 24
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Luu0/r;->a:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p2, p0, Luu0/r;->b:Ljava/util/List;

    .line 33
    .line 34
    iput-object p3, p0, Luu0/r;->c:Luu0/q;

    .line 35
    .line 36
    iput-boolean p4, p0, Luu0/r;->d:Z

    .line 37
    .line 38
    iput-boolean p5, p0, Luu0/r;->e:Z

    .line 39
    .line 40
    iput-object p6, p0, Luu0/r;->f:Ljava/lang/String;

    .line 41
    .line 42
    move-object p1, p7

    .line 43
    iput-object p1, p0, Luu0/r;->g:Lss0/n;

    .line 44
    .line 45
    iput-boolean v0, p0, Luu0/r;->h:Z

    .line 46
    .line 47
    iput-boolean v1, p0, Luu0/r;->i:Z

    .line 48
    .line 49
    move/from16 p1, p10

    .line 50
    .line 51
    iput-boolean p1, p0, Luu0/r;->j:Z

    .line 52
    .line 53
    iput-object v2, p0, Luu0/r;->k:Lss0/m;

    .line 54
    .line 55
    iput-boolean v3, p0, Luu0/r;->l:Z

    .line 56
    .line 57
    move-object/from16 p1, p13

    .line 58
    .line 59
    iput-object p1, p0, Luu0/r;->m:Lhp0/e;

    .line 60
    .line 61
    move/from16 p1, p14

    .line 62
    .line 63
    iput-boolean p1, p0, Luu0/r;->n:Z

    .line 64
    .line 65
    move/from16 p1, p15

    .line 66
    .line 67
    iput-boolean p1, p0, Luu0/r;->o:Z

    .line 68
    .line 69
    iput-boolean v4, p0, Luu0/r;->p:Z

    .line 70
    .line 71
    move-object/from16 p1, p17

    .line 72
    .line 73
    iput-object p1, p0, Luu0/r;->q:Ljava/time/OffsetDateTime;

    .line 74
    .line 75
    iput-object v5, p0, Luu0/r;->r:Lra0/c;

    .line 76
    .line 77
    move/from16 p1, p19

    .line 78
    .line 79
    iput-boolean p1, p0, Luu0/r;->s:Z

    .line 80
    .line 81
    move/from16 p1, p20

    .line 82
    .line 83
    iput-boolean p1, p0, Luu0/r;->t:Z

    .line 84
    .line 85
    sget-object p1, Luu0/x;->q1:Ljava/util/List;

    .line 86
    .line 87
    check-cast p1, Ljava/lang/Iterable;

    .line 88
    .line 89
    invoke-static {p1, v2}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    iput-boolean p1, p0, Luu0/r;->u:Z

    .line 94
    .line 95
    const/4 p1, 0x0

    .line 96
    const/4 v5, 0x1

    .line 97
    if-nez p3, :cond_0

    .line 98
    .line 99
    move p3, v5

    .line 100
    goto :goto_0

    .line 101
    :cond_0
    move p3, p1

    .line 102
    :goto_0
    iput-boolean p3, p0, Luu0/r;->v:Z

    .line 103
    .line 104
    check-cast p2, Ljava/util/Collection;

    .line 105
    .line 106
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    if-nez p2, :cond_1

    .line 111
    .line 112
    if-nez p4, :cond_1

    .line 113
    .line 114
    move p2, v5

    .line 115
    goto :goto_1

    .line 116
    :cond_1
    move p2, p1

    .line 117
    :goto_1
    iput-boolean p2, p0, Luu0/r;->w:Z

    .line 118
    .line 119
    if-nez v1, :cond_2

    .line 120
    .line 121
    if-eqz v3, :cond_2

    .line 122
    .line 123
    if-nez v0, :cond_2

    .line 124
    .line 125
    move p2, v5

    .line 126
    goto :goto_2

    .line 127
    :cond_2
    move p2, p1

    .line 128
    :goto_2
    iput-boolean p2, p0, Luu0/r;->x:Z

    .line 129
    .line 130
    if-eqz v4, :cond_3

    .line 131
    .line 132
    if-nez p5, :cond_3

    .line 133
    .line 134
    move p1, v5

    .line 135
    :cond_3
    iput-boolean p1, p0, Luu0/r;->y:Z

    .line 136
    .line 137
    sget-object p1, Luu0/x;->r1:Ljava/util/List;

    .line 138
    .line 139
    check-cast p1, Ljava/lang/Iterable;

    .line 140
    .line 141
    invoke-static {p1, v2}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    iput-boolean p1, p0, Luu0/r;->z:Z

    .line 146
    .line 147
    return-void
.end method

.method public static a(Luu0/r;Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZI)Luu0/r;
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
    iget-object v2, v0, Luu0/r;->a:Ljava/lang/String;

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
    iget-object v3, v0, Luu0/r;->b:Ljava/util/List;

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
    iget-object v4, v0, Luu0/r;->c:Luu0/q;

    .line 28
    .line 29
    goto :goto_2

    .line 30
    :cond_2
    move-object/from16 v4, p3

    .line 31
    .line 32
    :goto_2
    and-int/lit8 v5, v1, 0x8

    .line 33
    .line 34
    if-eqz v5, :cond_3

    .line 35
    .line 36
    iget-boolean v5, v0, Luu0/r;->d:Z

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
    iget-boolean v6, v0, Luu0/r;->e:Z

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
    iget-object v7, v0, Luu0/r;->f:Ljava/lang/String;

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
    iget-object v8, v0, Luu0/r;->g:Lss0/n;

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
    iget-boolean v9, v0, Luu0/r;->h:Z

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
    iget-boolean v10, v0, Luu0/r;->i:Z

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
    iget-boolean v11, v0, Luu0/r;->j:Z

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
    iget-object v12, v0, Luu0/r;->k:Lss0/m;

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
    iget-boolean v13, v0, Luu0/r;->l:Z

    .line 109
    .line 110
    goto :goto_b

    .line 111
    :cond_b
    move/from16 v13, p12

    .line 112
    .line 113
    :goto_b
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    and-int/lit16 v14, v1, 0x2000

    .line 117
    .line 118
    if-eqz v14, :cond_c

    .line 119
    .line 120
    iget-object v14, v0, Luu0/r;->m:Lhp0/e;

    .line 121
    .line 122
    goto :goto_c

    .line 123
    :cond_c
    move-object/from16 v14, p13

    .line 124
    .line 125
    :goto_c
    and-int/lit16 v15, v1, 0x4000

    .line 126
    .line 127
    if-eqz v15, :cond_d

    .line 128
    .line 129
    iget-boolean v15, v0, Luu0/r;->n:Z

    .line 130
    .line 131
    goto :goto_d

    .line 132
    :cond_d
    move/from16 v15, p14

    .line 133
    .line 134
    :goto_d
    const v16, 0x8000

    .line 135
    .line 136
    .line 137
    and-int v16, v1, v16

    .line 138
    .line 139
    if-eqz v16, :cond_e

    .line 140
    .line 141
    iget-boolean v1, v0, Luu0/r;->o:Z

    .line 142
    .line 143
    goto :goto_e

    .line 144
    :cond_e
    move/from16 v1, p15

    .line 145
    .line 146
    :goto_e
    const/high16 v16, 0x10000

    .line 147
    .line 148
    and-int v16, p21, v16

    .line 149
    .line 150
    move/from16 p15, v1

    .line 151
    .line 152
    if-eqz v16, :cond_f

    .line 153
    .line 154
    iget-boolean v1, v0, Luu0/r;->p:Z

    .line 155
    .line 156
    goto :goto_f

    .line 157
    :cond_f
    move/from16 v1, p16

    .line 158
    .line 159
    :goto_f
    const/high16 v16, 0x20000

    .line 160
    .line 161
    and-int v16, p21, v16

    .line 162
    .line 163
    move/from16 p16, v1

    .line 164
    .line 165
    if-eqz v16, :cond_10

    .line 166
    .line 167
    iget-object v1, v0, Luu0/r;->q:Ljava/time/OffsetDateTime;

    .line 168
    .line 169
    goto :goto_10

    .line 170
    :cond_10
    move-object/from16 v1, p17

    .line 171
    .line 172
    :goto_10
    const/high16 v16, 0x40000

    .line 173
    .line 174
    and-int v16, p21, v16

    .line 175
    .line 176
    move-object/from16 p17, v1

    .line 177
    .line 178
    if-eqz v16, :cond_11

    .line 179
    .line 180
    iget-object v1, v0, Luu0/r;->r:Lra0/c;

    .line 181
    .line 182
    goto :goto_11

    .line 183
    :cond_11
    move-object/from16 v1, p18

    .line 184
    .line 185
    :goto_11
    const/high16 v16, 0x80000

    .line 186
    .line 187
    and-int v16, p21, v16

    .line 188
    .line 189
    move-object/from16 p3, v4

    .line 190
    .line 191
    if-eqz v16, :cond_12

    .line 192
    .line 193
    iget-boolean v4, v0, Luu0/r;->s:Z

    .line 194
    .line 195
    goto :goto_12

    .line 196
    :cond_12
    move/from16 v4, p19

    .line 197
    .line 198
    :goto_12
    const/high16 v16, 0x100000

    .line 199
    .line 200
    and-int v16, p21, v16

    .line 201
    .line 202
    move/from16 p19, v4

    .line 203
    .line 204
    if-eqz v16, :cond_13

    .line 205
    .line 206
    iget-boolean v4, v0, Luu0/r;->t:Z

    .line 207
    .line 208
    goto :goto_13

    .line 209
    :cond_13
    move/from16 v4, p20

    .line 210
    .line 211
    :goto_13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 212
    .line 213
    .line 214
    const-string v0, "vehicleName"

    .line 215
    .line 216
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    const-string v0, "deliveredVehicleFeatures"

    .line 220
    .line 221
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    const-string v0, "vehicleConnectionStatus"

    .line 225
    .line 226
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    new-instance v0, Luu0/r;

    .line 230
    .line 231
    move-object/from16 p0, v0

    .line 232
    .line 233
    move-object/from16 p18, v1

    .line 234
    .line 235
    move-object/from16 p1, v2

    .line 236
    .line 237
    move-object/from16 p2, v3

    .line 238
    .line 239
    move/from16 p20, v4

    .line 240
    .line 241
    move/from16 p4, v5

    .line 242
    .line 243
    move/from16 p5, v6

    .line 244
    .line 245
    move-object/from16 p6, v7

    .line 246
    .line 247
    move-object/from16 p7, v8

    .line 248
    .line 249
    move/from16 p8, v9

    .line 250
    .line 251
    move/from16 p9, v10

    .line 252
    .line 253
    move/from16 p10, v11

    .line 254
    .line 255
    move-object/from16 p11, v12

    .line 256
    .line 257
    move/from16 p12, v13

    .line 258
    .line 259
    move-object/from16 p13, v14

    .line 260
    .line 261
    move/from16 p14, v15

    .line 262
    .line 263
    invoke-direct/range {p0 .. p20}, Luu0/r;-><init>(Ljava/lang/String;Ljava/util/List;Luu0/q;ZZLjava/lang/String;Lss0/n;ZZZLss0/m;ZLhp0/e;ZZZLjava/time/OffsetDateTime;Lra0/c;ZZ)V

    .line 264
    .line 265
    .line 266
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
    goto/16 :goto_3

    .line 5
    .line 6
    :cond_0
    instance-of v1, p1, Luu0/r;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    goto/16 :goto_2

    .line 12
    .line 13
    :cond_1
    check-cast p1, Luu0/r;

    .line 14
    .line 15
    iget-object v1, p0, Luu0/r;->a:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v3, p1, Luu0/r;->a:Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-nez v1, :cond_2

    .line 24
    .line 25
    goto/16 :goto_2

    .line 26
    .line 27
    :cond_2
    iget-object v1, p0, Luu0/r;->b:Ljava/util/List;

    .line 28
    .line 29
    iget-object v3, p1, Luu0/r;->b:Ljava/util/List;

    .line 30
    .line 31
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_3

    .line 36
    .line 37
    goto/16 :goto_2

    .line 38
    .line 39
    :cond_3
    iget-object v1, p0, Luu0/r;->c:Luu0/q;

    .line 40
    .line 41
    iget-object v3, p1, Luu0/r;->c:Luu0/q;

    .line 42
    .line 43
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-nez v1, :cond_4

    .line 48
    .line 49
    goto/16 :goto_2

    .line 50
    .line 51
    :cond_4
    iget-boolean v1, p0, Luu0/r;->d:Z

    .line 52
    .line 53
    iget-boolean v3, p1, Luu0/r;->d:Z

    .line 54
    .line 55
    if-eq v1, v3, :cond_5

    .line 56
    .line 57
    goto/16 :goto_2

    .line 58
    .line 59
    :cond_5
    iget-boolean v1, p0, Luu0/r;->e:Z

    .line 60
    .line 61
    iget-boolean v3, p1, Luu0/r;->e:Z

    .line 62
    .line 63
    if-eq v1, v3, :cond_6

    .line 64
    .line 65
    goto/16 :goto_2

    .line 66
    .line 67
    :cond_6
    iget-object v1, p1, Luu0/r;->f:Ljava/lang/String;

    .line 68
    .line 69
    iget-object v3, p0, Luu0/r;->f:Ljava/lang/String;

    .line 70
    .line 71
    if-nez v3, :cond_8

    .line 72
    .line 73
    if-nez v1, :cond_7

    .line 74
    .line 75
    move v1, v0

    .line 76
    goto :goto_1

    .line 77
    :cond_7
    :goto_0
    move v1, v2

    .line 78
    goto :goto_1

    .line 79
    :cond_8
    if-nez v1, :cond_9

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_9
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    :goto_1
    if-nez v1, :cond_a

    .line 87
    .line 88
    goto/16 :goto_2

    .line 89
    .line 90
    :cond_a
    iget-object v1, p0, Luu0/r;->g:Lss0/n;

    .line 91
    .line 92
    iget-object v3, p1, Luu0/r;->g:Lss0/n;

    .line 93
    .line 94
    if-eq v1, v3, :cond_b

    .line 95
    .line 96
    goto/16 :goto_2

    .line 97
    .line 98
    :cond_b
    iget-boolean v1, p0, Luu0/r;->h:Z

    .line 99
    .line 100
    iget-boolean v3, p1, Luu0/r;->h:Z

    .line 101
    .line 102
    if-eq v1, v3, :cond_c

    .line 103
    .line 104
    goto/16 :goto_2

    .line 105
    .line 106
    :cond_c
    iget-boolean v1, p0, Luu0/r;->i:Z

    .line 107
    .line 108
    iget-boolean v3, p1, Luu0/r;->i:Z

    .line 109
    .line 110
    if-eq v1, v3, :cond_d

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_d
    iget-boolean v1, p0, Luu0/r;->j:Z

    .line 114
    .line 115
    iget-boolean v3, p1, Luu0/r;->j:Z

    .line 116
    .line 117
    if-eq v1, v3, :cond_e

    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_e
    iget-object v1, p0, Luu0/r;->k:Lss0/m;

    .line 121
    .line 122
    iget-object v3, p1, Luu0/r;->k:Lss0/m;

    .line 123
    .line 124
    if-eq v1, v3, :cond_f

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_f
    iget-boolean v1, p0, Luu0/r;->l:Z

    .line 128
    .line 129
    iget-boolean v3, p1, Luu0/r;->l:Z

    .line 130
    .line 131
    if-eq v1, v3, :cond_10

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_10
    iget-object v1, p0, Luu0/r;->m:Lhp0/e;

    .line 135
    .line 136
    iget-object v3, p1, Luu0/r;->m:Lhp0/e;

    .line 137
    .line 138
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_11

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_11
    iget-boolean v1, p0, Luu0/r;->n:Z

    .line 146
    .line 147
    iget-boolean v3, p1, Luu0/r;->n:Z

    .line 148
    .line 149
    if-eq v1, v3, :cond_12

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_12
    iget-boolean v1, p0, Luu0/r;->o:Z

    .line 153
    .line 154
    iget-boolean v3, p1, Luu0/r;->o:Z

    .line 155
    .line 156
    if-eq v1, v3, :cond_13

    .line 157
    .line 158
    goto :goto_2

    .line 159
    :cond_13
    iget-boolean v1, p0, Luu0/r;->p:Z

    .line 160
    .line 161
    iget-boolean v3, p1, Luu0/r;->p:Z

    .line 162
    .line 163
    if-eq v1, v3, :cond_14

    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_14
    iget-object v1, p0, Luu0/r;->q:Ljava/time/OffsetDateTime;

    .line 167
    .line 168
    iget-object v3, p1, Luu0/r;->q:Ljava/time/OffsetDateTime;

    .line 169
    .line 170
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-nez v1, :cond_15

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_15
    iget-object v1, p0, Luu0/r;->r:Lra0/c;

    .line 178
    .line 179
    iget-object v3, p1, Luu0/r;->r:Lra0/c;

    .line 180
    .line 181
    if-eq v1, v3, :cond_16

    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_16
    iget-boolean v1, p0, Luu0/r;->s:Z

    .line 185
    .line 186
    iget-boolean v3, p1, Luu0/r;->s:Z

    .line 187
    .line 188
    if-eq v1, v3, :cond_17

    .line 189
    .line 190
    goto :goto_2

    .line 191
    :cond_17
    iget-boolean p0, p0, Luu0/r;->t:Z

    .line 192
    .line 193
    iget-boolean p1, p1, Luu0/r;->t:Z

    .line 194
    .line 195
    if-eq p0, p1, :cond_18

    .line 196
    .line 197
    :goto_2
    return v2

    .line 198
    :cond_18
    :goto_3
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Luu0/r;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Luu0/r;->b:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Luu0/r;->c:Luu0/q;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    move v3, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v3}, Luu0/q;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    add-int/2addr v0, v3

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-boolean v3, p0, Luu0/r;->d:Z

    .line 30
    .line 31
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-boolean v3, p0, Luu0/r;->e:Z

    .line 36
    .line 37
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-object v3, p0, Luu0/r;->f:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v3, :cond_1

    .line 44
    .line 45
    move v3, v2

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    :goto_1
    add-int/2addr v0, v3

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v3, p0, Luu0/r;->g:Lss0/n;

    .line 54
    .line 55
    if-nez v3, :cond_2

    .line 56
    .line 57
    move v3, v2

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_2
    add-int/2addr v0, v3

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-boolean v3, p0, Luu0/r;->h:Z

    .line 66
    .line 67
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    iget-boolean v3, p0, Luu0/r;->i:Z

    .line 72
    .line 73
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-boolean v3, p0, Luu0/r;->j:Z

    .line 78
    .line 79
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-object v3, p0, Luu0/r;->k:Lss0/m;

    .line 84
    .line 85
    if-nez v3, :cond_3

    .line 86
    .line 87
    move v3, v2

    .line 88
    goto :goto_3

    .line 89
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    :goto_3
    add-int/2addr v0, v3

    .line 94
    mul-int/2addr v0, v1

    .line 95
    iget-boolean v3, p0, Luu0/r;->l:Z

    .line 96
    .line 97
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    iget-object v3, p0, Luu0/r;->m:Lhp0/e;

    .line 106
    .line 107
    if-nez v3, :cond_4

    .line 108
    .line 109
    move v3, v2

    .line 110
    goto :goto_4

    .line 111
    :cond_4
    invoke-virtual {v3}, Lhp0/e;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    :goto_4
    add-int/2addr v0, v3

    .line 116
    mul-int/2addr v0, v1

    .line 117
    iget-boolean v3, p0, Luu0/r;->n:Z

    .line 118
    .line 119
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    iget-boolean v3, p0, Luu0/r;->o:Z

    .line 124
    .line 125
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    iget-boolean v3, p0, Luu0/r;->p:Z

    .line 130
    .line 131
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    iget-object v3, p0, Luu0/r;->q:Ljava/time/OffsetDateTime;

    .line 136
    .line 137
    if-nez v3, :cond_5

    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_5
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    :goto_5
    add-int/2addr v0, v2

    .line 145
    mul-int/2addr v0, v1

    .line 146
    iget-object v2, p0, Luu0/r;->r:Lra0/c;

    .line 147
    .line 148
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 149
    .line 150
    .line 151
    move-result v2

    .line 152
    add-int/2addr v2, v0

    .line 153
    mul-int/2addr v2, v1

    .line 154
    iget-boolean v0, p0, Luu0/r;->s:Z

    .line 155
    .line 156
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 157
    .line 158
    .line 159
    move-result v0

    .line 160
    iget-boolean p0, p0, Luu0/r;->t:Z

    .line 161
    .line 162
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    add-int/2addr p0, v0

    .line 167
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Luu0/r;->f:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "null"

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-static {v0}, Lss0/j0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :goto_0
    const-string v1, ", deliveredVehicleFeatures="

    .line 13
    .line 14
    const-string v2, ", invalidVehicleStatus="

    .line 15
    .line 16
    const-string v3, "State(vehicleName="

    .line 17
    .line 18
    iget-object v4, p0, Luu0/r;->a:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v5, p0, Luu0/r;->b:Ljava/util/List;

    .line 21
    .line 22
    invoke-static {v3, v4, v1, v2, v5}, Lvj/b;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    iget-object v2, p0, Luu0/r;->c:Luu0/q;

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v2, ", isVehicleLoading="

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-boolean v2, p0, Luu0/r;->d:Z

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v2, ", isRefreshing="

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v2, ", vin="

    .line 47
    .line 48
    const-string v3, ", devicePlatform="

    .line 49
    .line 50
    iget-boolean v4, p0, Luu0/r;->e:Z

    .line 51
    .line 52
    invoke-static {v2, v0, v3, v1, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 53
    .line 54
    .line 55
    iget-object v0, p0, Luu0/r;->g:Lss0/n;

    .line 56
    .line 57
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v0, ", isEmptyState="

    .line 61
    .line 62
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-boolean v0, p0, Luu0/r;->h:Z

    .line 66
    .line 67
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v0, ", isVehicleCached="

    .line 71
    .line 72
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v0, ", isTitleClickEnabled="

    .line 76
    .line 77
    const-string v2, ", vehicleState="

    .line 78
    .line 79
    iget-boolean v3, p0, Luu0/r;->i:Z

    .line 80
    .line 81
    iget-boolean v4, p0, Luu0/r;->j:Z

    .line 82
    .line 83
    invoke-static {v1, v3, v0, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 84
    .line 85
    .line 86
    iget-object v0, p0, Luu0/r;->k:Lss0/m;

    .line 87
    .line 88
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v0, ", isError="

    .line 92
    .line 93
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    iget-boolean v0, p0, Luu0/r;->l:Z

    .line 97
    .line 98
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v0, ", showAppUpdateOverlay=false, render="

    .line 102
    .line 103
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    iget-object v0, p0, Luu0/r;->m:Lhp0/e;

    .line 107
    .line 108
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string v0, ", allowServicePartnerBanner="

    .line 112
    .line 113
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    iget-boolean v0, p0, Luu0/r;->n:Z

    .line 117
    .line 118
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    const-string v0, ", isAppRatingDialogVisible="

    .line 122
    .line 123
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v0, ", isSilentLoading="

    .line 127
    .line 128
    const-string v2, ", lastUpdateTimestamp="

    .line 129
    .line 130
    iget-boolean v3, p0, Luu0/r;->o:Z

    .line 131
    .line 132
    iget-boolean v4, p0, Luu0/r;->p:Z

    .line 133
    .line 134
    invoke-static {v1, v3, v0, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 135
    .line 136
    .line 137
    iget-object v0, p0, Luu0/r;->q:Ljava/time/OffsetDateTime;

    .line 138
    .line 139
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    const-string v0, ", vehicleConnectionStatus="

    .line 143
    .line 144
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    iget-object v0, p0, Luu0/r;->r:Lra0/c;

    .line 148
    .line 149
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string v0, ", isTestDriveVisible="

    .line 153
    .line 154
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    const-string v0, ", isFleetVehicle="

    .line 158
    .line 159
    const-string v2, ")"

    .line 160
    .line 161
    iget-boolean v3, p0, Luu0/r;->s:Z

    .line 162
    .line 163
    iget-boolean p0, p0, Luu0/r;->t:Z

    .line 164
    .line 165
    invoke-static {v1, v3, v0, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    return-object p0
.end method
