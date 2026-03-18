.class public final Ll70/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/time/LocalDate;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/time/LocalTime;

.field public final f:Ljava/time/LocalTime;

.field public final g:Lqr0/d;

.field public final h:Lqr0/d;

.field public final i:D

.field public final j:J

.field public final k:Lqr0/l;

.field public final l:Lqr0/l;

.field public final m:Lqr0/p;

.field public final n:Lqr0/i;

.field public final o:Lqr0/h;

.field public final p:Lqr0/g;

.field public final q:Lqr0/j;

.field public final r:Lqr0/g;

.field public final s:Lqr0/i;

.field public final t:Ll70/u;

.field public final u:Ljava/util/List;

.field public final v:Ll70/o;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalTime;Ljava/time/LocalTime;Lqr0/d;Lqr0/d;DJLqr0/l;Lqr0/l;Lqr0/p;Lqr0/i;Lqr0/h;Lqr0/g;Lqr0/j;Lqr0/g;Lqr0/i;Ll70/u;Ljava/util/List;Ll70/o;)V
    .locals 1

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "endTime"

    .line 7
    .line 8
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Ll70/i;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Ll70/i;->b:Ljava/time/LocalDate;

    .line 17
    .line 18
    iput-object p3, p0, Ll70/i;->c:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p4, p0, Ll70/i;->d:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p5, p0, Ll70/i;->e:Ljava/time/LocalTime;

    .line 23
    .line 24
    iput-object p6, p0, Ll70/i;->f:Ljava/time/LocalTime;

    .line 25
    .line 26
    iput-object p7, p0, Ll70/i;->g:Lqr0/d;

    .line 27
    .line 28
    iput-object p8, p0, Ll70/i;->h:Lqr0/d;

    .line 29
    .line 30
    iput-wide p9, p0, Ll70/i;->i:D

    .line 31
    .line 32
    iput-wide p11, p0, Ll70/i;->j:J

    .line 33
    .line 34
    iput-object p13, p0, Ll70/i;->k:Lqr0/l;

    .line 35
    .line 36
    iput-object p14, p0, Ll70/i;->l:Lqr0/l;

    .line 37
    .line 38
    move-object/from16 p1, p15

    .line 39
    .line 40
    iput-object p1, p0, Ll70/i;->m:Lqr0/p;

    .line 41
    .line 42
    move-object/from16 p1, p16

    .line 43
    .line 44
    iput-object p1, p0, Ll70/i;->n:Lqr0/i;

    .line 45
    .line 46
    move-object/from16 p1, p17

    .line 47
    .line 48
    iput-object p1, p0, Ll70/i;->o:Lqr0/h;

    .line 49
    .line 50
    move-object/from16 p1, p18

    .line 51
    .line 52
    iput-object p1, p0, Ll70/i;->p:Lqr0/g;

    .line 53
    .line 54
    move-object/from16 p1, p19

    .line 55
    .line 56
    iput-object p1, p0, Ll70/i;->q:Lqr0/j;

    .line 57
    .line 58
    move-object/from16 p1, p20

    .line 59
    .line 60
    iput-object p1, p0, Ll70/i;->r:Lqr0/g;

    .line 61
    .line 62
    move-object/from16 p1, p21

    .line 63
    .line 64
    iput-object p1, p0, Ll70/i;->s:Lqr0/i;

    .line 65
    .line 66
    move-object/from16 p1, p22

    .line 67
    .line 68
    iput-object p1, p0, Ll70/i;->t:Ll70/u;

    .line 69
    .line 70
    move-object/from16 p1, p23

    .line 71
    .line 72
    iput-object p1, p0, Ll70/i;->u:Ljava/util/List;

    .line 73
    .line 74
    move-object/from16 p1, p24

    .line 75
    .line 76
    iput-object p1, p0, Ll70/i;->v:Ll70/o;

    .line 77
    .line 78
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Ll70/i;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Ll70/i;

    .line 12
    .line 13
    iget-object v0, p0, Ll70/i;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Ll70/i;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Ll70/i;->b:Ljava/time/LocalDate;

    .line 26
    .line 27
    iget-object v1, p1, Ll70/i;->b:Ljava/time/LocalDate;

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_3
    iget-object v0, p0, Ll70/i;->c:Ljava/lang/String;

    .line 38
    .line 39
    iget-object v1, p1, Ll70/i;->c:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-nez v0, :cond_4

    .line 46
    .line 47
    goto/16 :goto_0

    .line 48
    .line 49
    :cond_4
    iget-object v0, p0, Ll70/i;->d:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v1, p1, Ll70/i;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-nez v0, :cond_5

    .line 58
    .line 59
    goto/16 :goto_0

    .line 60
    .line 61
    :cond_5
    iget-object v0, p0, Ll70/i;->e:Ljava/time/LocalTime;

    .line 62
    .line 63
    iget-object v1, p1, Ll70/i;->e:Ljava/time/LocalTime;

    .line 64
    .line 65
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-nez v0, :cond_6

    .line 70
    .line 71
    goto/16 :goto_0

    .line 72
    .line 73
    :cond_6
    iget-object v0, p0, Ll70/i;->f:Ljava/time/LocalTime;

    .line 74
    .line 75
    iget-object v1, p1, Ll70/i;->f:Ljava/time/LocalTime;

    .line 76
    .line 77
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-nez v0, :cond_7

    .line 82
    .line 83
    goto/16 :goto_0

    .line 84
    .line 85
    :cond_7
    iget-object v0, p0, Ll70/i;->g:Lqr0/d;

    .line 86
    .line 87
    iget-object v1, p1, Ll70/i;->g:Lqr0/d;

    .line 88
    .line 89
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-nez v0, :cond_8

    .line 94
    .line 95
    goto/16 :goto_0

    .line 96
    .line 97
    :cond_8
    iget-object v0, p0, Ll70/i;->h:Lqr0/d;

    .line 98
    .line 99
    iget-object v1, p1, Ll70/i;->h:Lqr0/d;

    .line 100
    .line 101
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-nez v0, :cond_9

    .line 106
    .line 107
    goto/16 :goto_0

    .line 108
    .line 109
    :cond_9
    iget-wide v0, p0, Ll70/i;->i:D

    .line 110
    .line 111
    iget-wide v2, p1, Ll70/i;->i:D

    .line 112
    .line 113
    invoke-static {v0, v1, v2, v3}, Lqr0/d;->a(DD)Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-nez v0, :cond_a

    .line 118
    .line 119
    goto/16 :goto_0

    .line 120
    .line 121
    :cond_a
    iget-wide v0, p0, Ll70/i;->j:J

    .line 122
    .line 123
    iget-wide v2, p1, Ll70/i;->j:J

    .line 124
    .line 125
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->d(JJ)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-nez v0, :cond_b

    .line 130
    .line 131
    goto/16 :goto_0

    .line 132
    .line 133
    :cond_b
    iget-object v0, p0, Ll70/i;->k:Lqr0/l;

    .line 134
    .line 135
    iget-object v1, p1, Ll70/i;->k:Lqr0/l;

    .line 136
    .line 137
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    if-nez v0, :cond_c

    .line 142
    .line 143
    goto/16 :goto_0

    .line 144
    .line 145
    :cond_c
    iget-object v0, p0, Ll70/i;->l:Lqr0/l;

    .line 146
    .line 147
    iget-object v1, p1, Ll70/i;->l:Lqr0/l;

    .line 148
    .line 149
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    if-nez v0, :cond_d

    .line 154
    .line 155
    goto/16 :goto_0

    .line 156
    .line 157
    :cond_d
    iget-object v0, p0, Ll70/i;->m:Lqr0/p;

    .line 158
    .line 159
    iget-object v1, p1, Ll70/i;->m:Lqr0/p;

    .line 160
    .line 161
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    if-nez v0, :cond_e

    .line 166
    .line 167
    goto :goto_0

    .line 168
    :cond_e
    iget-object v0, p0, Ll70/i;->n:Lqr0/i;

    .line 169
    .line 170
    iget-object v1, p1, Ll70/i;->n:Lqr0/i;

    .line 171
    .line 172
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    if-nez v0, :cond_f

    .line 177
    .line 178
    goto :goto_0

    .line 179
    :cond_f
    iget-object v0, p0, Ll70/i;->o:Lqr0/h;

    .line 180
    .line 181
    iget-object v1, p1, Ll70/i;->o:Lqr0/h;

    .line 182
    .line 183
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v0

    .line 187
    if-nez v0, :cond_10

    .line 188
    .line 189
    goto :goto_0

    .line 190
    :cond_10
    iget-object v0, p0, Ll70/i;->p:Lqr0/g;

    .line 191
    .line 192
    iget-object v1, p1, Ll70/i;->p:Lqr0/g;

    .line 193
    .line 194
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v0

    .line 198
    if-nez v0, :cond_11

    .line 199
    .line 200
    goto :goto_0

    .line 201
    :cond_11
    iget-object v0, p0, Ll70/i;->q:Lqr0/j;

    .line 202
    .line 203
    iget-object v1, p1, Ll70/i;->q:Lqr0/j;

    .line 204
    .line 205
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v0

    .line 209
    if-nez v0, :cond_12

    .line 210
    .line 211
    goto :goto_0

    .line 212
    :cond_12
    iget-object v0, p0, Ll70/i;->r:Lqr0/g;

    .line 213
    .line 214
    iget-object v1, p1, Ll70/i;->r:Lqr0/g;

    .line 215
    .line 216
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v0

    .line 220
    if-nez v0, :cond_13

    .line 221
    .line 222
    goto :goto_0

    .line 223
    :cond_13
    iget-object v0, p0, Ll70/i;->s:Lqr0/i;

    .line 224
    .line 225
    iget-object v1, p1, Ll70/i;->s:Lqr0/i;

    .line 226
    .line 227
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result v0

    .line 231
    if-nez v0, :cond_14

    .line 232
    .line 233
    goto :goto_0

    .line 234
    :cond_14
    iget-object v0, p0, Ll70/i;->t:Ll70/u;

    .line 235
    .line 236
    iget-object v1, p1, Ll70/i;->t:Ll70/u;

    .line 237
    .line 238
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    move-result v0

    .line 242
    if-nez v0, :cond_15

    .line 243
    .line 244
    goto :goto_0

    .line 245
    :cond_15
    iget-object v0, p0, Ll70/i;->u:Ljava/util/List;

    .line 246
    .line 247
    iget-object v1, p1, Ll70/i;->u:Ljava/util/List;

    .line 248
    .line 249
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    move-result v0

    .line 253
    if-nez v0, :cond_16

    .line 254
    .line 255
    goto :goto_0

    .line 256
    :cond_16
    iget-object p0, p0, Ll70/i;->v:Ll70/o;

    .line 257
    .line 258
    iget-object p1, p1, Ll70/i;->v:Ll70/o;

    .line 259
    .line 260
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    if-nez p0, :cond_17

    .line 265
    .line 266
    :goto_0
    const/4 p0, 0x0

    .line 267
    return p0

    .line 268
    :cond_17
    :goto_1
    const/4 p0, 0x1

    .line 269
    return p0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Ll70/i;->a:Ljava/lang/String;

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
    iget-object v2, p0, Ll70/i;->b:Ljava/time/LocalDate;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/time/LocalDate;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    const/4 v0, 0x0

    .line 19
    iget-object v3, p0, Ll70/i;->c:Ljava/lang/String;

    .line 20
    .line 21
    if-nez v3, :cond_0

    .line 22
    .line 23
    move v3, v0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    :goto_0
    add-int/2addr v2, v3

    .line 30
    mul-int/2addr v2, v1

    .line 31
    iget-object v3, p0, Ll70/i;->d:Ljava/lang/String;

    .line 32
    .line 33
    if-nez v3, :cond_1

    .line 34
    .line 35
    move v3, v0

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_1
    add-int/2addr v2, v3

    .line 42
    mul-int/2addr v2, v1

    .line 43
    iget-object v3, p0, Ll70/i;->e:Ljava/time/LocalTime;

    .line 44
    .line 45
    if-nez v3, :cond_2

    .line 46
    .line 47
    move v3, v0

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    invoke-virtual {v3}, Ljava/time/LocalTime;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_2
    add-int/2addr v2, v3

    .line 54
    mul-int/2addr v2, v1

    .line 55
    iget-object v3, p0, Ll70/i;->f:Ljava/time/LocalTime;

    .line 56
    .line 57
    invoke-virtual {v3}, Ljava/time/LocalTime;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    add-int/2addr v3, v2

    .line 62
    mul-int/2addr v3, v1

    .line 63
    iget-object v2, p0, Ll70/i;->g:Lqr0/d;

    .line 64
    .line 65
    if-nez v2, :cond_3

    .line 66
    .line 67
    move v2, v0

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    iget-wide v4, v2, Lqr0/d;->a:D

    .line 70
    .line 71
    invoke-static {v4, v5}, Ljava/lang/Double;->hashCode(D)I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    :goto_3
    add-int/2addr v3, v2

    .line 76
    mul-int/2addr v3, v1

    .line 77
    iget-object v2, p0, Ll70/i;->h:Lqr0/d;

    .line 78
    .line 79
    if-nez v2, :cond_4

    .line 80
    .line 81
    move v2, v0

    .line 82
    goto :goto_4

    .line 83
    :cond_4
    iget-wide v4, v2, Lqr0/d;->a:D

    .line 84
    .line 85
    invoke-static {v4, v5}, Ljava/lang/Double;->hashCode(D)I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    :goto_4
    add-int/2addr v3, v2

    .line 90
    mul-int/2addr v3, v1

    .line 91
    iget-wide v4, p0, Ll70/i;->i:D

    .line 92
    .line 93
    invoke-static {v4, v5, v3, v1}, Lf2/m0;->a(DII)I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    sget v3, Lmy0/c;->g:I

    .line 98
    .line 99
    iget-wide v3, p0, Ll70/i;->j:J

    .line 100
    .line 101
    invoke-static {v3, v4, v2, v1}, La7/g0;->f(JII)I

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    iget-object v3, p0, Ll70/i;->k:Lqr0/l;

    .line 106
    .line 107
    if-nez v3, :cond_5

    .line 108
    .line 109
    move v3, v0

    .line 110
    goto :goto_5

    .line 111
    :cond_5
    iget v3, v3, Lqr0/l;->d:I

    .line 112
    .line 113
    invoke-static {v3}, Ljava/lang/Integer;->hashCode(I)I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    :goto_5
    add-int/2addr v2, v3

    .line 118
    mul-int/2addr v2, v1

    .line 119
    iget-object v3, p0, Ll70/i;->l:Lqr0/l;

    .line 120
    .line 121
    if-nez v3, :cond_6

    .line 122
    .line 123
    move v3, v0

    .line 124
    goto :goto_6

    .line 125
    :cond_6
    iget v3, v3, Lqr0/l;->d:I

    .line 126
    .line 127
    invoke-static {v3}, Ljava/lang/Integer;->hashCode(I)I

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    :goto_6
    add-int/2addr v2, v3

    .line 132
    mul-int/2addr v2, v1

    .line 133
    iget-object v3, p0, Ll70/i;->m:Lqr0/p;

    .line 134
    .line 135
    if-nez v3, :cond_7

    .line 136
    .line 137
    move v3, v0

    .line 138
    goto :goto_7

    .line 139
    :cond_7
    iget-wide v3, v3, Lqr0/p;->a:D

    .line 140
    .line 141
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    :goto_7
    add-int/2addr v2, v3

    .line 146
    mul-int/2addr v2, v1

    .line 147
    iget-object v3, p0, Ll70/i;->n:Lqr0/i;

    .line 148
    .line 149
    if-nez v3, :cond_8

    .line 150
    .line 151
    move v3, v0

    .line 152
    goto :goto_8

    .line 153
    :cond_8
    iget-wide v3, v3, Lqr0/i;->a:D

    .line 154
    .line 155
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    :goto_8
    add-int/2addr v2, v3

    .line 160
    mul-int/2addr v2, v1

    .line 161
    iget-object v3, p0, Ll70/i;->o:Lqr0/h;

    .line 162
    .line 163
    if-nez v3, :cond_9

    .line 164
    .line 165
    move v3, v0

    .line 166
    goto :goto_9

    .line 167
    :cond_9
    iget v3, v3, Lqr0/h;->a:I

    .line 168
    .line 169
    invoke-static {v3}, Ljava/lang/Integer;->hashCode(I)I

    .line 170
    .line 171
    .line 172
    move-result v3

    .line 173
    :goto_9
    add-int/2addr v2, v3

    .line 174
    mul-int/2addr v2, v1

    .line 175
    iget-object v3, p0, Ll70/i;->p:Lqr0/g;

    .line 176
    .line 177
    if-nez v3, :cond_a

    .line 178
    .line 179
    move v3, v0

    .line 180
    goto :goto_a

    .line 181
    :cond_a
    iget-wide v3, v3, Lqr0/g;->a:D

    .line 182
    .line 183
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 184
    .line 185
    .line 186
    move-result v3

    .line 187
    :goto_a
    add-int/2addr v2, v3

    .line 188
    mul-int/2addr v2, v1

    .line 189
    iget-object v3, p0, Ll70/i;->q:Lqr0/j;

    .line 190
    .line 191
    if-nez v3, :cond_b

    .line 192
    .line 193
    move v3, v0

    .line 194
    goto :goto_b

    .line 195
    :cond_b
    iget-wide v3, v3, Lqr0/j;->a:D

    .line 196
    .line 197
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    :goto_b
    add-int/2addr v2, v3

    .line 202
    mul-int/2addr v2, v1

    .line 203
    iget-object v3, p0, Ll70/i;->r:Lqr0/g;

    .line 204
    .line 205
    if-nez v3, :cond_c

    .line 206
    .line 207
    move v3, v0

    .line 208
    goto :goto_c

    .line 209
    :cond_c
    iget-wide v3, v3, Lqr0/g;->a:D

    .line 210
    .line 211
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    :goto_c
    add-int/2addr v2, v3

    .line 216
    mul-int/2addr v2, v1

    .line 217
    iget-object v3, p0, Ll70/i;->s:Lqr0/i;

    .line 218
    .line 219
    if-nez v3, :cond_d

    .line 220
    .line 221
    move v3, v0

    .line 222
    goto :goto_d

    .line 223
    :cond_d
    iget-wide v3, v3, Lqr0/i;->a:D

    .line 224
    .line 225
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 226
    .line 227
    .line 228
    move-result v3

    .line 229
    :goto_d
    add-int/2addr v2, v3

    .line 230
    mul-int/2addr v2, v1

    .line 231
    iget-object v3, p0, Ll70/i;->t:Ll70/u;

    .line 232
    .line 233
    if-nez v3, :cond_e

    .line 234
    .line 235
    move v3, v0

    .line 236
    goto :goto_e

    .line 237
    :cond_e
    invoke-virtual {v3}, Ll70/u;->hashCode()I

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    :goto_e
    add-int/2addr v2, v3

    .line 242
    mul-int/2addr v2, v1

    .line 243
    iget-object v3, p0, Ll70/i;->u:Ljava/util/List;

    .line 244
    .line 245
    if-nez v3, :cond_f

    .line 246
    .line 247
    goto :goto_f

    .line 248
    :cond_f
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 249
    .line 250
    .line 251
    move-result v0

    .line 252
    :goto_f
    add-int/2addr v2, v0

    .line 253
    mul-int/2addr v2, v1

    .line 254
    iget-object p0, p0, Ll70/i;->v:Ll70/o;

    .line 255
    .line 256
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 257
    .line 258
    .line 259
    move-result p0

    .line 260
    add-int/2addr p0, v2

    .line 261
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-wide v0, p0, Ll70/i;->i:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Lqr0/d;->b(D)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-wide v1, p0, Ll70/i;->j:J

    .line 8
    .line 9
    invoke-static {v1, v2}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    new-instance v2, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v3, "SingleTrip(id="

    .line 16
    .line 17
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v3, p0, Ll70/i;->a:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v3, ", date="

    .line 26
    .line 27
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object v3, p0, Ll70/i;->b:Ljava/time/LocalDate;

    .line 31
    .line 32
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v3, ", startLocationName="

    .line 36
    .line 37
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v3, ", endLocationName="

    .line 41
    .line 42
    const-string v4, ", startTime="

    .line 43
    .line 44
    iget-object v5, p0, Ll70/i;->c:Ljava/lang/String;

    .line 45
    .line 46
    iget-object v6, p0, Ll70/i;->d:Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {v2, v5, v3, v6, v4}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object v3, p0, Ll70/i;->e:Ljava/time/LocalTime;

    .line 52
    .line 53
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string v3, ", endTime="

    .line 57
    .line 58
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    iget-object v3, p0, Ll70/i;->f:Ljava/time/LocalTime;

    .line 62
    .line 63
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v3, ", startMileage="

    .line 67
    .line 68
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    iget-object v3, p0, Ll70/i;->g:Lqr0/d;

    .line 72
    .line 73
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v3, ", endMileage="

    .line 77
    .line 78
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    iget-object v3, p0, Ll70/i;->h:Lqr0/d;

    .line 82
    .line 83
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v3, ", mileage="

    .line 87
    .line 88
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v3, ", travelTime="

    .line 92
    .line 93
    const-string v4, ", startBatteryStateOfCharge="

    .line 94
    .line 95
    invoke-static {v2, v0, v3, v1, v4}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    iget-object v0, p0, Ll70/i;->k:Lqr0/l;

    .line 99
    .line 100
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v0, ", endBatteryStateOfCharge="

    .line 104
    .line 105
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v0, p0, Ll70/i;->l:Lqr0/l;

    .line 109
    .line 110
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v0, ", averageSpeed="

    .line 114
    .line 115
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object v0, p0, Ll70/i;->m:Lqr0/p;

    .line 119
    .line 120
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v0, ", averageFuelConsumption="

    .line 124
    .line 125
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    iget-object v0, p0, Ll70/i;->n:Lqr0/i;

    .line 129
    .line 130
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v0, ", totalElectricConsumption="

    .line 134
    .line 135
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    iget-object v0, p0, Ll70/i;->o:Lqr0/h;

    .line 139
    .line 140
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    const-string v0, ", averageElectricConsumption="

    .line 144
    .line 145
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    iget-object v0, p0, Ll70/i;->p:Lqr0/g;

    .line 149
    .line 150
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v0, ", averageGasConsumption="

    .line 154
    .line 155
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    iget-object v0, p0, Ll70/i;->q:Lqr0/j;

    .line 159
    .line 160
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    const-string v0, ", averageRecuperation="

    .line 164
    .line 165
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    iget-object v0, p0, Ll70/i;->r:Lqr0/g;

    .line 169
    .line 170
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    const-string v0, ", averageAuxConsumption="

    .line 174
    .line 175
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    iget-object v0, p0, Ll70/i;->s:Lqr0/i;

    .line 179
    .line 180
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v0, ", fuelCost="

    .line 184
    .line 185
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    iget-object v0, p0, Ll70/i;->t:Ll70/u;

    .line 189
    .line 190
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    const-string v0, ", waypoints="

    .line 194
    .line 195
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    iget-object v0, p0, Ll70/i;->u:Ljava/util/List;

    .line 199
    .line 200
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    const-string v0, ", length="

    .line 204
    .line 205
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    iget-object p0, p0, Ll70/i;->v:Ll70/o;

    .line 209
    .line 210
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    const-string p0, ")"

    .line 214
    .line 215
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    return-object p0
.end method
