.class public final Lm70/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Lqr0/s;

.field public final e:Ljava/util/List;

.field public final f:Z

.field public final g:Ll70/h;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/util/List;

.field public final j:Ll70/d;

.field public final k:Z

.field public final l:Ljava/lang/String;

.field public final m:Z

.field public final n:Ljava/util/Map;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;

.field public final q:Ljava/lang/String;

.field public final r:Z

.field public final s:Ljava/lang/String;

.field public final t:Z


# direct methods
.method public constructor <init>(ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    move/from16 v0, p13

    .line 2
    .line 3
    move-object/from16 v1, p14

    .line 4
    .line 5
    const-string v2, "unitsType"

    .line 6
    .line 7
    invoke-static {p4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "tabs"

    .line 11
    .line 12
    invoke-static {p5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v2, "prices"

    .line 16
    .line 17
    invoke-static {p9, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string v2, "fuelCosts"

    .line 21
    .line 22
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-boolean p1, p0, Lm70/l;->a:Z

    .line 29
    .line 30
    iput-boolean p2, p0, Lm70/l;->b:Z

    .line 31
    .line 32
    iput-boolean p3, p0, Lm70/l;->c:Z

    .line 33
    .line 34
    iput-object p4, p0, Lm70/l;->d:Lqr0/s;

    .line 35
    .line 36
    iput-object p5, p0, Lm70/l;->e:Ljava/util/List;

    .line 37
    .line 38
    iput-boolean p6, p0, Lm70/l;->f:Z

    .line 39
    .line 40
    iput-object p7, p0, Lm70/l;->g:Ll70/h;

    .line 41
    .line 42
    iput-object p8, p0, Lm70/l;->h:Ljava/lang/String;

    .line 43
    .line 44
    iput-object p9, p0, Lm70/l;->i:Ljava/util/List;

    .line 45
    .line 46
    iput-object p10, p0, Lm70/l;->j:Ll70/d;

    .line 47
    .line 48
    iput-boolean p11, p0, Lm70/l;->k:Z

    .line 49
    .line 50
    iput-object p12, p0, Lm70/l;->l:Ljava/lang/String;

    .line 51
    .line 52
    iput-boolean v0, p0, Lm70/l;->m:Z

    .line 53
    .line 54
    iput-object v1, p0, Lm70/l;->n:Ljava/util/Map;

    .line 55
    .line 56
    move-object/from16 p1, p15

    .line 57
    .line 58
    iput-object p1, p0, Lm70/l;->o:Ljava/lang/String;

    .line 59
    .line 60
    move-object/from16 p1, p16

    .line 61
    .line 62
    iput-object p1, p0, Lm70/l;->p:Ljava/lang/String;

    .line 63
    .line 64
    move-object/from16 p1, p17

    .line 65
    .line 66
    iput-object p1, p0, Lm70/l;->q:Ljava/lang/String;

    .line 67
    .line 68
    check-cast p5, Ljava/util/Collection;

    .line 69
    .line 70
    invoke-interface {p5}, Ljava/util/Collection;->size()I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    const/4 p2, 0x0

    .line 75
    const/4 p3, 0x1

    .line 76
    if-le p1, p3, :cond_0

    .line 77
    .line 78
    move p1, p3

    .line 79
    goto :goto_0

    .line 80
    :cond_0
    move p1, p2

    .line 81
    :goto_0
    iput-boolean p1, p0, Lm70/l;->r:Z

    .line 82
    .line 83
    invoke-interface {v1, p7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    check-cast p1, Ljava/lang/String;

    .line 88
    .line 89
    iput-object p1, p0, Lm70/l;->s:Ljava/lang/String;

    .line 90
    .line 91
    if-eqz v0, :cond_1

    .line 92
    .line 93
    if-nez p1, :cond_1

    .line 94
    .line 95
    move p2, p3

    .line 96
    :cond_1
    iput-boolean p2, p0, Lm70/l;->t:Z

    .line 97
    .line 98
    return-void
.end method

.method public static a(Lm70/l;ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/l;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p18

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-boolean v2, v0, Lm70/l;->a:Z

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
    iget-boolean v3, v0, Lm70/l;->b:Z

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
    iget-boolean v4, v0, Lm70/l;->c:Z

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
    iget-object v5, v0, Lm70/l;->d:Lqr0/s;

    .line 37
    .line 38
    goto :goto_3

    .line 39
    :cond_3
    move-object/from16 v5, p4

    .line 40
    .line 41
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 42
    .line 43
    if-eqz v6, :cond_4

    .line 44
    .line 45
    iget-object v6, v0, Lm70/l;->e:Ljava/util/List;

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
    iget-boolean v7, v0, Lm70/l;->f:Z

    .line 55
    .line 56
    goto :goto_5

    .line 57
    :cond_5
    move/from16 v7, p6

    .line 58
    .line 59
    :goto_5
    and-int/lit8 v8, v1, 0x40

    .line 60
    .line 61
    if-eqz v8, :cond_6

    .line 62
    .line 63
    iget-object v8, v0, Lm70/l;->g:Ll70/h;

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
    iget-object v9, v0, Lm70/l;->h:Ljava/lang/String;

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
    iget-object v10, v0, Lm70/l;->i:Ljava/util/List;

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
    iget-object v11, v0, Lm70/l;->j:Ll70/d;

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
    iget-boolean v12, v0, Lm70/l;->k:Z

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
    iget-object v13, v0, Lm70/l;->l:Ljava/lang/String;

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
    iget-boolean v14, v0, Lm70/l;->m:Z

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
    iget-object v15, v0, Lm70/l;->n:Ljava/util/Map;

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move-object/from16 v15, p14

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
    iget-object v2, v0, Lm70/l;->o:Ljava/lang/String;

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
    iget-object v1, v0, Lm70/l;->p:Ljava/lang/String;

    .line 150
    .line 151
    goto :goto_f

    .line 152
    :cond_f
    move-object/from16 v1, p16

    .line 153
    .line 154
    :goto_f
    const/high16 v16, 0x10000

    .line 155
    .line 156
    and-int v16, p18, v16

    .line 157
    .line 158
    move-object/from16 p16, v1

    .line 159
    .line 160
    if-eqz v16, :cond_10

    .line 161
    .line 162
    iget-object v1, v0, Lm70/l;->q:Ljava/lang/String;

    .line 163
    .line 164
    goto :goto_10

    .line 165
    :cond_10
    move-object/from16 v1, p17

    .line 166
    .line 167
    :goto_10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    const-string v0, "unitsType"

    .line 171
    .line 172
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    const-string v0, "tabs"

    .line 176
    .line 177
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    const-string v0, "title"

    .line 181
    .line 182
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    const-string v0, "prices"

    .line 186
    .line 187
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    const-string v0, "fuelCosts"

    .line 191
    .line 192
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    new-instance v0, Lm70/l;

    .line 196
    .line 197
    move-object/from16 p0, v0

    .line 198
    .line 199
    move-object/from16 p17, v1

    .line 200
    .line 201
    move-object/from16 p15, v2

    .line 202
    .line 203
    move/from16 p2, v3

    .line 204
    .line 205
    move/from16 p3, v4

    .line 206
    .line 207
    move-object/from16 p4, v5

    .line 208
    .line 209
    move-object/from16 p5, v6

    .line 210
    .line 211
    move/from16 p6, v7

    .line 212
    .line 213
    move-object/from16 p7, v8

    .line 214
    .line 215
    move-object/from16 p8, v9

    .line 216
    .line 217
    move-object/from16 p9, v10

    .line 218
    .line 219
    move-object/from16 p10, v11

    .line 220
    .line 221
    move/from16 p11, v12

    .line 222
    .line 223
    move-object/from16 p12, v13

    .line 224
    .line 225
    move/from16 p13, v14

    .line 226
    .line 227
    move-object/from16 p14, v15

    .line 228
    .line 229
    invoke-direct/range {p0 .. p17}, Lm70/l;-><init>(ZZZLqr0/s;Ljava/util/List;ZLl70/h;Ljava/lang/String;Ljava/util/List;Ll70/d;ZLjava/lang/String;ZLjava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
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
    instance-of v1, p1, Lm70/l;

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
    check-cast p1, Lm70/l;

    .line 12
    .line 13
    iget-boolean v1, p0, Lm70/l;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lm70/l;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lm70/l;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lm70/l;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lm70/l;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lm70/l;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Lm70/l;->d:Lqr0/s;

    .line 35
    .line 36
    iget-object v3, p1, Lm70/l;->d:Lqr0/s;

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lm70/l;->e:Ljava/util/List;

    .line 42
    .line 43
    iget-object v3, p1, Lm70/l;->e:Ljava/util/List;

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
    iget-boolean v1, p0, Lm70/l;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Lm70/l;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-object v1, p0, Lm70/l;->g:Ll70/h;

    .line 60
    .line 61
    iget-object v3, p1, Lm70/l;->g:Ll70/h;

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-object v1, p0, Lm70/l;->h:Ljava/lang/String;

    .line 67
    .line 68
    iget-object v3, p1, Lm70/l;->h:Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    if-nez v1, :cond_9

    .line 75
    .line 76
    return v2

    .line 77
    :cond_9
    iget-object v1, p0, Lm70/l;->i:Ljava/util/List;

    .line 78
    .line 79
    iget-object v3, p1, Lm70/l;->i:Ljava/util/List;

    .line 80
    .line 81
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-nez v1, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-object v1, p0, Lm70/l;->j:Ll70/d;

    .line 89
    .line 90
    iget-object v3, p1, Lm70/l;->j:Ll70/d;

    .line 91
    .line 92
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-nez v1, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-boolean v1, p0, Lm70/l;->k:Z

    .line 100
    .line 101
    iget-boolean v3, p1, Lm70/l;->k:Z

    .line 102
    .line 103
    if-eq v1, v3, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    iget-object v1, p0, Lm70/l;->l:Ljava/lang/String;

    .line 107
    .line 108
    iget-object v3, p1, Lm70/l;->l:Ljava/lang/String;

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
    iget-boolean v1, p0, Lm70/l;->m:Z

    .line 118
    .line 119
    iget-boolean v3, p1, Lm70/l;->m:Z

    .line 120
    .line 121
    if-eq v1, v3, :cond_e

    .line 122
    .line 123
    return v2

    .line 124
    :cond_e
    iget-object v1, p0, Lm70/l;->n:Ljava/util/Map;

    .line 125
    .line 126
    iget-object v3, p1, Lm70/l;->n:Ljava/util/Map;

    .line 127
    .line 128
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    if-nez v1, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-object v1, p0, Lm70/l;->o:Ljava/lang/String;

    .line 136
    .line 137
    iget-object v3, p1, Lm70/l;->o:Ljava/lang/String;

    .line 138
    .line 139
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    if-nez v1, :cond_10

    .line 144
    .line 145
    return v2

    .line 146
    :cond_10
    iget-object v1, p0, Lm70/l;->p:Ljava/lang/String;

    .line 147
    .line 148
    iget-object v3, p1, Lm70/l;->p:Ljava/lang/String;

    .line 149
    .line 150
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    if-nez v1, :cond_11

    .line 155
    .line 156
    return v2

    .line 157
    :cond_11
    iget-object p0, p0, Lm70/l;->q:Ljava/lang/String;

    .line 158
    .line 159
    iget-object p1, p1, Lm70/l;->q:Ljava/lang/String;

    .line 160
    .line 161
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-nez p0, :cond_12

    .line 166
    .line 167
    return v2

    .line 168
    :cond_12
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lm70/l;->a:Z

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
    iget-boolean v2, p0, Lm70/l;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lm70/l;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lm70/l;->d:Lqr0/s;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-object v0, p0, Lm70/l;->e:Ljava/util/List;

    .line 31
    .line 32
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-boolean v2, p0, Lm70/l;->f:Z

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    const/4 v2, 0x0

    .line 43
    iget-object v3, p0, Lm70/l;->g:Ll70/h;

    .line 44
    .line 45
    if-nez v3, :cond_0

    .line 46
    .line 47
    move v3, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_0
    add-int/2addr v0, v3

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object v3, p0, Lm70/l;->h:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    iget-object v3, p0, Lm70/l;->i:Ljava/util/List;

    .line 62
    .line 63
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    iget-object v3, p0, Lm70/l;->j:Ll70/d;

    .line 68
    .line 69
    if-nez v3, :cond_1

    .line 70
    .line 71
    move v3, v2

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    invoke-virtual {v3}, Ll70/d;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    :goto_1
    add-int/2addr v0, v3

    .line 78
    mul-int/2addr v0, v1

    .line 79
    iget-boolean v3, p0, Lm70/l;->k:Z

    .line 80
    .line 81
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    iget-object v3, p0, Lm70/l;->l:Ljava/lang/String;

    .line 86
    .line 87
    if-nez v3, :cond_2

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    :goto_2
    add-int/2addr v0, v2

    .line 95
    mul-int/2addr v0, v1

    .line 96
    iget-boolean v2, p0, Lm70/l;->m:Z

    .line 97
    .line 98
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    iget-object v2, p0, Lm70/l;->n:Ljava/util/Map;

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, Lp3/m;->a(IILjava/util/Map;)I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    iget-object v2, p0, Lm70/l;->o:Ljava/lang/String;

    .line 109
    .line 110
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    iget-object v2, p0, Lm70/l;->p:Ljava/lang/String;

    .line 115
    .line 116
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    iget-object p0, p0, Lm70/l;->q:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 123
    .line 124
    .line 125
    move-result p0

    .line 126
    add-int/2addr p0, v0

    .line 127
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isRefreshing="

    .line 2
    .line 3
    const-string v1, ", showTotalPrice="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lm70/l;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lm70/l;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Lm70/l;->c:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", unitsType="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lm70/l;->d:Lqr0/s;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", tabs="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", dataUnavailable="

    .line 36
    .line 37
    const-string v2, ", selectedFuelType="

    .line 38
    .line 39
    iget-object v3, p0, Lm70/l;->e:Ljava/util/List;

    .line 40
    .line 41
    iget-boolean v4, p0, Lm70/l;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lm70/l;->g:Ll70/h;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", title="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lm70/l;->h:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", prices="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    iget-object v1, p0, Lm70/l;->i:Ljava/util/List;

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, ", selectedFuelPrice="

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object v1, p0, Lm70/l;->j:Ll70/d;

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", isDeleting="

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v1, ", statisticsInterval="

    .line 87
    .line 88
    const-string v2, ", isStatisticsLoading="

    .line 89
    .line 90
    iget-object v3, p0, Lm70/l;->l:Ljava/lang/String;

    .line 91
    .line 92
    iget-boolean v4, p0, Lm70/l;->k:Z

    .line 93
    .line 94
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 95
    .line 96
    .line 97
    iget-boolean v1, p0, Lm70/l;->m:Z

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v1, ", fuelCosts="

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    iget-object v1, p0, Lm70/l;->n:Ljava/util/Map;

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", costsTitle="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", pricesTitle="

    .line 118
    .line 119
    const-string v2, ", emptyMessage="

    .line 120
    .line 121
    iget-object v3, p0, Lm70/l;->o:Ljava/lang/String;

    .line 122
    .line 123
    iget-object v4, p0, Lm70/l;->p:Ljava/lang/String;

    .line 124
    .line 125
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    const-string v1, ")"

    .line 129
    .line 130
    iget-object p0, p0, Lm70/l;->q:Ljava/lang/String;

    .line 131
    .line 132
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    return-object p0
.end method
