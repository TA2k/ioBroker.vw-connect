.class public final Ln50/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/List;

.field public final c:Ljava/util/List;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Lm50/b;

.field public final i:Lql0/g;

.field public final j:Z

.field public final k:Ljava/lang/Integer;

.field public final l:Z

.field public final m:Lhl0/a;

.field public final n:Z

.field public final o:Lyj0/a;

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:Z

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZZZLm50/b;Lql0/g;ZLjava/lang/Integer;ZLhl0/a;ZLyj0/a;ZZZZ)V
    .locals 4

    .line 1
    move v0, p10

    .line 2
    const-string v1, "recentPlaces"

    .line 3
    .line 4
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ln50/o0;->a:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p2, p0, Ln50/o0;->b:Ljava/util/List;

    .line 13
    .line 14
    iput-object p3, p0, Ln50/o0;->c:Ljava/util/List;

    .line 15
    .line 16
    iput-boolean p4, p0, Ln50/o0;->d:Z

    .line 17
    .line 18
    iput-boolean p5, p0, Ln50/o0;->e:Z

    .line 19
    .line 20
    iput-boolean p6, p0, Ln50/o0;->f:Z

    .line 21
    .line 22
    iput-boolean p7, p0, Ln50/o0;->g:Z

    .line 23
    .line 24
    iput-object p8, p0, Ln50/o0;->h:Lm50/b;

    .line 25
    .line 26
    iput-object p9, p0, Ln50/o0;->i:Lql0/g;

    .line 27
    .line 28
    iput-boolean v0, p0, Ln50/o0;->j:Z

    .line 29
    .line 30
    move-object v1, p11

    .line 31
    iput-object v1, p0, Ln50/o0;->k:Ljava/lang/Integer;

    .line 32
    .line 33
    move/from16 v1, p12

    .line 34
    .line 35
    iput-boolean v1, p0, Ln50/o0;->l:Z

    .line 36
    .line 37
    move-object/from16 v1, p13

    .line 38
    .line 39
    iput-object v1, p0, Ln50/o0;->m:Lhl0/a;

    .line 40
    .line 41
    move/from16 v1, p14

    .line 42
    .line 43
    iput-boolean v1, p0, Ln50/o0;->n:Z

    .line 44
    .line 45
    move-object/from16 v1, p15

    .line 46
    .line 47
    iput-object v1, p0, Ln50/o0;->o:Lyj0/a;

    .line 48
    .line 49
    move/from16 v1, p16

    .line 50
    .line 51
    iput-boolean v1, p0, Ln50/o0;->p:Z

    .line 52
    .line 53
    move/from16 v1, p17

    .line 54
    .line 55
    iput-boolean v1, p0, Ln50/o0;->q:Z

    .line 56
    .line 57
    move/from16 v1, p18

    .line 58
    .line 59
    iput-boolean v1, p0, Ln50/o0;->r:Z

    .line 60
    .line 61
    move/from16 v1, p19

    .line 62
    .line 63
    iput-boolean v1, p0, Ln50/o0;->s:Z

    .line 64
    .line 65
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    const/4 v2, 0x0

    .line 70
    const/4 v3, 0x1

    .line 71
    if-eqz v1, :cond_1

    .line 72
    .line 73
    check-cast p2, Ljava/util/Collection;

    .line 74
    .line 75
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-nez p2, :cond_1

    .line 80
    .line 81
    if-eqz p3, :cond_0

    .line 82
    .line 83
    move-object p2, p3

    .line 84
    check-cast p2, Ljava/util/Collection;

    .line 85
    .line 86
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    xor-int/2addr p2, v3

    .line 91
    if-ne p2, v3, :cond_0

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_0
    move p2, v3

    .line 95
    goto :goto_1

    .line 96
    :cond_1
    :goto_0
    move p2, v2

    .line 97
    :goto_1
    iput-boolean p2, p0, Ln50/o0;->t:Z

    .line 98
    .line 99
    if-eqz p4, :cond_2

    .line 100
    .line 101
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 102
    .line 103
    .line 104
    move-result p2

    .line 105
    if-eqz p2, :cond_2

    .line 106
    .line 107
    move p2, v3

    .line 108
    goto :goto_2

    .line 109
    :cond_2
    move p2, v2

    .line 110
    :goto_2
    iput-boolean p2, p0, Ln50/o0;->u:Z

    .line 111
    .line 112
    if-eqz p5, :cond_3

    .line 113
    .line 114
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    if-eqz p2, :cond_3

    .line 119
    .line 120
    move p2, v3

    .line 121
    goto :goto_3

    .line 122
    :cond_3
    move p2, v2

    .line 123
    :goto_3
    iput-boolean p2, p0, Ln50/o0;->v:Z

    .line 124
    .line 125
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 126
    .line 127
    .line 128
    move-result p2

    .line 129
    if-eqz p2, :cond_4

    .line 130
    .line 131
    if-eqz p6, :cond_4

    .line 132
    .line 133
    move p2, v3

    .line 134
    goto :goto_4

    .line 135
    :cond_4
    move p2, v2

    .line 136
    :goto_4
    iput-boolean p2, p0, Ln50/o0;->w:Z

    .line 137
    .line 138
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 139
    .line 140
    .line 141
    move-result p2

    .line 142
    if-nez p2, :cond_5

    .line 143
    .line 144
    if-eqz p3, :cond_5

    .line 145
    .line 146
    invoke-interface {p3}, Ljava/util/List;->isEmpty()Z

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    if-ne p2, v3, :cond_5

    .line 151
    .line 152
    invoke-virtual {p0}, Ln50/o0;->b()Z

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    if-nez p2, :cond_5

    .line 157
    .line 158
    move p2, v3

    .line 159
    goto :goto_5

    .line 160
    :cond_5
    move p2, v2

    .line 161
    :goto_5
    iput-boolean p2, p0, Ln50/o0;->x:Z

    .line 162
    .line 163
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    if-eqz p1, :cond_6

    .line 168
    .line 169
    if-nez p8, :cond_6

    .line 170
    .line 171
    if-eqz v0, :cond_6

    .line 172
    .line 173
    move v2, v3

    .line 174
    :cond_6
    iput-boolean v2, p0, Ln50/o0;->y:Z

    .line 175
    .line 176
    return-void
.end method

.method public static a(Ln50/o0;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZZZLm50/b;Lql0/g;ZLjava/lang/Integer;ZLhl0/a;ZLyj0/a;ZZZZI)Ln50/o0;
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
    iget-object v2, v0, Ln50/o0;->a:Ljava/lang/String;

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
    iget-object v3, v0, Ln50/o0;->b:Ljava/util/List;

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
    iget-object v4, v0, Ln50/o0;->c:Ljava/util/List;

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
    iget-boolean v5, v0, Ln50/o0;->d:Z

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
    iget-boolean v6, v0, Ln50/o0;->e:Z

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
    iget-boolean v7, v0, Ln50/o0;->f:Z

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
    iget-boolean v8, v0, Ln50/o0;->g:Z

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
    iget-object v9, v0, Ln50/o0;->h:Lm50/b;

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
    iget-object v10, v0, Ln50/o0;->i:Lql0/g;

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
    iget-boolean v11, v0, Ln50/o0;->j:Z

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
    iget-object v12, v0, Ln50/o0;->k:Ljava/lang/Integer;

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
    iget-boolean v13, v0, Ln50/o0;->l:Z

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
    iget-object v14, v0, Ln50/o0;->m:Lhl0/a;

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
    iget-boolean v15, v0, Ln50/o0;->n:Z

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move/from16 v15, p14

    .line 130
    .line 131
    :goto_d
    move-object/from16 p3, v4

    .line 132
    .line 133
    and-int/lit16 v4, v1, 0x4000

    .line 134
    .line 135
    if-eqz v4, :cond_e

    .line 136
    .line 137
    iget-object v4, v0, Ln50/o0;->o:Lyj0/a;

    .line 138
    .line 139
    goto :goto_e

    .line 140
    :cond_e
    move-object/from16 v4, p15

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
    iget-boolean v1, v0, Ln50/o0;->p:Z

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
    and-int v16, p20, v16

    .line 157
    .line 158
    move/from16 p16, v1

    .line 159
    .line 160
    if-eqz v16, :cond_10

    .line 161
    .line 162
    iget-boolean v1, v0, Ln50/o0;->q:Z

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
    and-int v16, p20, v16

    .line 170
    .line 171
    move/from16 p17, v1

    .line 172
    .line 173
    if-eqz v16, :cond_11

    .line 174
    .line 175
    iget-boolean v1, v0, Ln50/o0;->r:Z

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
    and-int v16, p20, v16

    .line 183
    .line 184
    move/from16 p18, v1

    .line 185
    .line 186
    if-eqz v16, :cond_12

    .line 187
    .line 188
    iget-boolean v1, v0, Ln50/o0;->s:Z

    .line 189
    .line 190
    goto :goto_12

    .line 191
    :cond_12
    move/from16 v1, p19

    .line 192
    .line 193
    :goto_12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 194
    .line 195
    .line 196
    const-string v0, "searchQuery"

    .line 197
    .line 198
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    const-string v0, "recentPlaces"

    .line 202
    .line 203
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    new-instance v0, Ln50/o0;

    .line 207
    .line 208
    move-object/from16 p0, v0

    .line 209
    .line 210
    move/from16 p19, v1

    .line 211
    .line 212
    move-object/from16 p1, v2

    .line 213
    .line 214
    move-object/from16 p2, v3

    .line 215
    .line 216
    move-object/from16 p15, v4

    .line 217
    .line 218
    move/from16 p4, v5

    .line 219
    .line 220
    move/from16 p5, v6

    .line 221
    .line 222
    move/from16 p6, v7

    .line 223
    .line 224
    move/from16 p7, v8

    .line 225
    .line 226
    move-object/from16 p8, v9

    .line 227
    .line 228
    move-object/from16 p9, v10

    .line 229
    .line 230
    move/from16 p10, v11

    .line 231
    .line 232
    move-object/from16 p11, v12

    .line 233
    .line 234
    move/from16 p12, v13

    .line 235
    .line 236
    move-object/from16 p13, v14

    .line 237
    .line 238
    move/from16 p14, v15

    .line 239
    .line 240
    invoke-direct/range {p0 .. p19}, Ln50/o0;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZZZLm50/b;Lql0/g;ZLjava/lang/Integer;ZLhl0/a;ZLyj0/a;ZZZZ)V

    .line 241
    .line 242
    .line 243
    return-object v0
.end method


# virtual methods
.method public final b()Z
    .locals 1

    .line 1
    iget-object p0, p0, Ln50/o0;->m:Lhl0/a;

    .line 2
    .line 3
    sget-object v0, Lhl0/a;->d:Lhl0/a;

    .line 4
    .line 5
    if-ne p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
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
    instance-of v1, p1, Ln50/o0;

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
    check-cast p1, Ln50/o0;

    .line 12
    .line 13
    iget-object v1, p0, Ln50/o0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ln50/o0;->a:Ljava/lang/String;

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
    iget-object v1, p0, Ln50/o0;->b:Ljava/util/List;

    .line 25
    .line 26
    iget-object v3, p1, Ln50/o0;->b:Ljava/util/List;

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
    iget-object v1, p0, Ln50/o0;->c:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Ln50/o0;->c:Ljava/util/List;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-boolean v1, p0, Ln50/o0;->d:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Ln50/o0;->d:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-boolean v1, p0, Ln50/o0;->e:Z

    .line 54
    .line 55
    iget-boolean v3, p1, Ln50/o0;->e:Z

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean v1, p0, Ln50/o0;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Ln50/o0;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Ln50/o0;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Ln50/o0;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Ln50/o0;->h:Lm50/b;

    .line 75
    .line 76
    iget-object v3, p1, Ln50/o0;->h:Lm50/b;

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
    iget-object v1, p0, Ln50/o0;->i:Lql0/g;

    .line 86
    .line 87
    iget-object v3, p1, Ln50/o0;->i:Lql0/g;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-boolean v1, p0, Ln50/o0;->j:Z

    .line 97
    .line 98
    iget-boolean v3, p1, Ln50/o0;->j:Z

    .line 99
    .line 100
    if-eq v1, v3, :cond_b

    .line 101
    .line 102
    return v2

    .line 103
    :cond_b
    iget-object v1, p0, Ln50/o0;->k:Ljava/lang/Integer;

    .line 104
    .line 105
    iget-object v3, p1, Ln50/o0;->k:Ljava/lang/Integer;

    .line 106
    .line 107
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-nez v1, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    iget-boolean v1, p0, Ln50/o0;->l:Z

    .line 115
    .line 116
    iget-boolean v3, p1, Ln50/o0;->l:Z

    .line 117
    .line 118
    if-eq v1, v3, :cond_d

    .line 119
    .line 120
    return v2

    .line 121
    :cond_d
    iget-object v1, p0, Ln50/o0;->m:Lhl0/a;

    .line 122
    .line 123
    iget-object v3, p1, Ln50/o0;->m:Lhl0/a;

    .line 124
    .line 125
    if-eq v1, v3, :cond_e

    .line 126
    .line 127
    return v2

    .line 128
    :cond_e
    iget-boolean v1, p0, Ln50/o0;->n:Z

    .line 129
    .line 130
    iget-boolean v3, p1, Ln50/o0;->n:Z

    .line 131
    .line 132
    if-eq v1, v3, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-object v1, p0, Ln50/o0;->o:Lyj0/a;

    .line 136
    .line 137
    iget-object v3, p1, Ln50/o0;->o:Lyj0/a;

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
    iget-boolean v1, p0, Ln50/o0;->p:Z

    .line 147
    .line 148
    iget-boolean v3, p1, Ln50/o0;->p:Z

    .line 149
    .line 150
    if-eq v1, v3, :cond_11

    .line 151
    .line 152
    return v2

    .line 153
    :cond_11
    iget-boolean v1, p0, Ln50/o0;->q:Z

    .line 154
    .line 155
    iget-boolean v3, p1, Ln50/o0;->q:Z

    .line 156
    .line 157
    if-eq v1, v3, :cond_12

    .line 158
    .line 159
    return v2

    .line 160
    :cond_12
    iget-boolean v1, p0, Ln50/o0;->r:Z

    .line 161
    .line 162
    iget-boolean v3, p1, Ln50/o0;->r:Z

    .line 163
    .line 164
    if-eq v1, v3, :cond_13

    .line 165
    .line 166
    return v2

    .line 167
    :cond_13
    iget-boolean p0, p0, Ln50/o0;->s:Z

    .line 168
    .line 169
    iget-boolean p1, p1, Ln50/o0;->s:Z

    .line 170
    .line 171
    if-eq p0, p1, :cond_14

    .line 172
    .line 173
    return v2

    .line 174
    :cond_14
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ln50/o0;->a:Ljava/lang/String;

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
    iget-object v2, p0, Ln50/o0;->b:Ljava/util/List;

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
    iget-object v3, p0, Ln50/o0;->c:Ljava/util/List;

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
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

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
    iget-boolean v3, p0, Ln50/o0;->d:Z

    .line 30
    .line 31
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-boolean v3, p0, Ln50/o0;->e:Z

    .line 36
    .line 37
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-boolean v3, p0, Ln50/o0;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-boolean v3, p0, Ln50/o0;->g:Z

    .line 48
    .line 49
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-object v3, p0, Ln50/o0;->h:Lm50/b;

    .line 54
    .line 55
    if-nez v3, :cond_1

    .line 56
    .line 57
    move v3, v2

    .line 58
    goto :goto_1

    .line 59
    :cond_1
    invoke-virtual {v3}, Lm50/b;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_1
    add-int/2addr v0, v3

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object v3, p0, Ln50/o0;->i:Lql0/g;

    .line 66
    .line 67
    if-nez v3, :cond_2

    .line 68
    .line 69
    move v3, v2

    .line 70
    goto :goto_2

    .line 71
    :cond_2
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    :goto_2
    add-int/2addr v0, v3

    .line 76
    mul-int/2addr v0, v1

    .line 77
    iget-boolean v3, p0, Ln50/o0;->j:Z

    .line 78
    .line 79
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-object v3, p0, Ln50/o0;->k:Ljava/lang/Integer;

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
    iget-boolean v3, p0, Ln50/o0;->l:Z

    .line 96
    .line 97
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    iget-object v3, p0, Ln50/o0;->m:Lhl0/a;

    .line 102
    .line 103
    if-nez v3, :cond_4

    .line 104
    .line 105
    move v3, v2

    .line 106
    goto :goto_4

    .line 107
    :cond_4
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_4
    add-int/2addr v0, v3

    .line 112
    mul-int/2addr v0, v1

    .line 113
    iget-boolean v3, p0, Ln50/o0;->n:Z

    .line 114
    .line 115
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    iget-object v3, p0, Ln50/o0;->o:Lyj0/a;

    .line 120
    .line 121
    if-nez v3, :cond_5

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_5
    invoke-virtual {v3}, Lyj0/a;->hashCode()I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    :goto_5
    add-int/2addr v0, v2

    .line 129
    mul-int/2addr v0, v1

    .line 130
    iget-boolean v2, p0, Ln50/o0;->p:Z

    .line 131
    .line 132
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    iget-boolean v2, p0, Ln50/o0;->q:Z

    .line 137
    .line 138
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    iget-boolean v2, p0, Ln50/o0;->r:Z

    .line 143
    .line 144
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    iget-boolean p0, p0, Ln50/o0;->s:Z

    .line 149
    .line 150
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    add-int/2addr p0, v0

    .line 155
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", recentPlaces="

    .line 2
    .line 3
    const-string v1, ", predictions="

    .line 4
    .line 5
    const-string v2, "State(searchQuery="

    .line 6
    .line 7
    iget-object v3, p0, Ln50/o0;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Ln50/o0;->b:Ljava/util/List;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lvj/b;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isDevicePositionAvailable="

    .line 16
    .line 17
    const-string v2, ", isVehiclePositionAvailable="

    .line 18
    .line 19
    iget-object v3, p0, Ln50/o0;->c:Ljava/util/List;

    .line 20
    .line 21
    iget-boolean v4, p0, Ln50/o0;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isSelectOnMapAvailable="

    .line 27
    .line 28
    const-string v2, ", isLoading="

    .line 29
    .line 30
    iget-boolean v3, p0, Ln50/o0;->e:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Ln50/o0;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-boolean v1, p0, Ln50/o0;->g:Z

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", addFavouritePlace="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Ln50/o0;->h:Lm50/b;

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v1, ", error="

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Ln50/o0;->i:Lql0/g;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", showChips="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-boolean v1, p0, Ln50/o0;->j:Z

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", searchPlaceholderRes="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Ln50/o0;->k:Ljava/lang/Integer;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", saveSearchedPlace="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-boolean v1, p0, Ln50/o0;->l:Z

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", mapSearchContext="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    iget-object v1, p0, Ln50/o0;->m:Lhl0/a;

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v1, ", isLauraLoading="

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    iget-boolean v1, p0, Ln50/o0;->n:Z

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", lauraSearchHint="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    iget-object v1, p0, Ln50/o0;->o:Lyj0/a;

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    const-string v1, ", isLauraLoadingAnimationFinished="

    .line 123
    .line 124
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    iget-boolean v1, p0, Ln50/o0;->p:Z

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v1, ", isAIAssistant="

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    const-string v1, ", isLauraIntroDialogVisible="

    .line 138
    .line 139
    const-string v2, ", isLauraIntroOngoing="

    .line 140
    .line 141
    iget-boolean v3, p0, Ln50/o0;->q:Z

    .line 142
    .line 143
    iget-boolean v4, p0, Ln50/o0;->r:Z

    .line 144
    .line 145
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 146
    .line 147
    .line 148
    const-string v1, ")"

    .line 149
    .line 150
    iget-boolean p0, p0, Ln50/o0;->s:Z

    .line 151
    .line 152
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    return-object p0
.end method
