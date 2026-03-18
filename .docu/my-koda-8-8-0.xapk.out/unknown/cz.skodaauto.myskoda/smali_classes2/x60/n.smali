.class public final Lx60/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Z

.field public final o:Z

.field public final p:Z

.field public final q:Lx60/m;

.field public final r:Lql0/g;


# direct methods
.method public constructor <init>(ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lx60/n;->a:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lx60/n;->b:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lx60/n;->c:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lx60/n;->d:Z

    .line 11
    .line 12
    iput-object p5, p0, Lx60/n;->e:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lx60/n;->f:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lx60/n;->g:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lx60/n;->h:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p9, p0, Lx60/n;->i:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p10, p0, Lx60/n;->j:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p11, p0, Lx60/n;->k:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p12, p0, Lx60/n;->l:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p13, p0, Lx60/n;->m:Ljava/lang/String;

    .line 29
    .line 30
    iput-boolean p14, p0, Lx60/n;->n:Z

    .line 31
    .line 32
    iput-boolean p15, p0, Lx60/n;->o:Z

    .line 33
    .line 34
    move/from16 p1, p16

    .line 35
    .line 36
    iput-boolean p1, p0, Lx60/n;->p:Z

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Lx60/n;->q:Lx60/m;

    .line 41
    .line 42
    move-object/from16 p1, p18

    .line 43
    .line 44
    iput-object p1, p0, Lx60/n;->r:Lql0/g;

    .line 45
    .line 46
    return-void
.end method

.method public static a(Lx60/n;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;I)Lx60/n;
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
    iget-boolean v2, v0, Lx60/n;->a:Z

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
    iget-boolean v3, v0, Lx60/n;->b:Z

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
    iget-boolean v4, v0, Lx60/n;->c:Z

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
    iget-boolean v5, v0, Lx60/n;->d:Z

    .line 37
    .line 38
    goto :goto_3

    .line 39
    :cond_3
    const/4 v5, 0x1

    .line 40
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 41
    .line 42
    if-eqz v6, :cond_4

    .line 43
    .line 44
    iget-object v6, v0, Lx60/n;->e:Ljava/lang/String;

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
    iget-object v7, v0, Lx60/n;->f:Ljava/lang/String;

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
    iget-object v8, v0, Lx60/n;->g:Ljava/lang/String;

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
    iget-object v9, v0, Lx60/n;->h:Ljava/lang/String;

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
    iget-object v10, v0, Lx60/n;->i:Ljava/lang/String;

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
    iget-object v11, v0, Lx60/n;->j:Ljava/lang/String;

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
    iget-object v12, v0, Lx60/n;->k:Ljava/lang/String;

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
    iget-object v13, v0, Lx60/n;->l:Ljava/lang/String;

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
    iget-object v14, v0, Lx60/n;->m:Ljava/lang/String;

    .line 117
    .line 118
    goto :goto_c

    .line 119
    :cond_c
    move-object/from16 v14, p12

    .line 120
    .line 121
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 122
    .line 123
    if-eqz v15, :cond_d

    .line 124
    .line 125
    iget-boolean v15, v0, Lx60/n;->n:Z

    .line 126
    .line 127
    goto :goto_d

    .line 128
    :cond_d
    move/from16 v15, p13

    .line 129
    .line 130
    :goto_d
    move/from16 p1, v2

    .line 131
    .line 132
    and-int/lit16 v2, v1, 0x4000

    .line 133
    .line 134
    if-eqz v2, :cond_e

    .line 135
    .line 136
    iget-boolean v2, v0, Lx60/n;->o:Z

    .line 137
    .line 138
    goto :goto_e

    .line 139
    :cond_e
    move/from16 v2, p14

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
    iget-boolean v1, v0, Lx60/n;->p:Z

    .line 149
    .line 150
    goto :goto_f

    .line 151
    :cond_f
    move/from16 v1, p15

    .line 152
    .line 153
    :goto_f
    const/high16 v16, 0x10000

    .line 154
    .line 155
    and-int v16, p18, v16

    .line 156
    .line 157
    move/from16 p2, v1

    .line 158
    .line 159
    if-eqz v16, :cond_10

    .line 160
    .line 161
    iget-object v1, v0, Lx60/n;->q:Lx60/m;

    .line 162
    .line 163
    goto :goto_10

    .line 164
    :cond_10
    move-object/from16 v1, p16

    .line 165
    .line 166
    :goto_10
    const/high16 v16, 0x20000

    .line 167
    .line 168
    and-int v16, p18, v16

    .line 169
    .line 170
    move-object/from16 p3, v1

    .line 171
    .line 172
    if-eqz v16, :cond_11

    .line 173
    .line 174
    iget-object v1, v0, Lx60/n;->r:Lql0/g;

    .line 175
    .line 176
    goto :goto_11

    .line 177
    :cond_11
    move-object/from16 v1, p17

    .line 178
    .line 179
    :goto_11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    new-instance v0, Lx60/n;

    .line 183
    .line 184
    move/from16 p16, p2

    .line 185
    .line 186
    move-object/from16 p17, p3

    .line 187
    .line 188
    move-object/from16 p0, v0

    .line 189
    .line 190
    move-object/from16 p18, v1

    .line 191
    .line 192
    move/from16 p15, v2

    .line 193
    .line 194
    move/from16 p2, v3

    .line 195
    .line 196
    move/from16 p3, v4

    .line 197
    .line 198
    move/from16 p4, v5

    .line 199
    .line 200
    move-object/from16 p5, v6

    .line 201
    .line 202
    move-object/from16 p6, v7

    .line 203
    .line 204
    move-object/from16 p7, v8

    .line 205
    .line 206
    move-object/from16 p8, v9

    .line 207
    .line 208
    move-object/from16 p9, v10

    .line 209
    .line 210
    move-object/from16 p10, v11

    .line 211
    .line 212
    move-object/from16 p11, v12

    .line 213
    .line 214
    move-object/from16 p12, v13

    .line 215
    .line 216
    move-object/from16 p13, v14

    .line 217
    .line 218
    move/from16 p14, v15

    .line 219
    .line 220
    invoke-direct/range {p0 .. p18}, Lx60/n;-><init>(ZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLx60/m;Lql0/g;)V

    .line 221
    .line 222
    .line 223
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
    instance-of v1, p1, Lx60/n;

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
    check-cast p1, Lx60/n;

    .line 12
    .line 13
    iget-boolean v1, p0, Lx60/n;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lx60/n;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lx60/n;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lx60/n;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lx60/n;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lx60/n;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lx60/n;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lx60/n;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lx60/n;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v3, p1, Lx60/n;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lx60/n;->f:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v3, p1, Lx60/n;->f:Ljava/lang/String;

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
    iget-object v1, p0, Lx60/n;->g:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v3, p1, Lx60/n;->g:Ljava/lang/String;

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
    iget-object v1, p0, Lx60/n;->h:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v3, p1, Lx60/n;->h:Ljava/lang/String;

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
    iget-object v1, p0, Lx60/n;->i:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v3, p1, Lx60/n;->i:Ljava/lang/String;

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
    iget-object v1, p0, Lx60/n;->j:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v3, p1, Lx60/n;->j:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object v1, p0, Lx60/n;->k:Ljava/lang/String;

    .line 108
    .line 109
    iget-object v3, p1, Lx60/n;->k:Ljava/lang/String;

    .line 110
    .line 111
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-nez v1, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object v1, p0, Lx60/n;->l:Ljava/lang/String;

    .line 119
    .line 120
    iget-object v3, p1, Lx60/n;->l:Ljava/lang/String;

    .line 121
    .line 122
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-nez v1, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    iget-object v1, p0, Lx60/n;->m:Ljava/lang/String;

    .line 130
    .line 131
    iget-object v3, p1, Lx60/n;->m:Ljava/lang/String;

    .line 132
    .line 133
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-nez v1, :cond_e

    .line 138
    .line 139
    return v2

    .line 140
    :cond_e
    iget-boolean v1, p0, Lx60/n;->n:Z

    .line 141
    .line 142
    iget-boolean v3, p1, Lx60/n;->n:Z

    .line 143
    .line 144
    if-eq v1, v3, :cond_f

    .line 145
    .line 146
    return v2

    .line 147
    :cond_f
    iget-boolean v1, p0, Lx60/n;->o:Z

    .line 148
    .line 149
    iget-boolean v3, p1, Lx60/n;->o:Z

    .line 150
    .line 151
    if-eq v1, v3, :cond_10

    .line 152
    .line 153
    return v2

    .line 154
    :cond_10
    iget-boolean v1, p0, Lx60/n;->p:Z

    .line 155
    .line 156
    iget-boolean v3, p1, Lx60/n;->p:Z

    .line 157
    .line 158
    if-eq v1, v3, :cond_11

    .line 159
    .line 160
    return v2

    .line 161
    :cond_11
    iget-object v1, p0, Lx60/n;->q:Lx60/m;

    .line 162
    .line 163
    iget-object v3, p1, Lx60/n;->q:Lx60/m;

    .line 164
    .line 165
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v1

    .line 169
    if-nez v1, :cond_12

    .line 170
    .line 171
    return v2

    .line 172
    :cond_12
    iget-object p0, p0, Lx60/n;->r:Lql0/g;

    .line 173
    .line 174
    iget-object p1, p1, Lx60/n;->r:Lql0/g;

    .line 175
    .line 176
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    if-nez p0, :cond_13

    .line 181
    .line 182
    return v2

    .line 183
    :cond_13
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lx60/n;->a:Z

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
    iget-boolean v2, p0, Lx60/n;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lx60/n;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lx60/n;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v2, 0x0

    .line 29
    iget-object v3, p0, Lx60/n;->e:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v3, :cond_0

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_0
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Lx60/n;->f:Ljava/lang/String;

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
    iget-object v3, p0, Lx60/n;->g:Ljava/lang/String;

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
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

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
    iget-object v3, p0, Lx60/n;->h:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v3, :cond_3

    .line 68
    .line 69
    move v3, v2

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    :goto_3
    add-int/2addr v0, v3

    .line 76
    mul-int/2addr v0, v1

    .line 77
    iget-object v3, p0, Lx60/n;->i:Ljava/lang/String;

    .line 78
    .line 79
    if-nez v3, :cond_4

    .line 80
    .line 81
    move v3, v2

    .line 82
    goto :goto_4

    .line 83
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    :goto_4
    add-int/2addr v0, v3

    .line 88
    mul-int/2addr v0, v1

    .line 89
    iget-object v3, p0, Lx60/n;->j:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v3, :cond_5

    .line 92
    .line 93
    move v3, v2

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    :goto_5
    add-int/2addr v0, v3

    .line 100
    mul-int/2addr v0, v1

    .line 101
    iget-object v3, p0, Lx60/n;->k:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v3, :cond_6

    .line 104
    .line 105
    move v3, v2

    .line 106
    goto :goto_6

    .line 107
    :cond_6
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_6
    add-int/2addr v0, v3

    .line 112
    mul-int/2addr v0, v1

    .line 113
    iget-object v3, p0, Lx60/n;->l:Ljava/lang/String;

    .line 114
    .line 115
    if-nez v3, :cond_7

    .line 116
    .line 117
    move v3, v2

    .line 118
    goto :goto_7

    .line 119
    :cond_7
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    :goto_7
    add-int/2addr v0, v3

    .line 124
    mul-int/2addr v0, v1

    .line 125
    iget-object v3, p0, Lx60/n;->m:Ljava/lang/String;

    .line 126
    .line 127
    if-nez v3, :cond_8

    .line 128
    .line 129
    move v3, v2

    .line 130
    goto :goto_8

    .line 131
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    :goto_8
    add-int/2addr v0, v3

    .line 136
    mul-int/2addr v0, v1

    .line 137
    iget-boolean v3, p0, Lx60/n;->n:Z

    .line 138
    .line 139
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    iget-boolean v3, p0, Lx60/n;->o:Z

    .line 144
    .line 145
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    iget-boolean v3, p0, Lx60/n;->p:Z

    .line 150
    .line 151
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    iget-object v3, p0, Lx60/n;->q:Lx60/m;

    .line 156
    .line 157
    if-nez v3, :cond_9

    .line 158
    .line 159
    move v3, v2

    .line 160
    goto :goto_9

    .line 161
    :cond_9
    invoke-virtual {v3}, Lx60/m;->hashCode()I

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    :goto_9
    add-int/2addr v0, v3

    .line 166
    mul-int/2addr v0, v1

    .line 167
    iget-object p0, p0, Lx60/n;->r:Lql0/g;

    .line 168
    .line 169
    if-nez p0, :cond_a

    .line 170
    .line 171
    goto :goto_a

    .line 172
    :cond_a
    invoke-virtual {p0}, Lql0/g;->hashCode()I

    .line 173
    .line 174
    .line 175
    move-result v2

    .line 176
    :goto_a
    add-int/2addr v0, v2

    .line 177
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isLoading="

    .line 2
    .line 3
    const-string v1, ", isRefreshing="

    .line 4
    .line 5
    const-string v2, "State(isDeleteUserConfirmationVisible="

    .line 6
    .line 7
    iget-boolean v3, p0, Lx60/n;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lx60/n;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isSigningOut="

    .line 16
    .line 17
    const-string v2, ", username="

    .line 18
    .line 19
    iget-boolean v3, p0, Lx60/n;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lx60/n;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", nickname="

    .line 27
    .line 28
    const-string v2, ", email="

    .line 29
    .line 30
    iget-object v3, p0, Lx60/n;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Lx60/n;->f:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", phone="

    .line 38
    .line 39
    const-string v2, ", birthday="

    .line 40
    .line 41
    iget-object v3, p0, Lx60/n;->g:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v4, p0, Lx60/n;->h:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v1, ", country="

    .line 49
    .line 50
    const-string v2, ", preferredContact="

    .line 51
    .line 52
    iget-object v3, p0, Lx60/n;->i:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v4, p0, Lx60/n;->j:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v1, ", contactLanguage="

    .line 60
    .line 61
    const-string v2, ", profilePictureUrl="

    .line 62
    .line 63
    iget-object v3, p0, Lx60/n;->k:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v4, p0, Lx60/n;->l:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v1, ", showBottomSheet="

    .line 71
    .line 72
    const-string v2, ", hideBottomSheet="

    .line 73
    .line 74
    iget-object v3, p0, Lx60/n;->m:Ljava/lang/String;

    .line 75
    .line 76
    iget-boolean v4, p0, Lx60/n;->n:Z

    .line 77
    .line 78
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 79
    .line 80
    .line 81
    const-string v1, ", addUserPhoneDialogVisible="

    .line 82
    .line 83
    const-string v2, ", contactChannelState="

    .line 84
    .line 85
    iget-boolean v3, p0, Lx60/n;->o:Z

    .line 86
    .line 87
    iget-boolean v4, p0, Lx60/n;->p:Z

    .line 88
    .line 89
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    iget-object v1, p0, Lx60/n;->q:Lx60/m;

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", error="

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lx60/n;->r:Lql0/g;

    .line 103
    .line 104
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    const-string p0, ")"

    .line 108
    .line 109
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0
.end method
