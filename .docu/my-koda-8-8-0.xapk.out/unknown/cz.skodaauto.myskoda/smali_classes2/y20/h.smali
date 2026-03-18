.class public final Ly20/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Ljava/util/List;

.field public final j:Ljava/lang/String;

.field public final k:Z

.field public final l:Z

.field public final m:Z

.field public final n:Z

.field public final o:Z

.field public final p:Lx20/c;


# direct methods
.method public constructor <init>(Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;)V
    .locals 1

    .line 1
    const-string v0, "vehicleCards"

    .line 2
    .line 3
    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ly20/h;->a:Lql0/g;

    .line 10
    .line 11
    iput-boolean p2, p0, Ly20/h;->b:Z

    .line 12
    .line 13
    iput-boolean p3, p0, Ly20/h;->c:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Ly20/h;->d:Z

    .line 16
    .line 17
    iput-boolean p5, p0, Ly20/h;->e:Z

    .line 18
    .line 19
    iput-boolean p6, p0, Ly20/h;->f:Z

    .line 20
    .line 21
    iput-boolean p7, p0, Ly20/h;->g:Z

    .line 22
    .line 23
    iput-boolean p8, p0, Ly20/h;->h:Z

    .line 24
    .line 25
    iput-object p9, p0, Ly20/h;->i:Ljava/util/List;

    .line 26
    .line 27
    iput-object p10, p0, Ly20/h;->j:Ljava/lang/String;

    .line 28
    .line 29
    iput-boolean p11, p0, Ly20/h;->k:Z

    .line 30
    .line 31
    iput-boolean p12, p0, Ly20/h;->l:Z

    .line 32
    .line 33
    iput-boolean p13, p0, Ly20/h;->m:Z

    .line 34
    .line 35
    iput-boolean p14, p0, Ly20/h;->n:Z

    .line 36
    .line 37
    move/from16 p1, p15

    .line 38
    .line 39
    iput-boolean p1, p0, Ly20/h;->o:Z

    .line 40
    .line 41
    move-object/from16 p1, p16

    .line 42
    .line 43
    iput-object p1, p0, Ly20/h;->p:Lx20/c;

    .line 44
    .line 45
    return-void
.end method

.method public static a(Ly20/h;Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;I)Ly20/h;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p17

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Ly20/h;->a:Lql0/g;

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
    iget-boolean v3, v0, Ly20/h;->b:Z

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
    iget-boolean v4, v0, Ly20/h;->c:Z

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
    iget-boolean v5, v0, Ly20/h;->d:Z

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
    iget-boolean v6, v0, Ly20/h;->e:Z

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
    iget-boolean v7, v0, Ly20/h;->f:Z

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
    iget-boolean v8, v0, Ly20/h;->g:Z

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
    iget-boolean v9, v0, Ly20/h;->h:Z

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
    iget-object v10, v0, Ly20/h;->i:Ljava/util/List;

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
    iget-object v11, v0, Ly20/h;->j:Ljava/lang/String;

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
    iget-boolean v12, v0, Ly20/h;->k:Z

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
    iget-boolean v13, v0, Ly20/h;->l:Z

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
    iget-boolean v14, v0, Ly20/h;->m:Z

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
    iget-boolean v15, v0, Ly20/h;->n:Z

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move/from16 v15, p14

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
    iget-boolean v2, v0, Ly20/h;->o:Z

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
    and-int v1, v1, v16

    .line 146
    .line 147
    if-eqz v1, :cond_f

    .line 148
    .line 149
    iget-object v1, v0, Ly20/h;->p:Lx20/c;

    .line 150
    .line 151
    goto :goto_f

    .line 152
    :cond_f
    move-object/from16 v1, p16

    .line 153
    .line 154
    :goto_f
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    const-string v0, "vehicleCards"

    .line 158
    .line 159
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    new-instance v0, Ly20/h;

    .line 163
    .line 164
    move-object/from16 p0, v0

    .line 165
    .line 166
    move-object/from16 p16, v1

    .line 167
    .line 168
    move/from16 p15, v2

    .line 169
    .line 170
    move/from16 p2, v3

    .line 171
    .line 172
    move/from16 p3, v4

    .line 173
    .line 174
    move/from16 p4, v5

    .line 175
    .line 176
    move/from16 p5, v6

    .line 177
    .line 178
    move/from16 p6, v7

    .line 179
    .line 180
    move/from16 p7, v8

    .line 181
    .line 182
    move/from16 p8, v9

    .line 183
    .line 184
    move-object/from16 p9, v10

    .line 185
    .line 186
    move-object/from16 p10, v11

    .line 187
    .line 188
    move/from16 p11, v12

    .line 189
    .line 190
    move/from16 p12, v13

    .line 191
    .line 192
    move/from16 p13, v14

    .line 193
    .line 194
    move/from16 p14, v15

    .line 195
    .line 196
    invoke-direct/range {p0 .. p16}, Ly20/h;-><init>(Lql0/g;ZZZZZZZLjava/util/List;Ljava/lang/String;ZZZZZLx20/c;)V

    .line 197
    .line 198
    .line 199
    return-object v0
.end method


# virtual methods
.method public final b()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ly20/h;->i:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Ly20/h;->d:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget-boolean v0, p0, Ly20/h;->b:Z

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    iget-boolean p0, p0, Ly20/h;->n:Z

    .line 18
    .line 19
    if-nez p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
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
    instance-of v1, p1, Ly20/h;

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
    check-cast p1, Ly20/h;

    .line 12
    .line 13
    iget-object v1, p0, Ly20/h;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Ly20/h;->a:Lql0/g;

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
    iget-boolean v1, p0, Ly20/h;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Ly20/h;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Ly20/h;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Ly20/h;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Ly20/h;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Ly20/h;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Ly20/h;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Ly20/h;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean v1, p0, Ly20/h;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Ly20/h;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-boolean v1, p0, Ly20/h;->g:Z

    .line 60
    .line 61
    iget-boolean v3, p1, Ly20/h;->g:Z

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-boolean v1, p0, Ly20/h;->h:Z

    .line 67
    .line 68
    iget-boolean v3, p1, Ly20/h;->h:Z

    .line 69
    .line 70
    if-eq v1, v3, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-object v1, p0, Ly20/h;->i:Ljava/util/List;

    .line 74
    .line 75
    iget-object v3, p1, Ly20/h;->i:Ljava/util/List;

    .line 76
    .line 77
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-object v1, p1, Ly20/h;->j:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v3, p0, Ly20/h;->j:Ljava/lang/String;

    .line 87
    .line 88
    if-nez v3, :cond_c

    .line 89
    .line 90
    if-nez v1, :cond_b

    .line 91
    .line 92
    move v1, v0

    .line 93
    goto :goto_1

    .line 94
    :cond_b
    :goto_0
    move v1, v2

    .line 95
    goto :goto_1

    .line 96
    :cond_c
    if-nez v1, :cond_d

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_d
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    :goto_1
    if-nez v1, :cond_e

    .line 104
    .line 105
    return v2

    .line 106
    :cond_e
    iget-boolean v1, p0, Ly20/h;->k:Z

    .line 107
    .line 108
    iget-boolean v3, p1, Ly20/h;->k:Z

    .line 109
    .line 110
    if-eq v1, v3, :cond_f

    .line 111
    .line 112
    return v2

    .line 113
    :cond_f
    iget-boolean v1, p0, Ly20/h;->l:Z

    .line 114
    .line 115
    iget-boolean v3, p1, Ly20/h;->l:Z

    .line 116
    .line 117
    if-eq v1, v3, :cond_10

    .line 118
    .line 119
    return v2

    .line 120
    :cond_10
    iget-boolean v1, p0, Ly20/h;->m:Z

    .line 121
    .line 122
    iget-boolean v3, p1, Ly20/h;->m:Z

    .line 123
    .line 124
    if-eq v1, v3, :cond_11

    .line 125
    .line 126
    return v2

    .line 127
    :cond_11
    iget-boolean v1, p0, Ly20/h;->n:Z

    .line 128
    .line 129
    iget-boolean v3, p1, Ly20/h;->n:Z

    .line 130
    .line 131
    if-eq v1, v3, :cond_12

    .line 132
    .line 133
    return v2

    .line 134
    :cond_12
    iget-boolean v1, p0, Ly20/h;->o:Z

    .line 135
    .line 136
    iget-boolean v3, p1, Ly20/h;->o:Z

    .line 137
    .line 138
    if-eq v1, v3, :cond_13

    .line 139
    .line 140
    return v2

    .line 141
    :cond_13
    iget-object p0, p0, Ly20/h;->p:Lx20/c;

    .line 142
    .line 143
    iget-object p1, p1, Ly20/h;->p:Lx20/c;

    .line 144
    .line 145
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    if-nez p0, :cond_14

    .line 150
    .line 151
    return v2

    .line 152
    :cond_14
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ly20/h;->a:Lql0/g;

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
    iget-boolean v3, p0, Ly20/h;->b:Z

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-boolean v3, p0, Ly20/h;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-boolean v3, p0, Ly20/h;->d:Z

    .line 28
    .line 29
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-boolean v3, p0, Ly20/h;->e:Z

    .line 34
    .line 35
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    iget-boolean v3, p0, Ly20/h;->f:Z

    .line 40
    .line 41
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iget-boolean v3, p0, Ly20/h;->g:Z

    .line 46
    .line 47
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    iget-boolean v3, p0, Ly20/h;->h:Z

    .line 52
    .line 53
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget-object v3, p0, Ly20/h;->i:Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v1, v2, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    iget-object v3, p0, Ly20/h;->j:Ljava/lang/String;

    .line 64
    .line 65
    if-nez v3, :cond_1

    .line 66
    .line 67
    move v3, v0

    .line 68
    goto :goto_1

    .line 69
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    :goto_1
    add-int/2addr v1, v3

    .line 74
    mul-int/2addr v1, v2

    .line 75
    iget-boolean v3, p0, Ly20/h;->k:Z

    .line 76
    .line 77
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    iget-boolean v3, p0, Ly20/h;->l:Z

    .line 82
    .line 83
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    iget-boolean v3, p0, Ly20/h;->m:Z

    .line 88
    .line 89
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    iget-boolean v3, p0, Ly20/h;->n:Z

    .line 94
    .line 95
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    iget-boolean v3, p0, Ly20/h;->o:Z

    .line 100
    .line 101
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    iget-object p0, p0, Ly20/h;->p:Lx20/c;

    .line 106
    .line 107
    if-nez p0, :cond_2

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    :goto_2
    add-int/2addr v1, v0

    .line 115
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Ly20/h;->j:Ljava/lang/String;

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
    const-string v1, ", isFetchGarageFail="

    .line 13
    .line 14
    const-string v2, ", isFetchGarageSuccess="

    .line 15
    .line 16
    const-string v3, "State(error="

    .line 17
    .line 18
    iget-object v4, p0, Ly20/h;->a:Lql0/g;

    .line 19
    .line 20
    iget-boolean v5, p0, Ly20/h;->b:Z

    .line 21
    .line 22
    invoke-static {v3, v4, v1, v5, v2}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    const-string v2, ", isLoading="

    .line 27
    .line 28
    const-string v3, ", isRefreshing="

    .line 29
    .line 30
    iget-boolean v4, p0, Ly20/h;->c:Z

    .line 31
    .line 32
    iget-boolean v5, p0, Ly20/h;->d:Z

    .line 33
    .line 34
    invoke-static {v1, v4, v2, v5, v3}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v2, ", isDeleteLoading="

    .line 38
    .line 39
    const-string v3, ", isBackupLoading="

    .line 40
    .line 41
    iget-boolean v4, p0, Ly20/h;->e:Z

    .line 42
    .line 43
    iget-boolean v5, p0, Ly20/h;->f:Z

    .line 44
    .line 45
    invoke-static {v1, v4, v2, v5, v3}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v2, ", isDemo="

    .line 49
    .line 50
    const-string v3, ", vehicleCards="

    .line 51
    .line 52
    iget-boolean v4, p0, Ly20/h;->g:Z

    .line 53
    .line 54
    iget-boolean v5, p0, Ly20/h;->h:Z

    .line 55
    .line 56
    invoke-static {v1, v4, v2, v5, v3}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v2, p0, Ly20/h;->i:Ljava/util/List;

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v2, ", selectedVinForAction="

    .line 65
    .line 66
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v0, ", isDeleteWithBackupDialogVisible="

    .line 73
    .line 74
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v0, ", isDeleteDialogVisible="

    .line 78
    .line 79
    const-string v2, ", loadingVehicle="

    .line 80
    .line 81
    iget-boolean v3, p0, Ly20/h;->k:Z

    .line 82
    .line 83
    iget-boolean v4, p0, Ly20/h;->l:Z

    .line 84
    .line 85
    invoke-static {v1, v3, v0, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 86
    .line 87
    .line 88
    const-string v0, ", expectGarageUpdate="

    .line 89
    .line 90
    const-string v2, ", shouldShowTestDriveCard="

    .line 91
    .line 92
    iget-boolean v3, p0, Ly20/h;->m:Z

    .line 93
    .line 94
    iget-boolean v4, p0, Ly20/h;->n:Z

    .line 95
    .line 96
    invoke-static {v1, v3, v0, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 97
    .line 98
    .line 99
    iget-boolean v0, p0, Ly20/h;->o:Z

    .line 100
    .line 101
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string v0, ", lastGarageVehicleStatesEvent="

    .line 105
    .line 106
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    iget-object p0, p0, Ly20/h;->p:Lx20/c;

    .line 110
    .line 111
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string p0, ")"

    .line 115
    .line 116
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0
.end method
