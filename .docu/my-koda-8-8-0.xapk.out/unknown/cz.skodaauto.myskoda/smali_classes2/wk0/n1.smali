.class public final Lwk0/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Lwk0/m1;

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Lqp0/b0;

.field public final i:Lay0/a;

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:Z

.field public final n:Lwk0/l1;

.field public final o:Z

.field public final p:Z


# direct methods
.method public constructor <init>(Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lay0/a;ZZZZLwk0/l1;ZZ)V
    .locals 1

    const-string v0, "primaryButton"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onPrimaryButtonClick"

    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lwk0/n1;->a:Lql0/g;

    .line 3
    iput-object p2, p0, Lwk0/n1;->b:Lwk0/m1;

    .line 4
    iput-boolean p3, p0, Lwk0/n1;->c:Z

    .line 5
    iput-boolean p4, p0, Lwk0/n1;->d:Z

    .line 6
    iput-boolean p5, p0, Lwk0/n1;->e:Z

    .line 7
    iput-boolean p6, p0, Lwk0/n1;->f:Z

    .line 8
    iput-boolean p7, p0, Lwk0/n1;->g:Z

    .line 9
    iput-object p8, p0, Lwk0/n1;->h:Lqp0/b0;

    .line 10
    iput-object p9, p0, Lwk0/n1;->i:Lay0/a;

    .line 11
    iput-boolean p10, p0, Lwk0/n1;->j:Z

    .line 12
    iput-boolean p11, p0, Lwk0/n1;->k:Z

    .line 13
    iput-boolean p12, p0, Lwk0/n1;->l:Z

    .line 14
    iput-boolean p13, p0, Lwk0/n1;->m:Z

    .line 15
    iput-object p14, p0, Lwk0/n1;->n:Lwk0/l1;

    move/from16 p1, p15

    .line 16
    iput-boolean p1, p0, Lwk0/n1;->o:Z

    move/from16 p1, p16

    .line 17
    iput-boolean p1, p0, Lwk0/n1;->p:Z

    return-void
.end method

.method public synthetic constructor <init>(Lwk0/m1;Lay0/a;I)V
    .locals 20

    move/from16 v0, p3

    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_0

    .line 18
    new-instance v1, Lwk0/m1;

    const/4 v2, 0x7

    invoke-direct {v1, v2}, Lwk0/m1;-><init>(I)V

    move-object v5, v1

    goto :goto_0

    :cond_0
    move-object/from16 v5, p1

    :goto_0
    and-int/lit8 v1, v0, 0x4

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    move v6, v3

    goto :goto_1

    :cond_1
    move v6, v2

    :goto_1
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_2

    .line 19
    new-instance v1, Lz81/g;

    const/4 v4, 0x2

    invoke-direct {v1, v4}, Lz81/g;-><init>(I)V

    move-object v12, v1

    goto :goto_2

    :cond_2
    move-object/from16 v12, p2

    :goto_2
    and-int/lit16 v0, v0, 0x400

    if-eqz v0, :cond_3

    move v14, v2

    goto :goto_3

    :cond_3
    move v14, v3

    .line 20
    :goto_3
    new-instance v0, Lwk0/l1;

    .line 21
    const-string v1, ""

    .line 22
    sget-object v2, Ler0/g;->d:Ler0/g;

    .line 23
    invoke-direct {v0, v2, v1, v1}, Lwk0/l1;-><init>(Ler0/g;Ljava/lang/String;Ljava/lang/String;)V

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/4 v4, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x1

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    move-object/from16 v3, p0

    move-object/from16 v17, v0

    .line 24
    invoke-direct/range {v3 .. v19}, Lwk0/n1;-><init>(Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lay0/a;ZZZZLwk0/l1;ZZ)V

    return-void
.end method

.method public static a(Lwk0/n1;Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lb71/o;ZZZZLwk0/l1;ZI)Lwk0/n1;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p16

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lwk0/n1;->a:Lql0/g;

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
    iget-object v3, v0, Lwk0/n1;->b:Lwk0/m1;

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
    iget-boolean v4, v0, Lwk0/n1;->c:Z

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
    iget-boolean v5, v0, Lwk0/n1;->d:Z

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
    iget-boolean v6, v0, Lwk0/n1;->e:Z

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
    iget-boolean v7, v0, Lwk0/n1;->f:Z

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
    iget-boolean v8, v0, Lwk0/n1;->g:Z

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
    iget-object v9, v0, Lwk0/n1;->h:Lqp0/b0;

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
    iget-object v10, v0, Lwk0/n1;->i:Lay0/a;

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
    iget-boolean v11, v0, Lwk0/n1;->j:Z

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
    iget-boolean v12, v0, Lwk0/n1;->k:Z

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
    iget-boolean v13, v0, Lwk0/n1;->l:Z

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
    iget-boolean v14, v0, Lwk0/n1;->m:Z

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
    iget-object v15, v0, Lwk0/n1;->n:Lwk0/l1;

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
    iget-boolean v2, v0, Lwk0/n1;->o:Z

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
    iget-boolean v1, v0, Lwk0/n1;->p:Z

    .line 150
    .line 151
    goto :goto_f

    .line 152
    :cond_f
    const/4 v1, 0x0

    .line 153
    :goto_f
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    const-string v0, "primaryButton"

    .line 157
    .line 158
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    const-string v0, "onPrimaryButtonClick"

    .line 162
    .line 163
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    const-string v0, "destinationsLicense"

    .line 167
    .line 168
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    new-instance v0, Lwk0/n1;

    .line 172
    .line 173
    move-object/from16 p0, v0

    .line 174
    .line 175
    move/from16 p16, v1

    .line 176
    .line 177
    move/from16 p15, v2

    .line 178
    .line 179
    move-object/from16 p2, v3

    .line 180
    .line 181
    move/from16 p3, v4

    .line 182
    .line 183
    move/from16 p4, v5

    .line 184
    .line 185
    move/from16 p5, v6

    .line 186
    .line 187
    move/from16 p6, v7

    .line 188
    .line 189
    move/from16 p7, v8

    .line 190
    .line 191
    move-object/from16 p8, v9

    .line 192
    .line 193
    move-object/from16 p9, v10

    .line 194
    .line 195
    move/from16 p10, v11

    .line 196
    .line 197
    move/from16 p11, v12

    .line 198
    .line 199
    move/from16 p12, v13

    .line 200
    .line 201
    move/from16 p13, v14

    .line 202
    .line 203
    move-object/from16 p14, v15

    .line 204
    .line 205
    invoke-direct/range {p0 .. p16}, Lwk0/n1;-><init>(Lql0/g;Lwk0/m1;ZZZZZLqp0/b0;Lay0/a;ZZZZLwk0/l1;ZZ)V

    .line 206
    .line 207
    .line 208
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
    instance-of v1, p1, Lwk0/n1;

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
    check-cast p1, Lwk0/n1;

    .line 12
    .line 13
    iget-object v1, p0, Lwk0/n1;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lwk0/n1;->a:Lql0/g;

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
    iget-object v1, p0, Lwk0/n1;->b:Lwk0/m1;

    .line 25
    .line 26
    iget-object v3, p1, Lwk0/n1;->b:Lwk0/m1;

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
    iget-boolean v1, p0, Lwk0/n1;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Lwk0/n1;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-boolean v1, p0, Lwk0/n1;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Lwk0/n1;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-boolean v1, p0, Lwk0/n1;->e:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Lwk0/n1;->e:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-boolean v1, p0, Lwk0/n1;->f:Z

    .line 57
    .line 58
    iget-boolean v3, p1, Lwk0/n1;->f:Z

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-boolean v1, p0, Lwk0/n1;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Lwk0/n1;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-object v1, p0, Lwk0/n1;->h:Lqp0/b0;

    .line 71
    .line 72
    iget-object v3, p1, Lwk0/n1;->h:Lqp0/b0;

    .line 73
    .line 74
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-nez v1, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-object v1, p0, Lwk0/n1;->i:Lay0/a;

    .line 82
    .line 83
    iget-object v3, p1, Lwk0/n1;->i:Lay0/a;

    .line 84
    .line 85
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-nez v1, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-boolean v1, p0, Lwk0/n1;->j:Z

    .line 93
    .line 94
    iget-boolean v3, p1, Lwk0/n1;->j:Z

    .line 95
    .line 96
    if-eq v1, v3, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-boolean v1, p0, Lwk0/n1;->k:Z

    .line 100
    .line 101
    iget-boolean v3, p1, Lwk0/n1;->k:Z

    .line 102
    .line 103
    if-eq v1, v3, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    iget-boolean v1, p0, Lwk0/n1;->l:Z

    .line 107
    .line 108
    iget-boolean v3, p1, Lwk0/n1;->l:Z

    .line 109
    .line 110
    if-eq v1, v3, :cond_d

    .line 111
    .line 112
    return v2

    .line 113
    :cond_d
    iget-boolean v1, p0, Lwk0/n1;->m:Z

    .line 114
    .line 115
    iget-boolean v3, p1, Lwk0/n1;->m:Z

    .line 116
    .line 117
    if-eq v1, v3, :cond_e

    .line 118
    .line 119
    return v2

    .line 120
    :cond_e
    iget-object v1, p0, Lwk0/n1;->n:Lwk0/l1;

    .line 121
    .line 122
    iget-object v3, p1, Lwk0/n1;->n:Lwk0/l1;

    .line 123
    .line 124
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-nez v1, :cond_f

    .line 129
    .line 130
    return v2

    .line 131
    :cond_f
    iget-boolean v1, p0, Lwk0/n1;->o:Z

    .line 132
    .line 133
    iget-boolean v3, p1, Lwk0/n1;->o:Z

    .line 134
    .line 135
    if-eq v1, v3, :cond_10

    .line 136
    .line 137
    return v2

    .line 138
    :cond_10
    iget-boolean p0, p0, Lwk0/n1;->p:Z

    .line 139
    .line 140
    iget-boolean p1, p1, Lwk0/n1;->p:Z

    .line 141
    .line 142
    if-eq p0, p1, :cond_11

    .line 143
    .line 144
    return v2

    .line 145
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lwk0/n1;->a:Lql0/g;

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
    iget-object v3, p0, Lwk0/n1;->b:Lwk0/m1;

    .line 16
    .line 17
    invoke-virtual {v3}, Lwk0/m1;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    add-int/2addr v3, v1

    .line 22
    mul-int/2addr v3, v2

    .line 23
    iget-boolean v1, p0, Lwk0/n1;->c:Z

    .line 24
    .line 25
    invoke-static {v3, v2, v1}, La7/g0;->e(IIZ)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    iget-boolean v3, p0, Lwk0/n1;->d:Z

    .line 30
    .line 31
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    iget-boolean v3, p0, Lwk0/n1;->e:Z

    .line 36
    .line 37
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    iget-boolean v3, p0, Lwk0/n1;->f:Z

    .line 42
    .line 43
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    iget-boolean v3, p0, Lwk0/n1;->g:Z

    .line 48
    .line 49
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    iget-object v3, p0, Lwk0/n1;->h:Lqp0/b0;

    .line 54
    .line 55
    if-nez v3, :cond_1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    invoke-virtual {v3}, Lqp0/b0;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    :goto_1
    add-int/2addr v1, v0

    .line 63
    mul-int/2addr v1, v2

    .line 64
    iget-object v0, p0, Lwk0/n1;->i:Lay0/a;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    add-int/2addr v0, v1

    .line 71
    mul-int/2addr v0, v2

    .line 72
    iget-boolean v1, p0, Lwk0/n1;->j:Z

    .line 73
    .line 74
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-boolean v1, p0, Lwk0/n1;->k:Z

    .line 79
    .line 80
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    iget-boolean v1, p0, Lwk0/n1;->l:Z

    .line 85
    .line 86
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    iget-boolean v1, p0, Lwk0/n1;->m:Z

    .line 91
    .line 92
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    iget-object v1, p0, Lwk0/n1;->n:Lwk0/l1;

    .line 97
    .line 98
    invoke-virtual {v1}, Lwk0/l1;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    add-int/2addr v1, v0

    .line 103
    mul-int/2addr v1, v2

    .line 104
    iget-boolean v0, p0, Lwk0/n1;->o:Z

    .line 105
    .line 106
    invoke-static {v1, v2, v0}, La7/g0;->e(IIZ)I

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    iget-boolean p0, p0, Lwk0/n1;->p:Z

    .line 111
    .line 112
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    add-int/2addr p0, v0

    .line 117
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(error="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lwk0/n1;->a:Lql0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", primaryButton="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lwk0/n1;->b:Lwk0/m1;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isLoading="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isFavouriteAnimating="

    .line 29
    .line 30
    const-string v2, ", isFavouriteEnabled="

    .line 31
    .line 32
    iget-boolean v3, p0, Lwk0/n1;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lwk0/n1;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isFavourite="

    .line 40
    .line 41
    const-string v2, ", isFavouriteVisible="

    .line 42
    .line 43
    iget-boolean v3, p0, Lwk0/n1;->e:Z

    .line 44
    .line 45
    iget-boolean v4, p0, Lwk0/n1;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-boolean v1, p0, Lwk0/n1;->g:Z

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v1, ", waypoint="

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Lwk0/n1;->h:Lqp0/b0;

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string v1, ", onPrimaryButtonClick="

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    iget-object v1, p0, Lwk0/n1;->i:Lay0/a;

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", isRefreshing="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    iget-boolean v1, p0, Lwk0/n1;->j:Z

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", isSendRouteVisible="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, ", isPrivateModeDialogVisible="

    .line 91
    .line 92
    const-string v2, ", isSendingPoiToCar="

    .line 93
    .line 94
    iget-boolean v3, p0, Lwk0/n1;->k:Z

    .line 95
    .line 96
    iget-boolean v4, p0, Lwk0/n1;->l:Z

    .line 97
    .line 98
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    iget-boolean v1, p0, Lwk0/n1;->m:Z

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string v1, ", destinationsLicense="

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    iget-object v1, p0, Lwk0/n1;->n:Lwk0/l1;

    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v1, ", showBottomSheet="

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    const-string v1, ", hideBottomSheet="

    .line 122
    .line 123
    const-string v2, ")"

    .line 124
    .line 125
    iget-boolean v3, p0, Lwk0/n1;->o:Z

    .line 126
    .line 127
    iget-boolean p0, p0, Lwk0/n1;->p:Z

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
