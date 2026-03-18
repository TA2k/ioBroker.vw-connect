.class public final Lc70/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Llf0/i;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Lvf0/k;

.field public final k:Lvf0/k;

.field public final l:F

.field public final m:Ljava/lang/Float;

.field public final n:Lvf0/l;

.field public final o:Lvf0/l;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Llf0/i;)V
    .locals 16

    move/from16 v0, p1

    .line 1
    sget-object v10, Lvf0/k;->d:Lvf0/k;

    .line 2
    sget-object v1, Lvf0/l;->f:Lvf0/l;

    and-int/lit8 v2, v0, 0x1

    if-eqz v2, :cond_0

    .line 3
    sget-object v2, Llf0/i;->j:Llf0/i;

    goto :goto_0

    :cond_0
    move-object/from16 v2, p3

    :goto_0
    and-int/lit8 v3, v0, 0x2

    .line 4
    const-string v4, ""

    if-eqz v3, :cond_1

    move-object v3, v4

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v5, v0, 0x4

    if-eqz v5, :cond_2

    move-object v5, v4

    goto :goto_2

    :cond_2
    const-string v5, "1 km"

    :goto_2
    and-int/lit8 v6, v0, 0x8

    if-eqz v6, :cond_3

    goto :goto_3

    :cond_3
    const-string v4, "Refill AdBlue"

    :goto_3
    and-int/lit8 v6, v0, 0x20

    if-eqz v6, :cond_4

    const/4 v6, 0x1

    goto :goto_4

    :cond_4
    const/4 v6, 0x0

    :goto_4
    and-int/lit16 v7, v0, 0x800

    if-eqz v7, :cond_5

    const/4 v7, 0x0

    :goto_5
    move v12, v7

    goto :goto_6

    :cond_5
    const v7, 0x3dcccccd    # 0.1f

    goto :goto_5

    :goto_6
    and-int/lit16 v0, v0, 0x2000

    if-eqz v0, :cond_6

    .line 5
    sget-object v1, Lvf0/l;->d:Lvf0/l;

    :cond_6
    move-object v14, v1

    move-object v1, v2

    move-object v2, v3

    move-object v3, v5

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v15, 0x0

    move-object/from16 v0, p0

    .line 6
    invoke-direct/range {v0 .. v15}, Lc70/d;-><init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;)V

    return-void
.end method

.method public constructor <init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;)V
    .locals 2

    move-object/from16 v0, p14

    const-string v1, "viewMode"

    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "title"

    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "range"

    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "adBlueWarning"

    invoke-static {p4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "primaryEngineIcon"

    invoke-static {p10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "primaryRangeStatus"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lc70/d;->a:Llf0/i;

    .line 9
    iput-object p2, p0, Lc70/d;->b:Ljava/lang/String;

    .line 10
    iput-object p3, p0, Lc70/d;->c:Ljava/lang/String;

    .line 11
    iput-object p4, p0, Lc70/d;->d:Ljava/lang/String;

    .line 12
    iput-boolean p5, p0, Lc70/d;->e:Z

    .line 13
    iput-boolean p6, p0, Lc70/d;->f:Z

    .line 14
    iput-boolean p7, p0, Lc70/d;->g:Z

    .line 15
    iput-boolean p8, p0, Lc70/d;->h:Z

    .line 16
    iput-boolean p9, p0, Lc70/d;->i:Z

    .line 17
    iput-object p10, p0, Lc70/d;->j:Lvf0/k;

    .line 18
    iput-object p11, p0, Lc70/d;->k:Lvf0/k;

    .line 19
    iput p12, p0, Lc70/d;->l:F

    .line 20
    iput-object p13, p0, Lc70/d;->m:Ljava/lang/Float;

    .line 21
    iput-object v0, p0, Lc70/d;->n:Lvf0/l;

    move-object/from16 p1, p15

    .line 22
    iput-object p1, p0, Lc70/d;->o:Lvf0/l;

    return-void
.end method

.method public static a(Lc70/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;I)Lc70/d;
    .locals 16

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
    iget-object v2, v0, Lc70/d;->a:Llf0/i;

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
    iget-object v3, v0, Lc70/d;->b:Ljava/lang/String;

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
    iget-object v4, v0, Lc70/d;->c:Ljava/lang/String;

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
    iget-object v5, v0, Lc70/d;->d:Ljava/lang/String;

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
    iget-boolean v6, v0, Lc70/d;->e:Z

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
    iget-boolean v7, v0, Lc70/d;->f:Z

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
    iget-boolean v8, v0, Lc70/d;->g:Z

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
    iget-boolean v9, v0, Lc70/d;->h:Z

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
    iget-boolean v10, v0, Lc70/d;->i:Z

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
    iget-object v11, v0, Lc70/d;->j:Lvf0/k;

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
    iget-object v12, v0, Lc70/d;->k:Lvf0/k;

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
    iget v13, v0, Lc70/d;->l:F

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
    iget-object v14, v0, Lc70/d;->m:Ljava/lang/Float;

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
    iget-object v15, v0, Lc70/d;->n:Lvf0/l;

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move-object/from16 v15, p14

    .line 130
    .line 131
    :goto_d
    and-int/lit16 v1, v1, 0x4000

    .line 132
    .line 133
    if-eqz v1, :cond_e

    .line 134
    .line 135
    iget-object v1, v0, Lc70/d;->o:Lvf0/l;

    .line 136
    .line 137
    goto :goto_e

    .line 138
    :cond_e
    move-object/from16 v1, p15

    .line 139
    .line 140
    :goto_e
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    const-string v0, "viewMode"

    .line 144
    .line 145
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    const-string v0, "title"

    .line 149
    .line 150
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    const-string v0, "range"

    .line 154
    .line 155
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    const-string v0, "adBlueWarning"

    .line 159
    .line 160
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    const-string v0, "primaryEngineIcon"

    .line 164
    .line 165
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    const-string v0, "primaryRangeStatus"

    .line 169
    .line 170
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    new-instance v0, Lc70/d;

    .line 174
    .line 175
    move-object/from16 p0, v0

    .line 176
    .line 177
    move-object/from16 p15, v1

    .line 178
    .line 179
    move-object/from16 p1, v2

    .line 180
    .line 181
    move-object/from16 p2, v3

    .line 182
    .line 183
    move-object/from16 p3, v4

    .line 184
    .line 185
    move-object/from16 p4, v5

    .line 186
    .line 187
    move/from16 p5, v6

    .line 188
    .line 189
    move/from16 p6, v7

    .line 190
    .line 191
    move/from16 p7, v8

    .line 192
    .line 193
    move/from16 p8, v9

    .line 194
    .line 195
    move/from16 p9, v10

    .line 196
    .line 197
    move-object/from16 p10, v11

    .line 198
    .line 199
    move-object/from16 p11, v12

    .line 200
    .line 201
    move/from16 p12, v13

    .line 202
    .line 203
    move-object/from16 p13, v14

    .line 204
    .line 205
    move-object/from16 p14, v15

    .line 206
    .line 207
    invoke-direct/range {p0 .. p15}, Lc70/d;-><init>(Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;)V

    .line 208
    .line 209
    .line 210
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
    instance-of v1, p1, Lc70/d;

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
    check-cast p1, Lc70/d;

    .line 12
    .line 13
    iget-object v1, p0, Lc70/d;->a:Llf0/i;

    .line 14
    .line 15
    iget-object v3, p1, Lc70/d;->a:Llf0/i;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lc70/d;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lc70/d;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lc70/d;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lc70/d;->c:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lc70/d;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lc70/d;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-boolean v1, p0, Lc70/d;->e:Z

    .line 54
    .line 55
    iget-boolean v3, p1, Lc70/d;->e:Z

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean v1, p0, Lc70/d;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Lc70/d;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Lc70/d;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Lc70/d;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean v1, p0, Lc70/d;->h:Z

    .line 75
    .line 76
    iget-boolean v3, p1, Lc70/d;->h:Z

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-boolean v1, p0, Lc70/d;->i:Z

    .line 82
    .line 83
    iget-boolean v3, p1, Lc70/d;->i:Z

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-object v1, p0, Lc70/d;->j:Lvf0/k;

    .line 89
    .line 90
    iget-object v3, p1, Lc70/d;->j:Lvf0/k;

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-object v1, p0, Lc70/d;->k:Lvf0/k;

    .line 96
    .line 97
    iget-object v3, p1, Lc70/d;->k:Lvf0/k;

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget v1, p0, Lc70/d;->l:F

    .line 103
    .line 104
    iget v3, p1, Lc70/d;->l:F

    .line 105
    .line 106
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    if-eqz v1, :cond_d

    .line 111
    .line 112
    return v2

    .line 113
    :cond_d
    iget-object v1, p0, Lc70/d;->m:Ljava/lang/Float;

    .line 114
    .line 115
    iget-object v3, p1, Lc70/d;->m:Ljava/lang/Float;

    .line 116
    .line 117
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-nez v1, :cond_e

    .line 122
    .line 123
    return v2

    .line 124
    :cond_e
    iget-object v1, p0, Lc70/d;->n:Lvf0/l;

    .line 125
    .line 126
    iget-object v3, p1, Lc70/d;->n:Lvf0/l;

    .line 127
    .line 128
    if-eq v1, v3, :cond_f

    .line 129
    .line 130
    return v2

    .line 131
    :cond_f
    iget-object p0, p0, Lc70/d;->o:Lvf0/l;

    .line 132
    .line 133
    iget-object p1, p1, Lc70/d;->o:Lvf0/l;

    .line 134
    .line 135
    if-eq p0, p1, :cond_10

    .line 136
    .line 137
    return v2

    .line 138
    :cond_10
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lc70/d;->a:Llf0/i;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lc70/d;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lc70/d;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lc70/d;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lc70/d;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lc70/d;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lc70/d;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Lc70/d;->h:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Lc70/d;->i:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object v2, p0, Lc70/d;->j:Lvf0/k;

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    add-int/2addr v2, v0

    .line 65
    mul-int/2addr v2, v1

    .line 66
    const/4 v0, 0x0

    .line 67
    iget-object v3, p0, Lc70/d;->k:Lvf0/k;

    .line 68
    .line 69
    if-nez v3, :cond_0

    .line 70
    .line 71
    move v3, v0

    .line 72
    goto :goto_0

    .line 73
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    :goto_0
    add-int/2addr v2, v3

    .line 78
    mul-int/2addr v2, v1

    .line 79
    iget v3, p0, Lc70/d;->l:F

    .line 80
    .line 81
    invoke-static {v3, v2, v1}, La7/g0;->c(FII)I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    iget-object v3, p0, Lc70/d;->m:Ljava/lang/Float;

    .line 86
    .line 87
    if-nez v3, :cond_1

    .line 88
    .line 89
    move v3, v0

    .line 90
    goto :goto_1

    .line 91
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_1
    add-int/2addr v2, v3

    .line 96
    mul-int/2addr v2, v1

    .line 97
    iget-object v3, p0, Lc70/d;->n:Lvf0/l;

    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    add-int/2addr v3, v2

    .line 104
    mul-int/2addr v3, v1

    .line 105
    iget-object p0, p0, Lc70/d;->o:Lvf0/l;

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
    add-int/2addr v3, v0

    .line 115
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(viewMode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc70/d;->a:Llf0/i;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", title="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lc70/d;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", range="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", adBlueWarning="

    .line 29
    .line 30
    const-string v2, ", isAdBlueCritical="

    .line 31
    .line 32
    iget-object v3, p0, Lc70/d;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-object v4, p0, Lc70/d;->d:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isLoading="

    .line 40
    .line 41
    const-string v2, ", isNotifySilentLoading="

    .line 42
    .line 43
    iget-boolean v3, p0, Lc70/d;->e:Z

    .line 44
    .line 45
    iget-boolean v4, p0, Lc70/d;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, ", isSilentLoading="

    .line 51
    .line 52
    const-string v2, ", hasSecondaryEngine="

    .line 53
    .line 54
    iget-boolean v3, p0, Lc70/d;->g:Z

    .line 55
    .line 56
    iget-boolean v4, p0, Lc70/d;->h:Z

    .line 57
    .line 58
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-boolean v1, p0, Lc70/d;->i:Z

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", primaryEngineIcon="

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Lc70/d;->j:Lvf0/k;

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v1, ", secondaryEngineIcon="

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    iget-object v1, p0, Lc70/d;->k:Lvf0/k;

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v1, ", primaryRangeProgress="

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    iget v1, p0, Lc70/d;->l:F

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v1, ", secondaryRangeProgress="

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    iget-object v1, p0, Lc70/d;->m:Ljava/lang/Float;

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string v1, ", primaryRangeStatus="

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    iget-object v1, p0, Lc70/d;->n:Lvf0/l;

    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v1, ", secondaryRangeStatus="

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    iget-object p0, p0, Lc70/d;->o:Lvf0/l;

    .line 122
    .line 123
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string p0, ")"

    .line 127
    .line 128
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0
.end method
