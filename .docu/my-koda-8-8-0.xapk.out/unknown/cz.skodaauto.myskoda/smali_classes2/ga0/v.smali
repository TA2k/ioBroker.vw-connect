.class public final Lga0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ler0/g;

.field public final b:Landroid/net/Uri;

.field public final c:Lga0/t;

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Lga0/u;

.field public final j:Lga0/u;

.field public final k:Lga0/u;

.field public final l:Lga0/u;

.field public final m:Lga0/u;

.field public final n:Lga0/u;

.field public final o:Llf0/i;

.field public final p:Ljava/time/OffsetDateTime;

.field public final q:Z

.field public final r:Z


# direct methods
.method public constructor <init>(Ler0/g;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Llf0/i;Ljava/time/OffsetDateTime;)V
    .locals 6

    move-object/from16 v0, p10

    move-object/from16 v1, p11

    move-object/from16 v2, p13

    move-object/from16 v3, p14

    move-object/from16 v4, p15

    const-string v5, "subscriptionLicenseState"

    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "status"

    invoke-static {p3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "doorsState"

    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "lightsState"

    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "bootState"

    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "bonnetState"

    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "viewMode"

    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lga0/v;->a:Ler0/g;

    .line 3
    iput-object p2, p0, Lga0/v;->b:Landroid/net/Uri;

    .line 4
    iput-object p3, p0, Lga0/v;->c:Lga0/t;

    .line 5
    iput-boolean p4, p0, Lga0/v;->d:Z

    .line 6
    iput-boolean p5, p0, Lga0/v;->e:Z

    .line 7
    iput-boolean p6, p0, Lga0/v;->f:Z

    .line 8
    iput-boolean p7, p0, Lga0/v;->g:Z

    .line 9
    iput-boolean p8, p0, Lga0/v;->h:Z

    .line 10
    iput-object p9, p0, Lga0/v;->i:Lga0/u;

    .line 11
    iput-object v0, p0, Lga0/v;->j:Lga0/u;

    .line 12
    iput-object v1, p0, Lga0/v;->k:Lga0/u;

    move-object/from16 p1, p12

    .line 13
    iput-object p1, p0, Lga0/v;->l:Lga0/u;

    .line 14
    iput-object v2, p0, Lga0/v;->m:Lga0/u;

    .line 15
    iput-object v3, p0, Lga0/v;->n:Lga0/u;

    .line 16
    iput-object v4, p0, Lga0/v;->o:Llf0/i;

    move-object/from16 p1, p16

    .line 17
    iput-object p1, p0, Lga0/v;->p:Ljava/time/OffsetDateTime;

    .line 18
    sget-object p1, Llf0/i;->h:Llf0/i;

    if-ne v4, p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, p0, Lga0/v;->q:Z

    .line 19
    invoke-static {v4}, Llp/tf;->d(Llf0/i;)Z

    move-result p1

    iput-boolean p1, p0, Lga0/v;->r:Z

    return-void
.end method

.method public synthetic constructor <init>(Ler0/g;ZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Llf0/i;I)V
    .locals 17

    move/from16 v0, p10

    .line 20
    sget-object v3, Lga0/t;->h:Lga0/t;

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 21
    sget-object v1, Ler0/g;->d:Ler0/g;

    goto :goto_0

    :cond_0
    move-object/from16 v1, p1

    :goto_0
    and-int/lit8 v2, v0, 0x8

    const/4 v4, 0x0

    if-eqz v2, :cond_1

    move v2, v4

    goto :goto_1

    :cond_1
    move/from16 v2, p2

    :goto_1
    and-int/lit8 v5, v0, 0x40

    const/4 v6, 0x1

    if-eqz v5, :cond_2

    move v7, v6

    goto :goto_2

    :cond_2
    move v7, v4

    :goto_2
    and-int/lit16 v5, v0, 0x80

    if-eqz v5, :cond_3

    move v8, v4

    goto :goto_3

    :cond_3
    move v8, v6

    :goto_3
    and-int/lit16 v4, v0, 0x100

    const/4 v5, 0x0

    if-eqz v4, :cond_4

    move-object v9, v5

    goto :goto_4

    :cond_4
    move-object/from16 v9, p3

    :goto_4
    and-int/lit16 v4, v0, 0x200

    if-eqz v4, :cond_5

    .line 22
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    move-result-object v4

    move-object v10, v4

    goto :goto_5

    :cond_5
    move-object/from16 v10, p4

    :goto_5
    and-int/lit16 v4, v0, 0x400

    if-eqz v4, :cond_6

    .line 23
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    move-result-object v4

    move-object v11, v4

    goto :goto_6

    :cond_6
    move-object/from16 v11, p5

    :goto_6
    and-int/lit16 v4, v0, 0x800

    if-eqz v4, :cond_7

    move-object v12, v5

    goto :goto_7

    :cond_7
    move-object/from16 v12, p6

    :goto_7
    and-int/lit16 v4, v0, 0x1000

    if-eqz v4, :cond_8

    .line 24
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    move-result-object v4

    move-object v13, v4

    goto :goto_8

    :cond_8
    move-object/from16 v13, p7

    :goto_8
    and-int/lit16 v4, v0, 0x2000

    if-eqz v4, :cond_9

    .line 25
    invoke-static {}, Lkp/t8;->c()Lga0/u;

    move-result-object v4

    move-object v14, v4

    goto :goto_9

    :cond_9
    move-object/from16 v14, p8

    :goto_9
    and-int/lit16 v0, v0, 0x4000

    if-eqz v0, :cond_a

    .line 26
    sget-object v0, Llf0/i;->j:Llf0/i;

    move-object v15, v0

    :goto_a
    move v4, v2

    goto :goto_b

    :cond_a
    move-object/from16 v15, p9

    goto :goto_a

    :goto_b
    const/4 v2, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/16 v16, 0x0

    move-object/from16 v0, p0

    .line 27
    invoke-direct/range {v0 .. v16}, Lga0/v;-><init>(Ler0/g;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Llf0/i;Ljava/time/OffsetDateTime;)V

    return-void
.end method

.method public static a(Lga0/v;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Ljava/time/OffsetDateTime;I)Lga0/v;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p15

    .line 4
    .line 5
    iget-object v2, v0, Lga0/v;->a:Ler0/g;

    .line 6
    .line 7
    and-int/lit8 v3, v1, 0x2

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    iget-object v3, v0, Lga0/v;->b:Landroid/net/Uri;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object/from16 v3, p1

    .line 15
    .line 16
    :goto_0
    and-int/lit8 v4, v1, 0x4

    .line 17
    .line 18
    if-eqz v4, :cond_1

    .line 19
    .line 20
    iget-object v4, v0, Lga0/v;->c:Lga0/t;

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move-object/from16 v4, p2

    .line 24
    .line 25
    :goto_1
    and-int/lit8 v5, v1, 0x8

    .line 26
    .line 27
    if-eqz v5, :cond_2

    .line 28
    .line 29
    iget-boolean v5, v0, Lga0/v;->d:Z

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    move/from16 v5, p3

    .line 33
    .line 34
    :goto_2
    and-int/lit8 v6, v1, 0x10

    .line 35
    .line 36
    if-eqz v6, :cond_3

    .line 37
    .line 38
    iget-boolean v6, v0, Lga0/v;->e:Z

    .line 39
    .line 40
    goto :goto_3

    .line 41
    :cond_3
    move/from16 v6, p4

    .line 42
    .line 43
    :goto_3
    and-int/lit8 v7, v1, 0x20

    .line 44
    .line 45
    if-eqz v7, :cond_4

    .line 46
    .line 47
    iget-boolean v7, v0, Lga0/v;->f:Z

    .line 48
    .line 49
    goto :goto_4

    .line 50
    :cond_4
    move/from16 v7, p5

    .line 51
    .line 52
    :goto_4
    and-int/lit8 v8, v1, 0x40

    .line 53
    .line 54
    if-eqz v8, :cond_5

    .line 55
    .line 56
    iget-boolean v8, v0, Lga0/v;->g:Z

    .line 57
    .line 58
    goto :goto_5

    .line 59
    :cond_5
    move/from16 v8, p6

    .line 60
    .line 61
    :goto_5
    and-int/lit16 v9, v1, 0x80

    .line 62
    .line 63
    if-eqz v9, :cond_6

    .line 64
    .line 65
    iget-boolean v9, v0, Lga0/v;->h:Z

    .line 66
    .line 67
    goto :goto_6

    .line 68
    :cond_6
    move/from16 v9, p7

    .line 69
    .line 70
    :goto_6
    and-int/lit16 v10, v1, 0x100

    .line 71
    .line 72
    if-eqz v10, :cond_7

    .line 73
    .line 74
    iget-object v10, v0, Lga0/v;->i:Lga0/u;

    .line 75
    .line 76
    goto :goto_7

    .line 77
    :cond_7
    move-object/from16 v10, p8

    .line 78
    .line 79
    :goto_7
    and-int/lit16 v11, v1, 0x200

    .line 80
    .line 81
    if-eqz v11, :cond_8

    .line 82
    .line 83
    iget-object v11, v0, Lga0/v;->j:Lga0/u;

    .line 84
    .line 85
    goto :goto_8

    .line 86
    :cond_8
    move-object/from16 v11, p9

    .line 87
    .line 88
    :goto_8
    and-int/lit16 v12, v1, 0x400

    .line 89
    .line 90
    if-eqz v12, :cond_9

    .line 91
    .line 92
    iget-object v12, v0, Lga0/v;->k:Lga0/u;

    .line 93
    .line 94
    goto :goto_9

    .line 95
    :cond_9
    move-object/from16 v12, p10

    .line 96
    .line 97
    :goto_9
    and-int/lit16 v13, v1, 0x800

    .line 98
    .line 99
    if-eqz v13, :cond_a

    .line 100
    .line 101
    iget-object v13, v0, Lga0/v;->l:Lga0/u;

    .line 102
    .line 103
    goto :goto_a

    .line 104
    :cond_a
    move-object/from16 v13, p11

    .line 105
    .line 106
    :goto_a
    and-int/lit16 v14, v1, 0x1000

    .line 107
    .line 108
    if-eqz v14, :cond_b

    .line 109
    .line 110
    iget-object v14, v0, Lga0/v;->m:Lga0/u;

    .line 111
    .line 112
    goto :goto_b

    .line 113
    :cond_b
    move-object/from16 v14, p12

    .line 114
    .line 115
    :goto_b
    and-int/lit16 v15, v1, 0x2000

    .line 116
    .line 117
    if-eqz v15, :cond_c

    .line 118
    .line 119
    iget-object v15, v0, Lga0/v;->n:Lga0/u;

    .line 120
    .line 121
    goto :goto_c

    .line 122
    :cond_c
    move-object/from16 v15, p13

    .line 123
    .line 124
    :goto_c
    iget-object v1, v0, Lga0/v;->o:Llf0/i;

    .line 125
    .line 126
    const v16, 0x8000

    .line 127
    .line 128
    .line 129
    and-int v16, p15, v16

    .line 130
    .line 131
    move-object/from16 p1, v3

    .line 132
    .line 133
    if-eqz v16, :cond_d

    .line 134
    .line 135
    iget-object v3, v0, Lga0/v;->p:Ljava/time/OffsetDateTime;

    .line 136
    .line 137
    move-object/from16 v16, v3

    .line 138
    .line 139
    goto :goto_d

    .line 140
    :cond_d
    move-object/from16 v16, p14

    .line 141
    .line 142
    :goto_d
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    const-string v0, "subscriptionLicenseState"

    .line 146
    .line 147
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    const-string v0, "status"

    .line 151
    .line 152
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-string v0, "doorsState"

    .line 156
    .line 157
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    const-string v0, "lightsState"

    .line 161
    .line 162
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    const-string v0, "bootState"

    .line 166
    .line 167
    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    const-string v0, "bonnetState"

    .line 171
    .line 172
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    const-string v0, "viewMode"

    .line 176
    .line 177
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    new-instance v0, Lga0/v;

    .line 181
    .line 182
    move-object v3, v4

    .line 183
    move v4, v5

    .line 184
    move v5, v6

    .line 185
    move v6, v7

    .line 186
    move v7, v8

    .line 187
    move v8, v9

    .line 188
    move-object v9, v10

    .line 189
    move-object v10, v11

    .line 190
    move-object v11, v12

    .line 191
    move-object v12, v13

    .line 192
    move-object v13, v14

    .line 193
    move-object v14, v15

    .line 194
    move-object v15, v1

    .line 195
    move-object v1, v2

    .line 196
    move-object/from16 v2, p1

    .line 197
    .line 198
    invoke-direct/range {v0 .. v16}, Lga0/v;-><init>(Ler0/g;Landroid/net/Uri;Lga0/t;ZZZZZLga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Lga0/u;Llf0/i;Ljava/time/OffsetDateTime;)V

    .line 199
    .line 200
    .line 201
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
    instance-of v1, p1, Lga0/v;

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
    check-cast p1, Lga0/v;

    .line 12
    .line 13
    iget-object v1, p0, Lga0/v;->a:Ler0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lga0/v;->a:Ler0/g;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lga0/v;->b:Landroid/net/Uri;

    .line 21
    .line 22
    iget-object v3, p1, Lga0/v;->b:Landroid/net/Uri;

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
    iget-object v1, p0, Lga0/v;->c:Lga0/t;

    .line 32
    .line 33
    iget-object v3, p1, Lga0/v;->c:Lga0/t;

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Lga0/v;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lga0/v;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Lga0/v;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Lga0/v;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean v1, p0, Lga0/v;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Lga0/v;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-boolean v1, p0, Lga0/v;->g:Z

    .line 60
    .line 61
    iget-boolean v3, p1, Lga0/v;->g:Z

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-boolean v1, p0, Lga0/v;->h:Z

    .line 67
    .line 68
    iget-boolean v3, p1, Lga0/v;->h:Z

    .line 69
    .line 70
    if-eq v1, v3, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-object v1, p0, Lga0/v;->i:Lga0/u;

    .line 74
    .line 75
    iget-object v3, p1, Lga0/v;->i:Lga0/u;

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
    iget-object v1, p0, Lga0/v;->j:Lga0/u;

    .line 85
    .line 86
    iget-object v3, p1, Lga0/v;->j:Lga0/u;

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
    iget-object v1, p0, Lga0/v;->k:Lga0/u;

    .line 96
    .line 97
    iget-object v3, p1, Lga0/v;->k:Lga0/u;

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
    iget-object v1, p0, Lga0/v;->l:Lga0/u;

    .line 107
    .line 108
    iget-object v3, p1, Lga0/v;->l:Lga0/u;

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
    iget-object v1, p0, Lga0/v;->m:Lga0/u;

    .line 118
    .line 119
    iget-object v3, p1, Lga0/v;->m:Lga0/u;

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
    iget-object v1, p0, Lga0/v;->n:Lga0/u;

    .line 129
    .line 130
    iget-object v3, p1, Lga0/v;->n:Lga0/u;

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
    iget-object v1, p0, Lga0/v;->o:Llf0/i;

    .line 140
    .line 141
    iget-object v3, p1, Lga0/v;->o:Llf0/i;

    .line 142
    .line 143
    if-eq v1, v3, :cond_10

    .line 144
    .line 145
    return v2

    .line 146
    :cond_10
    iget-object p0, p0, Lga0/v;->p:Ljava/time/OffsetDateTime;

    .line 147
    .line 148
    iget-object p1, p1, Lga0/v;->p:Ljava/time/OffsetDateTime;

    .line 149
    .line 150
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    if-nez p0, :cond_11

    .line 155
    .line 156
    return v2

    .line 157
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lga0/v;->a:Ler0/g;

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lga0/v;->b:Landroid/net/Uri;

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    move v3, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v3}, Landroid/net/Uri;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    :goto_0
    add-int/2addr v0, v3

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-object v3, p0, Lga0/v;->c:Lga0/t;

    .line 24
    .line 25
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    add-int/2addr v3, v0

    .line 30
    mul-int/2addr v3, v1

    .line 31
    iget-boolean v0, p0, Lga0/v;->d:Z

    .line 32
    .line 33
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget-boolean v3, p0, Lga0/v;->e:Z

    .line 38
    .line 39
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget-boolean v3, p0, Lga0/v;->f:Z

    .line 44
    .line 45
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    iget-boolean v3, p0, Lga0/v;->g:Z

    .line 50
    .line 51
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    iget-boolean v3, p0, Lga0/v;->h:Z

    .line 56
    .line 57
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    iget-object v3, p0, Lga0/v;->i:Lga0/u;

    .line 62
    .line 63
    if-nez v3, :cond_1

    .line 64
    .line 65
    move v3, v2

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-virtual {v3}, Lga0/u;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_1
    add-int/2addr v0, v3

    .line 72
    mul-int/2addr v0, v1

    .line 73
    iget-object v3, p0, Lga0/v;->j:Lga0/u;

    .line 74
    .line 75
    invoke-virtual {v3}, Lga0/u;->hashCode()I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    add-int/2addr v3, v0

    .line 80
    mul-int/2addr v3, v1

    .line 81
    iget-object v0, p0, Lga0/v;->k:Lga0/u;

    .line 82
    .line 83
    invoke-virtual {v0}, Lga0/u;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    add-int/2addr v0, v3

    .line 88
    mul-int/2addr v0, v1

    .line 89
    iget-object v3, p0, Lga0/v;->l:Lga0/u;

    .line 90
    .line 91
    if-nez v3, :cond_2

    .line 92
    .line 93
    move v3, v2

    .line 94
    goto :goto_2

    .line 95
    :cond_2
    invoke-virtual {v3}, Lga0/u;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    :goto_2
    add-int/2addr v0, v3

    .line 100
    mul-int/2addr v0, v1

    .line 101
    iget-object v3, p0, Lga0/v;->m:Lga0/u;

    .line 102
    .line 103
    invoke-virtual {v3}, Lga0/u;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    add-int/2addr v3, v0

    .line 108
    mul-int/2addr v3, v1

    .line 109
    iget-object v0, p0, Lga0/v;->n:Lga0/u;

    .line 110
    .line 111
    invoke-virtual {v0}, Lga0/u;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    add-int/2addr v0, v3

    .line 116
    mul-int/2addr v0, v1

    .line 117
    iget-object v3, p0, Lga0/v;->o:Llf0/i;

    .line 118
    .line 119
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    add-int/2addr v3, v0

    .line 124
    mul-int/2addr v3, v1

    .line 125
    iget-object p0, p0, Lga0/v;->p:Ljava/time/OffsetDateTime;

    .line 126
    .line 127
    if-nez p0, :cond_3

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_3
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    :goto_3
    add-int/2addr v3, v2

    .line 135
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(subscriptionLicenseState="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lga0/v;->a:Ler0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", render="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lga0/v;->b:Landroid/net/Uri;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", status="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lga0/v;->c:Lga0/t;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", lockUnlockButtonVisible="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Lga0/v;->d:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", lockUnlockButtonEnabled="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", isRefreshing="

    .line 49
    .line 50
    const-string v2, ", isLoading="

    .line 51
    .line 52
    iget-boolean v3, p0, Lga0/v;->e:Z

    .line 53
    .line 54
    iget-boolean v4, p0, Lga0/v;->f:Z

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v1, ", isEnabled="

    .line 60
    .line 61
    const-string v2, ", windowsState="

    .line 62
    .line 63
    iget-boolean v3, p0, Lga0/v;->g:Z

    .line 64
    .line 65
    iget-boolean v4, p0, Lga0/v;->h:Z

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object v1, p0, Lga0/v;->i:Lga0/u;

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", doorsState="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    iget-object v1, p0, Lga0/v;->j:Lga0/u;

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", lightsState="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    iget-object v1, p0, Lga0/v;->k:Lga0/u;

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v1, ", sunroofState="

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    iget-object v1, p0, Lga0/v;->l:Lga0/u;

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", bootState="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    iget-object v1, p0, Lga0/v;->m:Lga0/u;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v1, ", bonnetState="

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    iget-object v1, p0, Lga0/v;->n:Lga0/u;

    .line 121
    .line 122
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    const-string v1, ", viewMode="

    .line 126
    .line 127
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    iget-object v1, p0, Lga0/v;->o:Llf0/i;

    .line 131
    .line 132
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string v1, ", lastUpdateTimestamp="

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    iget-object p0, p0, Lga0/v;->p:Ljava/time/OffsetDateTime;

    .line 141
    .line 142
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const-string p0, ")"

    .line 146
    .line 147
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    return-object p0
.end method
