.class public final Lc00/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lc00/u0;

.field public final f:Lc00/w0;

.field public final g:Lc00/x0;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Lc00/v0;

.field public final l:Ler0/g;

.field public final m:Llf0/i;

.field public final n:Z

.field public final o:Z

.field public final p:Lqr0/q;

.field public final q:Lqr0/q;

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:I

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z


# direct methods
.method public synthetic constructor <init>(Lc00/v0;Ler0/g;Llf0/i;I)V
    .locals 20

    move/from16 v0, p4

    .line 1
    sget-object v5, Lc00/u0;->e:Lc00/u0;

    .line 2
    sget-object v1, Lc00/x0;->f:Lc00/x0;

    and-int/lit8 v2, v0, 0x2

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v2, :cond_0

    move v2, v4

    goto :goto_0

    :cond_0
    move v2, v3

    :goto_0
    and-int/lit8 v6, v0, 0x4

    if-eqz v6, :cond_1

    move v3, v4

    :cond_1
    and-int/lit8 v4, v0, 0x40

    if-eqz v4, :cond_2

    .line 3
    sget-object v1, Lc00/x0;->d:Lc00/x0;

    :cond_2
    move-object v7, v1

    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_3

    .line 4
    new-instance v8, Lc00/v0;

    const/4 v13, 0x0

    const/16 v14, 0x3f

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    invoke-direct/range {v8 .. v14}, Lc00/v0;-><init>(Ljava/lang/String;Ljava/lang/String;FZZI)V

    move-object v11, v8

    goto :goto_1

    :cond_3
    move-object/from16 v11, p1

    :goto_1
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_4

    .line 5
    sget-object v1, Ler0/g;->d:Ler0/g;

    move-object v12, v1

    goto :goto_2

    :cond_4
    move-object/from16 v12, p2

    :goto_2
    and-int/lit16 v0, v0, 0x1000

    if-eqz v0, :cond_5

    .line 6
    sget-object v0, Llf0/i;->j:Llf0/i;

    move-object v13, v0

    goto :goto_3

    :cond_5
    move-object/from16 v13, p3

    :goto_3
    const/16 v18, 0x0

    const/16 v19, 0x0

    const/4 v1, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v14, 0x1

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    move-object/from16 v0, p0

    .line 7
    invoke-direct/range {v0 .. v19}, Lc00/y0;-><init>(ZZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Ler0/g;Llf0/i;ZZLqr0/q;Lqr0/q;ZZ)V

    return-void
.end method

.method public constructor <init>(ZZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Ler0/g;Llf0/i;ZZLqr0/q;Lqr0/q;ZZ)V
    .locals 3

    move-object v0, p12

    move-object/from16 v1, p13

    const-string v2, "climateState"

    invoke-static {p5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "windowHeatingState"

    invoke-static {p7, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "gauge"

    invoke-static {p11, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "subscriptionLicenseState"

    invoke-static {p12, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "viewMode"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-boolean p1, p0, Lc00/y0;->a:Z

    .line 10
    iput-boolean p2, p0, Lc00/y0;->b:Z

    .line 11
    iput-boolean p3, p0, Lc00/y0;->c:Z

    .line 12
    iput-boolean p4, p0, Lc00/y0;->d:Z

    .line 13
    iput-object p5, p0, Lc00/y0;->e:Lc00/u0;

    .line 14
    iput-object p6, p0, Lc00/y0;->f:Lc00/w0;

    .line 15
    iput-object p7, p0, Lc00/y0;->g:Lc00/x0;

    .line 16
    iput-object p8, p0, Lc00/y0;->h:Ljava/lang/String;

    .line 17
    iput-object p9, p0, Lc00/y0;->i:Ljava/lang/String;

    .line 18
    iput-object p10, p0, Lc00/y0;->j:Ljava/lang/String;

    .line 19
    iput-object p11, p0, Lc00/y0;->k:Lc00/v0;

    .line 20
    iput-object v0, p0, Lc00/y0;->l:Ler0/g;

    .line 21
    iput-object v1, p0, Lc00/y0;->m:Llf0/i;

    move/from16 p1, p14

    .line 22
    iput-boolean p1, p0, Lc00/y0;->n:Z

    move/from16 p1, p15

    .line 23
    iput-boolean p1, p0, Lc00/y0;->o:Z

    move-object/from16 p1, p16

    .line 24
    iput-object p1, p0, Lc00/y0;->p:Lqr0/q;

    move-object/from16 p2, p17

    .line 25
    iput-object p2, p0, Lc00/y0;->q:Lqr0/q;

    move/from16 p3, p18

    .line 26
    iput-boolean p3, p0, Lc00/y0;->r:Z

    move/from16 p3, p19

    .line 27
    iput-boolean p3, p0, Lc00/y0;->s:Z

    .line 28
    invoke-static/range {p16 .. p17}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    xor-int/lit8 p2, p1, 0x1

    iput-boolean p2, p0, Lc00/y0;->t:Z

    if-nez p1, :cond_0

    const p1, 0x7f120076

    goto :goto_0

    :cond_0
    const p1, 0x7f120075

    .line 29
    :goto_0
    iput p1, p0, Lc00/y0;->u:I

    .line 30
    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/4 p2, 0x0

    const/4 p3, 0x1

    packed-switch p1, :pswitch_data_0

    new-instance p0, La8/r0;

    .line 31
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 32
    throw p0

    :pswitch_0
    move p1, p3

    goto :goto_1

    :pswitch_1
    move p1, p2

    :goto_1
    iput-boolean p1, p0, Lc00/y0;->v:Z

    .line 33
    sget-object p1, Llf0/i;->h:Llf0/i;

    if-ne v1, p1, :cond_1

    move p1, p3

    goto :goto_2

    :cond_1
    move p1, p2

    :goto_2
    iput-boolean p1, p0, Lc00/y0;->w:Z

    .line 34
    invoke-static {v1}, Llp/tf;->d(Llf0/i;)Z

    move-result p4

    iput-boolean p4, p0, Lc00/y0;->x:Z

    if-nez p1, :cond_2

    if-eqz p4, :cond_3

    :cond_2
    move p2, p3

    .line 35
    :cond_3
    iput-boolean p2, p0, Lc00/y0;->y:Z

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public static a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p17

    .line 4
    .line 5
    sget-object v2, Ler0/g;->d:Ler0/g;

    .line 6
    .line 7
    and-int/lit8 v3, v1, 0x1

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    iget-boolean v3, v0, Lc00/y0;->a:Z

    .line 12
    .line 13
    move v5, v3

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move/from16 v5, p1

    .line 16
    .line 17
    :goto_0
    and-int/lit8 v3, v1, 0x2

    .line 18
    .line 19
    if-eqz v3, :cond_1

    .line 20
    .line 21
    iget-boolean v3, v0, Lc00/y0;->b:Z

    .line 22
    .line 23
    :goto_1
    move v6, v3

    .line 24
    goto :goto_2

    .line 25
    :cond_1
    const/4 v3, 0x0

    .line 26
    goto :goto_1

    .line 27
    :goto_2
    and-int/lit8 v3, v1, 0x4

    .line 28
    .line 29
    if-eqz v3, :cond_2

    .line 30
    .line 31
    iget-boolean v3, v0, Lc00/y0;->c:Z

    .line 32
    .line 33
    move v7, v3

    .line 34
    goto :goto_3

    .line 35
    :cond_2
    move/from16 v7, p2

    .line 36
    .line 37
    :goto_3
    and-int/lit8 v3, v1, 0x8

    .line 38
    .line 39
    if-eqz v3, :cond_3

    .line 40
    .line 41
    iget-boolean v3, v0, Lc00/y0;->d:Z

    .line 42
    .line 43
    move v8, v3

    .line 44
    goto :goto_4

    .line 45
    :cond_3
    move/from16 v8, p3

    .line 46
    .line 47
    :goto_4
    and-int/lit8 v3, v1, 0x10

    .line 48
    .line 49
    if-eqz v3, :cond_4

    .line 50
    .line 51
    iget-object v3, v0, Lc00/y0;->e:Lc00/u0;

    .line 52
    .line 53
    move-object v9, v3

    .line 54
    goto :goto_5

    .line 55
    :cond_4
    move-object/from16 v9, p4

    .line 56
    .line 57
    :goto_5
    and-int/lit8 v3, v1, 0x20

    .line 58
    .line 59
    if-eqz v3, :cond_5

    .line 60
    .line 61
    iget-object v3, v0, Lc00/y0;->f:Lc00/w0;

    .line 62
    .line 63
    move-object v10, v3

    .line 64
    goto :goto_6

    .line 65
    :cond_5
    move-object/from16 v10, p5

    .line 66
    .line 67
    :goto_6
    and-int/lit8 v3, v1, 0x40

    .line 68
    .line 69
    if-eqz v3, :cond_6

    .line 70
    .line 71
    iget-object v3, v0, Lc00/y0;->g:Lc00/x0;

    .line 72
    .line 73
    move-object v11, v3

    .line 74
    goto :goto_7

    .line 75
    :cond_6
    move-object/from16 v11, p6

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v3, v1, 0x80

    .line 78
    .line 79
    if-eqz v3, :cond_7

    .line 80
    .line 81
    iget-object v3, v0, Lc00/y0;->h:Ljava/lang/String;

    .line 82
    .line 83
    move-object v12, v3

    .line 84
    goto :goto_8

    .line 85
    :cond_7
    move-object/from16 v12, p7

    .line 86
    .line 87
    :goto_8
    and-int/lit16 v3, v1, 0x100

    .line 88
    .line 89
    if-eqz v3, :cond_8

    .line 90
    .line 91
    iget-object v3, v0, Lc00/y0;->i:Ljava/lang/String;

    .line 92
    .line 93
    move-object v13, v3

    .line 94
    goto :goto_9

    .line 95
    :cond_8
    move-object/from16 v13, p8

    .line 96
    .line 97
    :goto_9
    and-int/lit16 v3, v1, 0x200

    .line 98
    .line 99
    if-eqz v3, :cond_9

    .line 100
    .line 101
    iget-object v3, v0, Lc00/y0;->j:Ljava/lang/String;

    .line 102
    .line 103
    move-object v14, v3

    .line 104
    goto :goto_a

    .line 105
    :cond_9
    move-object/from16 v14, p9

    .line 106
    .line 107
    :goto_a
    and-int/lit16 v3, v1, 0x400

    .line 108
    .line 109
    if-eqz v3, :cond_a

    .line 110
    .line 111
    iget-object v3, v0, Lc00/y0;->k:Lc00/v0;

    .line 112
    .line 113
    move-object v15, v3

    .line 114
    goto :goto_b

    .line 115
    :cond_a
    move-object/from16 v15, p10

    .line 116
    .line 117
    :goto_b
    and-int/lit16 v3, v1, 0x800

    .line 118
    .line 119
    if-eqz v3, :cond_b

    .line 120
    .line 121
    iget-object v2, v0, Lc00/y0;->l:Ler0/g;

    .line 122
    .line 123
    :cond_b
    and-int/lit16 v3, v1, 0x1000

    .line 124
    .line 125
    if-eqz v3, :cond_c

    .line 126
    .line 127
    iget-object v3, v0, Lc00/y0;->m:Llf0/i;

    .line 128
    .line 129
    goto :goto_c

    .line 130
    :cond_c
    move-object/from16 v3, p11

    .line 131
    .line 132
    :goto_c
    and-int/lit16 v4, v1, 0x2000

    .line 133
    .line 134
    if-eqz v4, :cond_d

    .line 135
    .line 136
    iget-boolean v4, v0, Lc00/y0;->n:Z

    .line 137
    .line 138
    move/from16 v18, v4

    .line 139
    .line 140
    goto :goto_d

    .line 141
    :cond_d
    move/from16 v18, p12

    .line 142
    .line 143
    :goto_d
    and-int/lit16 v4, v1, 0x4000

    .line 144
    .line 145
    if-eqz v4, :cond_e

    .line 146
    .line 147
    iget-boolean v4, v0, Lc00/y0;->o:Z

    .line 148
    .line 149
    move/from16 v19, v4

    .line 150
    .line 151
    goto :goto_e

    .line 152
    :cond_e
    move/from16 v19, p13

    .line 153
    .line 154
    :goto_e
    const v4, 0x8000

    .line 155
    .line 156
    .line 157
    and-int/2addr v4, v1

    .line 158
    if-eqz v4, :cond_f

    .line 159
    .line 160
    iget-object v4, v0, Lc00/y0;->p:Lqr0/q;

    .line 161
    .line 162
    move-object/from16 v20, v4

    .line 163
    .line 164
    goto :goto_f

    .line 165
    :cond_f
    move-object/from16 v20, p14

    .line 166
    .line 167
    :goto_f
    const/high16 v4, 0x10000

    .line 168
    .line 169
    and-int/2addr v4, v1

    .line 170
    if-eqz v4, :cond_10

    .line 171
    .line 172
    iget-object v4, v0, Lc00/y0;->q:Lqr0/q;

    .line 173
    .line 174
    move-object/from16 v21, v4

    .line 175
    .line 176
    goto :goto_10

    .line 177
    :cond_10
    move-object/from16 v21, p15

    .line 178
    .line 179
    :goto_10
    const/high16 v4, 0x20000

    .line 180
    .line 181
    and-int/2addr v4, v1

    .line 182
    if-eqz v4, :cond_11

    .line 183
    .line 184
    iget-boolean v4, v0, Lc00/y0;->r:Z

    .line 185
    .line 186
    :goto_11
    move/from16 v22, v4

    .line 187
    .line 188
    goto :goto_12

    .line 189
    :cond_11
    const/4 v4, 0x1

    .line 190
    goto :goto_11

    .line 191
    :goto_12
    const/high16 v4, 0x40000

    .line 192
    .line 193
    and-int/2addr v1, v4

    .line 194
    if-eqz v1, :cond_12

    .line 195
    .line 196
    iget-boolean v1, v0, Lc00/y0;->s:Z

    .line 197
    .line 198
    move/from16 v23, v1

    .line 199
    .line 200
    goto :goto_13

    .line 201
    :cond_12
    move/from16 v23, p16

    .line 202
    .line 203
    :goto_13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 204
    .line 205
    .line 206
    const-string v0, "climateState"

    .line 207
    .line 208
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    const-string v0, "windowHeatingState"

    .line 212
    .line 213
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    const-string v0, "gauge"

    .line 217
    .line 218
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    const-string v0, "subscriptionLicenseState"

    .line 222
    .line 223
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string v0, "viewMode"

    .line 227
    .line 228
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    new-instance v4, Lc00/y0;

    .line 232
    .line 233
    move-object/from16 v16, v2

    .line 234
    .line 235
    move-object/from16 v17, v3

    .line 236
    .line 237
    invoke-direct/range {v4 .. v23}, Lc00/y0;-><init>(ZZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Ler0/g;Llf0/i;ZZLqr0/q;Lqr0/q;ZZ)V

    .line 238
    .line 239
    .line 240
    return-object v4
.end method


# virtual methods
.method public final b()Z
    .locals 5

    .line 1
    sget-object v0, Lc00/x0;->f:Lc00/x0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    iget-object v3, p0, Lc00/y0;->g:Lc00/x0;

    .line 6
    .line 7
    if-eq v3, v0, :cond_1

    .line 8
    .line 9
    sget-object v0, Lc00/x0;->e:Lc00/x0;

    .line 10
    .line 11
    if-ne v3, v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v0, v2

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    :goto_0
    move v0, v1

    .line 17
    :goto_1
    iget-boolean v3, p0, Lc00/y0;->v:Z

    .line 18
    .line 19
    iget-object v4, p0, Lc00/y0;->f:Lc00/w0;

    .line 20
    .line 21
    if-nez v3, :cond_2

    .line 22
    .line 23
    if-eqz v4, :cond_4

    .line 24
    .line 25
    :cond_2
    sget-object v3, Lc00/w0;->e:Lc00/w0;

    .line 26
    .line 27
    if-eq v4, v3, :cond_4

    .line 28
    .line 29
    sget-object v3, Lc00/w0;->f:Lc00/w0;

    .line 30
    .line 31
    if-ne v4, v3, :cond_3

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_3
    move v3, v2

    .line 35
    goto :goto_3

    .line 36
    :cond_4
    :goto_2
    move v3, v1

    .line 37
    :goto_3
    if-eqz v0, :cond_5

    .line 38
    .line 39
    if-eqz v3, :cond_5

    .line 40
    .line 41
    iget-boolean p0, p0, Lc00/y0;->d:Z

    .line 42
    .line 43
    if-nez p0, :cond_5

    .line 44
    .line 45
    return v1

    .line 46
    :cond_5
    return v2
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
    instance-of v1, p1, Lc00/y0;

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
    check-cast p1, Lc00/y0;

    .line 12
    .line 13
    iget-boolean v1, p0, Lc00/y0;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lc00/y0;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lc00/y0;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lc00/y0;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lc00/y0;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lc00/y0;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lc00/y0;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lc00/y0;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lc00/y0;->e:Lc00/u0;

    .line 42
    .line 43
    iget-object v3, p1, Lc00/y0;->e:Lc00/u0;

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-object v1, p0, Lc00/y0;->f:Lc00/w0;

    .line 49
    .line 50
    iget-object v3, p1, Lc00/y0;->f:Lc00/w0;

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-object v1, p0, Lc00/y0;->g:Lc00/x0;

    .line 56
    .line 57
    iget-object v3, p1, Lc00/y0;->g:Lc00/x0;

    .line 58
    .line 59
    if-eq v1, v3, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    iget-object v1, p0, Lc00/y0;->h:Ljava/lang/String;

    .line 63
    .line 64
    iget-object v3, p1, Lc00/y0;->h:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-nez v1, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-object v1, p0, Lc00/y0;->i:Ljava/lang/String;

    .line 74
    .line 75
    iget-object v3, p1, Lc00/y0;->i:Ljava/lang/String;

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
    iget-object v1, p0, Lc00/y0;->j:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v3, p1, Lc00/y0;->j:Ljava/lang/String;

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
    iget-object v1, p0, Lc00/y0;->k:Lc00/v0;

    .line 96
    .line 97
    iget-object v3, p1, Lc00/y0;->k:Lc00/v0;

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
    iget-object v1, p0, Lc00/y0;->l:Ler0/g;

    .line 107
    .line 108
    iget-object v3, p1, Lc00/y0;->l:Ler0/g;

    .line 109
    .line 110
    if-eq v1, v3, :cond_d

    .line 111
    .line 112
    return v2

    .line 113
    :cond_d
    iget-object v1, p0, Lc00/y0;->m:Llf0/i;

    .line 114
    .line 115
    iget-object v3, p1, Lc00/y0;->m:Llf0/i;

    .line 116
    .line 117
    if-eq v1, v3, :cond_e

    .line 118
    .line 119
    return v2

    .line 120
    :cond_e
    iget-boolean v1, p0, Lc00/y0;->n:Z

    .line 121
    .line 122
    iget-boolean v3, p1, Lc00/y0;->n:Z

    .line 123
    .line 124
    if-eq v1, v3, :cond_f

    .line 125
    .line 126
    return v2

    .line 127
    :cond_f
    iget-boolean v1, p0, Lc00/y0;->o:Z

    .line 128
    .line 129
    iget-boolean v3, p1, Lc00/y0;->o:Z

    .line 130
    .line 131
    if-eq v1, v3, :cond_10

    .line 132
    .line 133
    return v2

    .line 134
    :cond_10
    iget-object v1, p0, Lc00/y0;->p:Lqr0/q;

    .line 135
    .line 136
    iget-object v3, p1, Lc00/y0;->p:Lqr0/q;

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
    return v2

    .line 145
    :cond_11
    iget-object v1, p0, Lc00/y0;->q:Lqr0/q;

    .line 146
    .line 147
    iget-object v3, p1, Lc00/y0;->q:Lqr0/q;

    .line 148
    .line 149
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_12

    .line 154
    .line 155
    return v2

    .line 156
    :cond_12
    iget-boolean v1, p0, Lc00/y0;->r:Z

    .line 157
    .line 158
    iget-boolean v3, p1, Lc00/y0;->r:Z

    .line 159
    .line 160
    if-eq v1, v3, :cond_13

    .line 161
    .line 162
    return v2

    .line 163
    :cond_13
    iget-boolean p0, p0, Lc00/y0;->s:Z

    .line 164
    .line 165
    iget-boolean p1, p1, Lc00/y0;->s:Z

    .line 166
    .line 167
    if-eq p0, p1, :cond_14

    .line 168
    .line 169
    return v2

    .line 170
    :cond_14
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lc00/y0;->a:Z

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
    iget-boolean v2, p0, Lc00/y0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lc00/y0;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lc00/y0;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lc00/y0;->e:Lc00/u0;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    const/4 v0, 0x0

    .line 37
    iget-object v3, p0, Lc00/y0;->f:Lc00/w0;

    .line 38
    .line 39
    if-nez v3, :cond_0

    .line 40
    .line 41
    move v3, v0

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    :goto_0
    add-int/2addr v2, v3

    .line 48
    mul-int/2addr v2, v1

    .line 49
    iget-object v3, p0, Lc00/y0;->g:Lc00/x0;

    .line 50
    .line 51
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    add-int/2addr v3, v2

    .line 56
    mul-int/2addr v3, v1

    .line 57
    iget-object v2, p0, Lc00/y0;->h:Ljava/lang/String;

    .line 58
    .line 59
    if-nez v2, :cond_1

    .line 60
    .line 61
    move v2, v0

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    :goto_1
    add-int/2addr v3, v2

    .line 68
    mul-int/2addr v3, v1

    .line 69
    iget-object v2, p0, Lc00/y0;->i:Ljava/lang/String;

    .line 70
    .line 71
    if-nez v2, :cond_2

    .line 72
    .line 73
    move v2, v0

    .line 74
    goto :goto_2

    .line 75
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    :goto_2
    add-int/2addr v3, v2

    .line 80
    mul-int/2addr v3, v1

    .line 81
    iget-object v2, p0, Lc00/y0;->j:Ljava/lang/String;

    .line 82
    .line 83
    if-nez v2, :cond_3

    .line 84
    .line 85
    move v2, v0

    .line 86
    goto :goto_3

    .line 87
    :cond_3
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    :goto_3
    add-int/2addr v3, v2

    .line 92
    mul-int/2addr v3, v1

    .line 93
    iget-object v2, p0, Lc00/y0;->k:Lc00/v0;

    .line 94
    .line 95
    invoke-virtual {v2}, Lc00/v0;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    add-int/2addr v2, v3

    .line 100
    mul-int/2addr v2, v1

    .line 101
    iget-object v3, p0, Lc00/y0;->l:Ler0/g;

    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    add-int/2addr v3, v2

    .line 108
    mul-int/2addr v3, v1

    .line 109
    iget-object v2, p0, Lc00/y0;->m:Llf0/i;

    .line 110
    .line 111
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    add-int/2addr v2, v3

    .line 116
    mul-int/2addr v2, v1

    .line 117
    iget-boolean v3, p0, Lc00/y0;->n:Z

    .line 118
    .line 119
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    iget-boolean v3, p0, Lc00/y0;->o:Z

    .line 124
    .line 125
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 126
    .line 127
    .line 128
    move-result v2

    .line 129
    iget-object v3, p0, Lc00/y0;->p:Lqr0/q;

    .line 130
    .line 131
    if-nez v3, :cond_4

    .line 132
    .line 133
    move v3, v0

    .line 134
    goto :goto_4

    .line 135
    :cond_4
    invoke-virtual {v3}, Lqr0/q;->hashCode()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    :goto_4
    add-int/2addr v2, v3

    .line 140
    mul-int/2addr v2, v1

    .line 141
    iget-object v3, p0, Lc00/y0;->q:Lqr0/q;

    .line 142
    .line 143
    if-nez v3, :cond_5

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_5
    invoke-virtual {v3}, Lqr0/q;->hashCode()I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    :goto_5
    add-int/2addr v2, v0

    .line 151
    mul-int/2addr v2, v1

    .line 152
    iget-boolean v0, p0, Lc00/y0;->r:Z

    .line 153
    .line 154
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    iget-boolean p0, p0, Lc00/y0;->s:Z

    .line 159
    .line 160
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    add-int/2addr p0, v0

    .line 165
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isStatusLoading="

    .line 2
    .line 3
    const-string v1, ", isStatusMissing="

    .line 4
    .line 5
    const-string v2, "State(isRefreshing="

    .line 6
    .line 7
    iget-boolean v3, p0, Lc00/y0;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lc00/y0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isDemoMode="

    .line 16
    .line 17
    const-string v2, ", climateState="

    .line 18
    .line 19
    iget-boolean v3, p0, Lc00/y0;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lc00/y0;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lc00/y0;->e:Lc00/u0;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", climaOperationRequestStatus="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lc00/y0;->f:Lc00/w0;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", windowHeatingState="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lc00/y0;->g:Lc00/x0;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", statusTitle="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lc00/y0;->h:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", climaStatusSubtitle="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", windowHeatingStatusSubtitle="

    .line 67
    .line 68
    const-string v2, ", gauge="

    .line 69
    .line 70
    iget-object v3, p0, Lc00/y0;->i:Ljava/lang/String;

    .line 71
    .line 72
    iget-object v4, p0, Lc00/y0;->j:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lc00/y0;->k:Lc00/v0;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", subscriptionLicenseState="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-object v1, p0, Lc00/y0;->l:Ler0/g;

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", viewMode="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    iget-object v1, p0, Lc00/y0;->m:Llf0/i;

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v1, ", isSaveEnabled="

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    iget-boolean v1, p0, Lc00/y0;->n:Z

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", isWindowHeatingSupported="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    iget-boolean v1, p0, Lc00/y0;->o:Z

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    const-string v1, ", currentTemperature="

    .line 123
    .line 124
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    iget-object v1, p0, Lc00/y0;->p:Lqr0/q;

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v1, ", targetTemperature="

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    iget-object v1, p0, Lc00/y0;->q:Lqr0/q;

    .line 138
    .line 139
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    const-string v1, ", isStatusForceFetched="

    .line 143
    .line 144
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    iget-boolean v1, p0, Lc00/y0;->r:Z

    .line 148
    .line 149
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string v1, ", hasOutsideTemperatureCapability="

    .line 153
    .line 154
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    const-string v1, ")"

    .line 158
    .line 159
    iget-boolean p0, p0, Lc00/y0;->s:Z

    .line 160
    .line 161
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0
.end method
