.class public final Lh40/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Z

.field public final B:Z

.field public final C:Z

.field public final D:Z

.field public final E:Z

.field public final F:Z

.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:I

.field public final f:I

.field public final g:I

.field public final h:J

.field public final i:Lh40/n;

.field public final j:Lh40/o;

.field public final k:Z

.field public final l:Z

.field public final m:Landroid/net/Uri;

.field public final n:Z

.field public final o:Ljava/lang/Boolean;

.field public final p:Ljava/lang/String;

.field public final q:Lh40/l;

.field public final r:Ljava/lang/Integer;

.field public final s:Ljava/lang/Integer;

.field public final t:Ljava/lang/Integer;

.field public final u:Ljava/lang/Integer;

.field public final v:Z

.field public final w:Z

.field public final x:Z

.field public final y:Z

.field public final z:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIJLh40/n;Lh40/o;ZZLandroid/net/Uri;ZLjava/lang/Boolean;Ljava/lang/String;Lh40/l;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V
    .locals 4

    move-object v0, p11

    move/from16 v1, p15

    move-object/from16 v2, p16

    const-string v3, "id"

    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "title"

    invoke-static {p2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "description"

    invoke-static {p3, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "detailedDescription"

    invoke-static {p4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lh40/m;->a:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lh40/m;->b:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lh40/m;->c:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lh40/m;->d:Ljava/lang/String;

    .line 6
    iput p5, p0, Lh40/m;->e:I

    .line 7
    iput p6, p0, Lh40/m;->f:I

    .line 8
    iput p7, p0, Lh40/m;->g:I

    .line 9
    iput-wide p8, p0, Lh40/m;->h:J

    .line 10
    iput-object p10, p0, Lh40/m;->i:Lh40/n;

    .line 11
    iput-object v0, p0, Lh40/m;->j:Lh40/o;

    move/from16 p1, p12

    .line 12
    iput-boolean p1, p0, Lh40/m;->k:Z

    move/from16 p1, p13

    .line 13
    iput-boolean p1, p0, Lh40/m;->l:Z

    move-object/from16 p1, p14

    .line 14
    iput-object p1, p0, Lh40/m;->m:Landroid/net/Uri;

    .line 15
    iput-boolean v1, p0, Lh40/m;->n:Z

    .line 16
    iput-object v2, p0, Lh40/m;->o:Ljava/lang/Boolean;

    move-object/from16 p1, p17

    .line 17
    iput-object p1, p0, Lh40/m;->p:Ljava/lang/String;

    move-object/from16 p1, p18

    .line 18
    iput-object p1, p0, Lh40/m;->q:Lh40/l;

    move-object/from16 p1, p19

    .line 19
    iput-object p1, p0, Lh40/m;->r:Ljava/lang/Integer;

    move-object/from16 p1, p20

    .line 20
    iput-object p1, p0, Lh40/m;->s:Ljava/lang/Integer;

    move-object/from16 p1, p21

    .line 21
    iput-object p1, p0, Lh40/m;->t:Ljava/lang/Integer;

    move-object/from16 p1, p22

    .line 22
    iput-object p1, p0, Lh40/m;->u:Ljava/lang/Integer;

    .line 23
    sget-object p1, Lh40/n;->d:Lh40/n;

    const/4 p2, 0x0

    const/4 p3, 0x1

    if-ne p10, p1, :cond_0

    move p1, p3

    goto :goto_0

    :cond_0
    move p1, p2

    :goto_0
    iput-boolean p1, p0, Lh40/m;->v:Z

    .line 24
    sget-object p1, Lh40/n;->f:Lh40/n;

    if-ne p10, p1, :cond_1

    move p1, p3

    goto :goto_1

    :cond_1
    move p1, p2

    :goto_1
    iput-boolean p1, p0, Lh40/m;->w:Z

    .line 25
    sget-object p4, Lh40/n;->e:Lh40/n;

    if-ne p10, p4, :cond_2

    move p4, p3

    goto :goto_2

    :cond_2
    move p4, p2

    :goto_2
    iput-boolean p4, p0, Lh40/m;->x:Z

    .line 26
    sget-object p5, Lh40/n;->g:Lh40/n;

    if-ne p10, p5, :cond_3

    move p5, p3

    goto :goto_3

    :cond_3
    move p5, p2

    :goto_3
    iput-boolean p5, p0, Lh40/m;->y:Z

    if-eqz v1, :cond_4

    .line 27
    sget-object p5, Lh40/o;->i:Lh40/o;

    if-ne v0, p5, :cond_4

    move p5, p3

    goto :goto_4

    :cond_4
    move p5, p2

    :goto_4
    iput-boolean p5, p0, Lh40/m;->z:Z

    if-nez p4, :cond_5

    .line 28
    sget-object p5, Lh40/o;->f:Lh40/o;

    if-ne v0, p5, :cond_5

    move p5, p3

    goto :goto_5

    :cond_5
    move p5, p2

    :goto_5
    iput-boolean p5, p0, Lh40/m;->A:Z

    .line 29
    sget-object p5, Lh40/o;->i:Lh40/o;

    if-ne v0, p5, :cond_6

    if-eqz p1, :cond_6

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_6

    move p1, p3

    goto :goto_6

    :cond_6
    move p1, p2

    :goto_6
    iput-boolean p1, p0, Lh40/m;->B:Z

    if-nez p4, :cond_7

    .line 30
    sget-object p1, Lh40/o;->h:Lh40/o;

    if-ne v0, p1, :cond_7

    move p1, p3

    goto :goto_7

    :cond_7
    move p1, p2

    :goto_7
    iput-boolean p1, p0, Lh40/m;->C:Z

    if-nez p4, :cond_8

    .line 31
    sget-object p1, Lh40/o;->e:Lh40/o;

    if-ne v0, p1, :cond_8

    move p1, p3

    goto :goto_8

    :cond_8
    move p1, p2

    :goto_8
    iput-boolean p1, p0, Lh40/m;->D:Z

    if-nez p4, :cond_9

    .line 32
    sget-object p1, Lh40/o;->j:Lh40/o;

    if-ne v0, p1, :cond_9

    move p1, p3

    goto :goto_9

    :cond_9
    move p1, p2

    :goto_9
    iput-boolean p1, p0, Lh40/m;->E:Z

    if-nez p4, :cond_a

    .line 33
    sget-object p1, Lh40/o;->g:Lh40/o;

    if-ne v0, p1, :cond_a

    move p2, p3

    :cond_a
    iput-boolean p2, p0, Lh40/m;->F:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIJLh40/n;Ljava/lang/Boolean;Lh40/l;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;I)V
    .locals 23

    move/from16 v0, p16

    sget-object v11, Lh40/o;->i:Lh40/o;

    and-int/lit8 v1, v0, 0x20

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move v6, v2

    goto :goto_0

    :cond_0
    move/from16 v6, p6

    :goto_0
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_1

    move v7, v2

    goto :goto_1

    :cond_1
    const/16 v1, 0x16

    move v7, v1

    :goto_1
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_2

    const-wide/16 v3, 0x0

    move-wide v8, v3

    goto :goto_2

    :cond_2
    move-wide/from16 v8, p7

    :goto_2
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_3

    :goto_3
    move v13, v2

    goto :goto_4

    :cond_3
    const/4 v2, 0x1

    goto :goto_3

    :goto_4
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    const/4 v2, 0x0

    if-eqz v1, :cond_4

    move-object/from16 v18, v2

    goto :goto_5

    :cond_4
    move-object/from16 v18, p11

    :goto_5
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_5

    move-object/from16 v19, v2

    goto :goto_6

    :cond_5
    move-object/from16 v19, p12

    :goto_6
    const/high16 v1, 0x40000

    and-int/2addr v1, v0

    if-eqz v1, :cond_6

    move-object/from16 v20, v2

    goto :goto_7

    :cond_6
    move-object/from16 v20, p13

    :goto_7
    const/high16 v1, 0x80000

    and-int/2addr v1, v0

    if-eqz v1, :cond_7

    move-object/from16 v21, v2

    goto :goto_8

    :cond_7
    move-object/from16 v21, p14

    :goto_8
    const/high16 v1, 0x100000

    and-int/2addr v0, v1

    if-eqz v0, :cond_8

    move-object/from16 v22, v2

    goto :goto_9

    :cond_8
    move-object/from16 v22, p15

    :goto_9
    const/4 v12, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x1

    const/16 v17, 0x0

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    move-object/from16 v4, p4

    move/from16 v5, p5

    move-object/from16 v10, p9

    move-object/from16 v16, p10

    .line 34
    invoke-direct/range {v0 .. v22}, Lh40/m;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIJLh40/n;Lh40/o;ZZLandroid/net/Uri;ZLjava/lang/Boolean;Ljava/lang/String;Lh40/l;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lh40/m;

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
    check-cast p1, Lh40/m;

    .line 12
    .line 13
    iget-object v1, p0, Lh40/m;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lh40/m;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lh40/m;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lh40/m;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lh40/m;->d:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget v1, p0, Lh40/m;->e:I

    .line 58
    .line 59
    iget v3, p1, Lh40/m;->e:I

    .line 60
    .line 61
    if-eq v1, v3, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget v1, p0, Lh40/m;->f:I

    .line 65
    .line 66
    iget v3, p1, Lh40/m;->f:I

    .line 67
    .line 68
    if-eq v1, v3, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget v1, p0, Lh40/m;->g:I

    .line 72
    .line 73
    iget v3, p1, Lh40/m;->g:I

    .line 74
    .line 75
    if-eq v1, v3, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-wide v3, p0, Lh40/m;->h:J

    .line 79
    .line 80
    iget-wide v5, p1, Lh40/m;->h:J

    .line 81
    .line 82
    cmp-long v1, v3, v5

    .line 83
    .line 84
    if-eqz v1, :cond_9

    .line 85
    .line 86
    return v2

    .line 87
    :cond_9
    iget-object v1, p0, Lh40/m;->i:Lh40/n;

    .line 88
    .line 89
    iget-object v3, p1, Lh40/m;->i:Lh40/n;

    .line 90
    .line 91
    if-eq v1, v3, :cond_a

    .line 92
    .line 93
    return v2

    .line 94
    :cond_a
    iget-object v1, p0, Lh40/m;->j:Lh40/o;

    .line 95
    .line 96
    iget-object v3, p1, Lh40/m;->j:Lh40/o;

    .line 97
    .line 98
    if-eq v1, v3, :cond_b

    .line 99
    .line 100
    return v2

    .line 101
    :cond_b
    iget-boolean v1, p0, Lh40/m;->k:Z

    .line 102
    .line 103
    iget-boolean v3, p1, Lh40/m;->k:Z

    .line 104
    .line 105
    if-eq v1, v3, :cond_c

    .line 106
    .line 107
    return v2

    .line 108
    :cond_c
    iget-boolean v1, p0, Lh40/m;->l:Z

    .line 109
    .line 110
    iget-boolean v3, p1, Lh40/m;->l:Z

    .line 111
    .line 112
    if-eq v1, v3, :cond_d

    .line 113
    .line 114
    return v2

    .line 115
    :cond_d
    iget-object v1, p0, Lh40/m;->m:Landroid/net/Uri;

    .line 116
    .line 117
    iget-object v3, p1, Lh40/m;->m:Landroid/net/Uri;

    .line 118
    .line 119
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    if-nez v1, :cond_e

    .line 124
    .line 125
    return v2

    .line 126
    :cond_e
    iget-boolean v1, p0, Lh40/m;->n:Z

    .line 127
    .line 128
    iget-boolean v3, p1, Lh40/m;->n:Z

    .line 129
    .line 130
    if-eq v1, v3, :cond_f

    .line 131
    .line 132
    return v2

    .line 133
    :cond_f
    iget-object v1, p0, Lh40/m;->o:Ljava/lang/Boolean;

    .line 134
    .line 135
    iget-object v3, p1, Lh40/m;->o:Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-nez v1, :cond_10

    .line 142
    .line 143
    return v2

    .line 144
    :cond_10
    iget-object v1, p0, Lh40/m;->p:Ljava/lang/String;

    .line 145
    .line 146
    iget-object v3, p1, Lh40/m;->p:Ljava/lang/String;

    .line 147
    .line 148
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-nez v1, :cond_11

    .line 153
    .line 154
    return v2

    .line 155
    :cond_11
    iget-object v1, p0, Lh40/m;->q:Lh40/l;

    .line 156
    .line 157
    iget-object v3, p1, Lh40/m;->q:Lh40/l;

    .line 158
    .line 159
    if-eq v1, v3, :cond_12

    .line 160
    .line 161
    return v2

    .line 162
    :cond_12
    iget-object v1, p0, Lh40/m;->r:Ljava/lang/Integer;

    .line 163
    .line 164
    iget-object v3, p1, Lh40/m;->r:Ljava/lang/Integer;

    .line 165
    .line 166
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v1

    .line 170
    if-nez v1, :cond_13

    .line 171
    .line 172
    return v2

    .line 173
    :cond_13
    iget-object v1, p0, Lh40/m;->s:Ljava/lang/Integer;

    .line 174
    .line 175
    iget-object v3, p1, Lh40/m;->s:Ljava/lang/Integer;

    .line 176
    .line 177
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-nez v1, :cond_14

    .line 182
    .line 183
    return v2

    .line 184
    :cond_14
    iget-object v1, p0, Lh40/m;->t:Ljava/lang/Integer;

    .line 185
    .line 186
    iget-object v3, p1, Lh40/m;->t:Ljava/lang/Integer;

    .line 187
    .line 188
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    if-nez v1, :cond_15

    .line 193
    .line 194
    return v2

    .line 195
    :cond_15
    iget-object p0, p0, Lh40/m;->u:Ljava/lang/Integer;

    .line 196
    .line 197
    iget-object p1, p1, Lh40/m;->u:Ljava/lang/Integer;

    .line 198
    .line 199
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    if-nez p0, :cond_16

    .line 204
    .line 205
    return v2

    .line 206
    :cond_16
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lh40/m;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lh40/m;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lh40/m;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lh40/m;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget v2, p0, Lh40/m;->e:I

    .line 29
    .line 30
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget v2, p0, Lh40/m;->f:I

    .line 35
    .line 36
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget v2, p0, Lh40/m;->g:I

    .line 41
    .line 42
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-wide v2, p0, Lh40/m;->h:J

    .line 47
    .line 48
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Lh40/m;->i:Lh40/n;

    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    add-int/2addr v2, v0

    .line 59
    mul-int/2addr v2, v1

    .line 60
    iget-object v0, p0, Lh40/m;->j:Lh40/o;

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    add-int/2addr v0, v2

    .line 67
    mul-int/2addr v0, v1

    .line 68
    iget-boolean v2, p0, Lh40/m;->k:Z

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-boolean v2, p0, Lh40/m;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    const/4 v2, 0x0

    .line 81
    iget-object v3, p0, Lh40/m;->m:Landroid/net/Uri;

    .line 82
    .line 83
    if-nez v3, :cond_0

    .line 84
    .line 85
    move v3, v2

    .line 86
    goto :goto_0

    .line 87
    :cond_0
    invoke-virtual {v3}, Landroid/net/Uri;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    :goto_0
    add-int/2addr v0, v3

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-boolean v3, p0, Lh40/m;->n:Z

    .line 94
    .line 95
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    iget-object v3, p0, Lh40/m;->o:Ljava/lang/Boolean;

    .line 100
    .line 101
    if-nez v3, :cond_1

    .line 102
    .line 103
    move v3, v2

    .line 104
    goto :goto_1

    .line 105
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    :goto_1
    add-int/2addr v0, v3

    .line 110
    mul-int/2addr v0, v1

    .line 111
    iget-object v3, p0, Lh40/m;->p:Ljava/lang/String;

    .line 112
    .line 113
    if-nez v3, :cond_2

    .line 114
    .line 115
    move v3, v2

    .line 116
    goto :goto_2

    .line 117
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    :goto_2
    add-int/2addr v0, v3

    .line 122
    mul-int/2addr v0, v1

    .line 123
    iget-object v3, p0, Lh40/m;->q:Lh40/l;

    .line 124
    .line 125
    if-nez v3, :cond_3

    .line 126
    .line 127
    move v3, v2

    .line 128
    goto :goto_3

    .line 129
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    :goto_3
    add-int/2addr v0, v3

    .line 134
    mul-int/2addr v0, v1

    .line 135
    iget-object v3, p0, Lh40/m;->r:Ljava/lang/Integer;

    .line 136
    .line 137
    if-nez v3, :cond_4

    .line 138
    .line 139
    move v3, v2

    .line 140
    goto :goto_4

    .line 141
    :cond_4
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    :goto_4
    add-int/2addr v0, v3

    .line 146
    mul-int/2addr v0, v1

    .line 147
    iget-object v3, p0, Lh40/m;->s:Ljava/lang/Integer;

    .line 148
    .line 149
    if-nez v3, :cond_5

    .line 150
    .line 151
    move v3, v2

    .line 152
    goto :goto_5

    .line 153
    :cond_5
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 154
    .line 155
    .line 156
    move-result v3

    .line 157
    :goto_5
    add-int/2addr v0, v3

    .line 158
    mul-int/2addr v0, v1

    .line 159
    iget-object v3, p0, Lh40/m;->t:Ljava/lang/Integer;

    .line 160
    .line 161
    if-nez v3, :cond_6

    .line 162
    .line 163
    move v3, v2

    .line 164
    goto :goto_6

    .line 165
    :cond_6
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    :goto_6
    add-int/2addr v0, v3

    .line 170
    mul-int/2addr v0, v1

    .line 171
    iget-object p0, p0, Lh40/m;->u:Ljava/lang/Integer;

    .line 172
    .line 173
    if-nez p0, :cond_7

    .line 174
    .line 175
    goto :goto_7

    .line 176
    :cond_7
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    :goto_7
    add-int/2addr v0, v2

    .line 181
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", title="

    .line 2
    .line 3
    const-string v1, ", description="

    .line 4
    .line 5
    const-string v2, "ChallengeState(id="

    .line 6
    .line 7
    iget-object v3, p0, Lh40/m;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lh40/m;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", detailedDescription="

    .line 16
    .line 17
    const-string v2, ", points="

    .line 18
    .line 19
    iget-object v3, p0, Lh40/m;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lh40/m;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", totalActivities="

    .line 27
    .line 28
    const-string v2, ", percentageCompleted="

    .line 29
    .line 30
    iget v3, p0, Lh40/m;->e:I

    .line 31
    .line 32
    iget v4, p0, Lh40/m;->f:I

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget v1, p0, Lh40/m;->g:I

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", daysLeft="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-wide v1, p0, Lh40/m;->h:J

    .line 48
    .line 49
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v1, ", status="

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lh40/m;->i:Lh40/n;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", type="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Lh40/m;->j:Lh40/o;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", highlighted="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-boolean v1, p0, Lh40/m;->k:Z

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", displayImage="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-boolean v1, p0, Lh40/m;->l:Z

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", imageUri="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    iget-object v1, p0, Lh40/m;->m:Landroid/net/Uri;

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v1, ", isEnrollmentRequired="

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    iget-boolean v1, p0, Lh40/m;->n:Z

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", showEligibilityHint="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    iget-object v1, p0, Lh40/m;->o:Ljava/lang/Boolean;

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    const-string v1, ", vehicleName="

    .line 123
    .line 124
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    iget-object v1, p0, Lh40/m;->p:Ljava/lang/String;

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v1, ", progressType="

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    iget-object v1, p0, Lh40/m;->q:Lh40/l;

    .line 138
    .line 139
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    const-string v1, ", maxFailedAttempts="

    .line 143
    .line 144
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    iget-object v1, p0, Lh40/m;->r:Ljava/lang/Integer;

    .line 148
    .line 149
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string v1, ", attemptsRemaining="

    .line 153
    .line 154
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    iget-object v1, p0, Lh40/m;->s:Ljava/lang/Integer;

    .line 158
    .line 159
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    const-string v1, ", daysToComplete="

    .line 163
    .line 164
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    iget-object v1, p0, Lh40/m;->t:Ljava/lang/Integer;

    .line 168
    .line 169
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    const-string v1, ", daysCompleted="

    .line 173
    .line 174
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    iget-object p0, p0, Lh40/m;->u:Ljava/lang/Integer;

    .line 178
    .line 179
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    const-string p0, ")"

    .line 183
    .line 184
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    return-object p0
.end method
