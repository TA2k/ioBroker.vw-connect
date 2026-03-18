.class public final Lh50/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/Integer;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Lh50/w0;

.field public final g:Lh50/s;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Z

.field public final l:Landroid/net/Uri;

.field public final m:Ljava/lang/String;

.field public final n:Z

.field public final o:Z

.field public final p:Lqp0/e;

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Ljava/lang/String;

.field public final u:Z

.field public final v:Z


# direct methods
.method public constructor <init>(ZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Lh50/w0;Lh50/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLandroid/net/Uri;Ljava/lang/String;ZZLqp0/e;ZZZLjava/lang/String;)V
    .locals 2

    .line 1
    move-object/from16 v0, p16

    .line 2
    .line 3
    const-string v1, "name"

    .line 4
    .line 5
    invoke-static {p5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "indicator"

    .line 9
    .line 10
    invoke-static {p6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-boolean p1, p0, Lh50/u;->a:Z

    .line 17
    .line 18
    iput-object p2, p0, Lh50/u;->b:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p3, p0, Lh50/u;->c:Ljava/lang/Integer;

    .line 21
    .line 22
    iput-object p4, p0, Lh50/u;->d:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p5, p0, Lh50/u;->e:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p6, p0, Lh50/u;->f:Lh50/w0;

    .line 27
    .line 28
    iput-object p7, p0, Lh50/u;->g:Lh50/s;

    .line 29
    .line 30
    iput-object p8, p0, Lh50/u;->h:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p9, p0, Lh50/u;->i:Ljava/lang/String;

    .line 33
    .line 34
    iput-object p10, p0, Lh50/u;->j:Ljava/lang/String;

    .line 35
    .line 36
    iput-boolean p11, p0, Lh50/u;->k:Z

    .line 37
    .line 38
    move-object p1, p12

    .line 39
    iput-object p1, p0, Lh50/u;->l:Landroid/net/Uri;

    .line 40
    .line 41
    move-object p1, p13

    .line 42
    iput-object p1, p0, Lh50/u;->m:Ljava/lang/String;

    .line 43
    .line 44
    move/from16 p1, p14

    .line 45
    .line 46
    iput-boolean p1, p0, Lh50/u;->n:Z

    .line 47
    .line 48
    move/from16 p1, p15

    .line 49
    .line 50
    iput-boolean p1, p0, Lh50/u;->o:Z

    .line 51
    .line 52
    iput-object v0, p0, Lh50/u;->p:Lqp0/e;

    .line 53
    .line 54
    move/from16 p1, p17

    .line 55
    .line 56
    iput-boolean p1, p0, Lh50/u;->q:Z

    .line 57
    .line 58
    move/from16 p1, p18

    .line 59
    .line 60
    iput-boolean p1, p0, Lh50/u;->r:Z

    .line 61
    .line 62
    move/from16 p1, p19

    .line 63
    .line 64
    iput-boolean p1, p0, Lh50/u;->s:Z

    .line 65
    .line 66
    move-object/from16 p1, p20

    .line 67
    .line 68
    iput-object p1, p0, Lh50/u;->t:Ljava/lang/String;

    .line 69
    .line 70
    const/4 p1, 0x1

    .line 71
    const/4 p5, 0x0

    .line 72
    if-nez p4, :cond_1

    .line 73
    .line 74
    if-eqz p3, :cond_0

    .line 75
    .line 76
    if-eqz p2, :cond_0

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_0
    move p2, p5

    .line 80
    goto :goto_1

    .line 81
    :cond_1
    :goto_0
    move p2, p1

    .line 82
    :goto_1
    iput-boolean p2, p0, Lh50/u;->u:Z

    .line 83
    .line 84
    if-nez p7, :cond_4

    .line 85
    .line 86
    if-nez p8, :cond_4

    .line 87
    .line 88
    if-eqz p9, :cond_2

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_2
    if-eqz v0, :cond_3

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_3
    move p1, p5

    .line 95
    :cond_4
    :goto_2
    iput-boolean p1, p0, Lh50/u;->v:Z

    .line 96
    .line 97
    return-void
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
    instance-of v1, p1, Lh50/u;

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
    check-cast p1, Lh50/u;

    .line 12
    .line 13
    iget-boolean v1, p0, Lh50/u;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lh50/u;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lh50/u;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lh50/u;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lh50/u;->c:Ljava/lang/Integer;

    .line 32
    .line 33
    iget-object v3, p1, Lh50/u;->c:Ljava/lang/Integer;

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
    iget-object v1, p0, Lh50/u;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lh50/u;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lh50/u;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lh50/u;->e:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lh50/u;->f:Lh50/w0;

    .line 65
    .line 66
    iget-object v3, p1, Lh50/u;->f:Lh50/w0;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lh50/u;->g:Lh50/s;

    .line 76
    .line 77
    iget-object v3, p1, Lh50/u;->g:Lh50/s;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lh50/u;->h:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v3, p1, Lh50/u;->h:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-object v1, p0, Lh50/u;->i:Ljava/lang/String;

    .line 98
    .line 99
    iget-object v3, p1, Lh50/u;->i:Ljava/lang/String;

    .line 100
    .line 101
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-nez v1, :cond_a

    .line 106
    .line 107
    return v2

    .line 108
    :cond_a
    iget-object v1, p0, Lh50/u;->j:Ljava/lang/String;

    .line 109
    .line 110
    iget-object v3, p1, Lh50/u;->j:Ljava/lang/String;

    .line 111
    .line 112
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-nez v1, :cond_b

    .line 117
    .line 118
    return v2

    .line 119
    :cond_b
    iget-boolean v1, p0, Lh50/u;->k:Z

    .line 120
    .line 121
    iget-boolean v3, p1, Lh50/u;->k:Z

    .line 122
    .line 123
    if-eq v1, v3, :cond_c

    .line 124
    .line 125
    return v2

    .line 126
    :cond_c
    iget-object v1, p0, Lh50/u;->l:Landroid/net/Uri;

    .line 127
    .line 128
    iget-object v3, p1, Lh50/u;->l:Landroid/net/Uri;

    .line 129
    .line 130
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-nez v1, :cond_d

    .line 135
    .line 136
    return v2

    .line 137
    :cond_d
    iget-object v1, p0, Lh50/u;->m:Ljava/lang/String;

    .line 138
    .line 139
    iget-object v3, p1, Lh50/u;->m:Ljava/lang/String;

    .line 140
    .line 141
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    if-nez v1, :cond_e

    .line 146
    .line 147
    return v2

    .line 148
    :cond_e
    iget-boolean v1, p0, Lh50/u;->n:Z

    .line 149
    .line 150
    iget-boolean v3, p1, Lh50/u;->n:Z

    .line 151
    .line 152
    if-eq v1, v3, :cond_f

    .line 153
    .line 154
    return v2

    .line 155
    :cond_f
    iget-boolean v1, p0, Lh50/u;->o:Z

    .line 156
    .line 157
    iget-boolean v3, p1, Lh50/u;->o:Z

    .line 158
    .line 159
    if-eq v1, v3, :cond_10

    .line 160
    .line 161
    return v2

    .line 162
    :cond_10
    iget-object v1, p0, Lh50/u;->p:Lqp0/e;

    .line 163
    .line 164
    iget-object v3, p1, Lh50/u;->p:Lqp0/e;

    .line 165
    .line 166
    if-eq v1, v3, :cond_11

    .line 167
    .line 168
    return v2

    .line 169
    :cond_11
    iget-boolean v1, p0, Lh50/u;->q:Z

    .line 170
    .line 171
    iget-boolean v3, p1, Lh50/u;->q:Z

    .line 172
    .line 173
    if-eq v1, v3, :cond_12

    .line 174
    .line 175
    return v2

    .line 176
    :cond_12
    iget-boolean v1, p0, Lh50/u;->r:Z

    .line 177
    .line 178
    iget-boolean v3, p1, Lh50/u;->r:Z

    .line 179
    .line 180
    if-eq v1, v3, :cond_13

    .line 181
    .line 182
    return v2

    .line 183
    :cond_13
    iget-boolean v1, p0, Lh50/u;->s:Z

    .line 184
    .line 185
    iget-boolean v3, p1, Lh50/u;->s:Z

    .line 186
    .line 187
    if-eq v1, v3, :cond_14

    .line 188
    .line 189
    return v2

    .line 190
    :cond_14
    iget-object p0, p0, Lh50/u;->t:Ljava/lang/String;

    .line 191
    .line 192
    iget-object p1, p1, Lh50/u;->t:Ljava/lang/String;

    .line 193
    .line 194
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result p0

    .line 198
    if-nez p0, :cond_15

    .line 199
    .line 200
    return v2

    .line 201
    :cond_15
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lh50/u;->a:Z

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lh50/u;->b:Ljava/lang/String;

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
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

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
    iget-object v3, p0, Lh50/u;->c:Ljava/lang/Integer;

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    move v3, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    :goto_1
    add-int/2addr v0, v3

    .line 34
    mul-int/2addr v0, v1

    .line 35
    iget-object v3, p0, Lh50/u;->d:Ljava/lang/String;

    .line 36
    .line 37
    if-nez v3, :cond_2

    .line 38
    .line 39
    move v3, v2

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    :goto_2
    add-int/2addr v0, v3

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v3, p0, Lh50/u;->e:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-object v3, p0, Lh50/u;->f:Lh50/w0;

    .line 54
    .line 55
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    add-int/2addr v3, v0

    .line 60
    mul-int/2addr v3, v1

    .line 61
    iget-object v0, p0, Lh50/u;->g:Lh50/s;

    .line 62
    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    move v0, v2

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    invoke-virtual {v0}, Lh50/s;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    :goto_3
    add-int/2addr v3, v0

    .line 72
    mul-int/2addr v3, v1

    .line 73
    iget-object v0, p0, Lh50/u;->h:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v0, :cond_4

    .line 76
    .line 77
    move v0, v2

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    :goto_4
    add-int/2addr v3, v0

    .line 84
    mul-int/2addr v3, v1

    .line 85
    iget-object v0, p0, Lh50/u;->i:Ljava/lang/String;

    .line 86
    .line 87
    if-nez v0, :cond_5

    .line 88
    .line 89
    move v0, v2

    .line 90
    goto :goto_5

    .line 91
    :cond_5
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    :goto_5
    add-int/2addr v3, v0

    .line 96
    mul-int/2addr v3, v1

    .line 97
    iget-object v0, p0, Lh50/u;->j:Ljava/lang/String;

    .line 98
    .line 99
    if-nez v0, :cond_6

    .line 100
    .line 101
    move v0, v2

    .line 102
    goto :goto_6

    .line 103
    :cond_6
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    :goto_6
    add-int/2addr v3, v0

    .line 108
    mul-int/2addr v3, v1

    .line 109
    iget-boolean v0, p0, Lh50/u;->k:Z

    .line 110
    .line 111
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    iget-object v3, p0, Lh50/u;->l:Landroid/net/Uri;

    .line 116
    .line 117
    if-nez v3, :cond_7

    .line 118
    .line 119
    move v3, v2

    .line 120
    goto :goto_7

    .line 121
    :cond_7
    invoke-virtual {v3}, Landroid/net/Uri;->hashCode()I

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    :goto_7
    add-int/2addr v0, v3

    .line 126
    mul-int/2addr v0, v1

    .line 127
    iget-object v3, p0, Lh50/u;->m:Ljava/lang/String;

    .line 128
    .line 129
    if-nez v3, :cond_8

    .line 130
    .line 131
    move v3, v2

    .line 132
    goto :goto_8

    .line 133
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    :goto_8
    add-int/2addr v0, v3

    .line 138
    mul-int/2addr v0, v1

    .line 139
    iget-boolean v3, p0, Lh50/u;->n:Z

    .line 140
    .line 141
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    iget-boolean v3, p0, Lh50/u;->o:Z

    .line 146
    .line 147
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    iget-object v3, p0, Lh50/u;->p:Lqp0/e;

    .line 152
    .line 153
    if-nez v3, :cond_9

    .line 154
    .line 155
    move v3, v2

    .line 156
    goto :goto_9

    .line 157
    :cond_9
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    :goto_9
    add-int/2addr v0, v3

    .line 162
    mul-int/2addr v0, v1

    .line 163
    iget-boolean v3, p0, Lh50/u;->q:Z

    .line 164
    .line 165
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    iget-boolean v3, p0, Lh50/u;->r:Z

    .line 170
    .line 171
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 172
    .line 173
    .line 174
    move-result v0

    .line 175
    iget-boolean v3, p0, Lh50/u;->s:Z

    .line 176
    .line 177
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    iget-object p0, p0, Lh50/u;->t:Ljava/lang/String;

    .line 182
    .line 183
    if-nez p0, :cond_a

    .line 184
    .line 185
    goto :goto_a

    .line 186
    :cond_a
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 187
    .line 188
    .line 189
    move-result v2

    .line 190
    :goto_a
    add-int/2addr v0, v2

    .line 191
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", chargingPower="

    .line 2
    .line 3
    const-string v1, ", chargingIconResId="

    .line 4
    .line 5
    const-string v2, "Stop(isPowerpassIconVisible="

    .line 6
    .line 7
    iget-object v3, p0, Lh50/u;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lh50/u;->a:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v3, v1, v4}, La7/g0;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lh50/u;->c:Ljava/lang/Integer;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", chargerType="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lh50/u;->d:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", name="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lh50/u;->e:Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", indicator="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lh50/u;->f:Lh50/w0;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, ", batteryStart="

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-object v1, p0, Lh50/u;->g:Lh50/s;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v1, ", batteryEnd="

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lh50/u;->h:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, ", chargeDuration="

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", distanceDuration="

    .line 76
    .line 77
    const-string v2, ", isCharger="

    .line 78
    .line 79
    iget-object v3, p0, Lh50/u;->i:Ljava/lang/String;

    .line 80
    .line 81
    iget-object v4, p0, Lh50/u;->j:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    iget-boolean v1, p0, Lh50/u;->k:Z

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v1, ", image="

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Lh50/u;->l:Landroid/net/Uri;

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v1, ", rating="

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string v1, ", isSuggestion="

    .line 107
    .line 108
    const-string v2, ", isBatteryLevelSet="

    .line 109
    .line 110
    iget-object v3, p0, Lh50/u;->m:Ljava/lang/String;

    .line 111
    .line 112
    iget-boolean v4, p0, Lh50/u;->n:Z

    .line 113
    .line 114
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 115
    .line 116
    .line 117
    iget-boolean v1, p0, Lh50/u;->o:Z

    .line 118
    .line 119
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    const-string v1, ", batteryLevelType="

    .line 123
    .line 124
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    iget-object v1, p0, Lh50/u;->p:Lqp0/e;

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string v1, ", isBatteryLevelChangeEnabled="

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    const-string v1, ", isAIGenerated="

    .line 138
    .line 139
    const-string v2, ", isNextWaypointInWalkingDistance="

    .line 140
    .line 141
    iget-boolean v3, p0, Lh50/u;->q:Z

    .line 142
    .line 143
    iget-boolean v4, p0, Lh50/u;->r:Z

    .line 144
    .line 145
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 146
    .line 147
    .line 148
    iget-boolean v1, p0, Lh50/u;->s:Z

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string v1, ", placeReviewRating="

    .line 154
    .line 155
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    iget-object p0, p0, Lh50/u;->t:Ljava/lang/String;

    .line 159
    .line 160
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    const-string p0, ")"

    .line 164
    .line 165
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0
.end method
