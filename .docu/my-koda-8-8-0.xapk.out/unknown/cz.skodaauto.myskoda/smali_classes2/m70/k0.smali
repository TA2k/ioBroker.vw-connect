.class public final Lm70/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;

.field public final q:Ljava/lang/String;

.field public final r:Ljava/lang/String;


# direct methods
.method public constructor <init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "date"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "endTime"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "duration"

    .line 12
    .line 13
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "distance"

    .line 17
    .line 18
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-boolean p1, p0, Lm70/k0;->a:Z

    .line 25
    .line 26
    iput-object p2, p0, Lm70/k0;->b:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p3, p0, Lm70/k0;->c:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p4, p0, Lm70/k0;->d:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p5, p0, Lm70/k0;->e:Ljava/lang/String;

    .line 33
    .line 34
    iput-object p6, p0, Lm70/k0;->f:Ljava/lang/String;

    .line 35
    .line 36
    iput-object p7, p0, Lm70/k0;->g:Ljava/lang/String;

    .line 37
    .line 38
    iput-object p8, p0, Lm70/k0;->h:Ljava/lang/String;

    .line 39
    .line 40
    iput-object p9, p0, Lm70/k0;->i:Ljava/lang/String;

    .line 41
    .line 42
    iput-object p10, p0, Lm70/k0;->j:Ljava/lang/String;

    .line 43
    .line 44
    iput-object p11, p0, Lm70/k0;->k:Ljava/lang/String;

    .line 45
    .line 46
    iput-object p12, p0, Lm70/k0;->l:Ljava/lang/String;

    .line 47
    .line 48
    iput-object p13, p0, Lm70/k0;->m:Ljava/lang/String;

    .line 49
    .line 50
    iput-object p14, p0, Lm70/k0;->n:Ljava/lang/String;

    .line 51
    .line 52
    move-object/from16 p1, p15

    .line 53
    .line 54
    iput-object p1, p0, Lm70/k0;->o:Ljava/lang/String;

    .line 55
    .line 56
    move-object/from16 p1, p16

    .line 57
    .line 58
    iput-object p1, p0, Lm70/k0;->p:Ljava/lang/String;

    .line 59
    .line 60
    move-object/from16 p1, p17

    .line 61
    .line 62
    iput-object p1, p0, Lm70/k0;->q:Ljava/lang/String;

    .line 63
    .line 64
    move-object/from16 p1, p18

    .line 65
    .line 66
    iput-object p1, p0, Lm70/k0;->r:Ljava/lang/String;

    .line 67
    .line 68
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
    instance-of v1, p1, Lm70/k0;

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
    check-cast p1, Lm70/k0;

    .line 12
    .line 13
    iget-boolean v1, p0, Lm70/k0;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lm70/k0;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lm70/k0;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lm70/k0;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lm70/k0;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->d:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lm70/k0;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lm70/k0;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->f:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v3, p1, Lm70/k0;->f:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->g:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v3, p1, Lm70/k0;->g:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->h:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v3, p1, Lm70/k0;->h:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->i:Ljava/lang/String;

    .line 98
    .line 99
    iget-object v3, p1, Lm70/k0;->i:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->j:Ljava/lang/String;

    .line 109
    .line 110
    iget-object v3, p1, Lm70/k0;->j:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/k0;->k:Ljava/lang/String;

    .line 120
    .line 121
    iget-object v3, p1, Lm70/k0;->k:Ljava/lang/String;

    .line 122
    .line 123
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-nez v1, :cond_c

    .line 128
    .line 129
    return v2

    .line 130
    :cond_c
    iget-object v1, p0, Lm70/k0;->l:Ljava/lang/String;

    .line 131
    .line 132
    iget-object v3, p1, Lm70/k0;->l:Ljava/lang/String;

    .line 133
    .line 134
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    if-nez v1, :cond_d

    .line 139
    .line 140
    return v2

    .line 141
    :cond_d
    iget-object v1, p0, Lm70/k0;->m:Ljava/lang/String;

    .line 142
    .line 143
    iget-object v3, p1, Lm70/k0;->m:Ljava/lang/String;

    .line 144
    .line 145
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-nez v1, :cond_e

    .line 150
    .line 151
    return v2

    .line 152
    :cond_e
    iget-object v1, p0, Lm70/k0;->n:Ljava/lang/String;

    .line 153
    .line 154
    iget-object v3, p1, Lm70/k0;->n:Ljava/lang/String;

    .line 155
    .line 156
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-nez v1, :cond_f

    .line 161
    .line 162
    return v2

    .line 163
    :cond_f
    iget-object v1, p0, Lm70/k0;->o:Ljava/lang/String;

    .line 164
    .line 165
    iget-object v3, p1, Lm70/k0;->o:Ljava/lang/String;

    .line 166
    .line 167
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-nez v1, :cond_10

    .line 172
    .line 173
    return v2

    .line 174
    :cond_10
    iget-object v1, p0, Lm70/k0;->p:Ljava/lang/String;

    .line 175
    .line 176
    iget-object v3, p1, Lm70/k0;->p:Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    if-nez v1, :cond_11

    .line 183
    .line 184
    return v2

    .line 185
    :cond_11
    iget-object v1, p0, Lm70/k0;->q:Ljava/lang/String;

    .line 186
    .line 187
    iget-object v3, p1, Lm70/k0;->q:Ljava/lang/String;

    .line 188
    .line 189
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-nez v1, :cond_12

    .line 194
    .line 195
    return v2

    .line 196
    :cond_12
    iget-object p0, p0, Lm70/k0;->r:Ljava/lang/String;

    .line 197
    .line 198
    iget-object p1, p1, Lm70/k0;->r:Ljava/lang/String;

    .line 199
    .line 200
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result p0

    .line 204
    if-nez p0, :cond_13

    .line 205
    .line 206
    return v2

    .line 207
    :cond_13
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lm70/k0;->a:Z

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
    iget-object v2, p0, Lm70/k0;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lm70/k0;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lm70/k0;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v2, 0x0

    .line 29
    iget-object v3, p0, Lm70/k0;->e:Ljava/lang/String;

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
    iget-object v3, p0, Lm70/k0;->f:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-object v3, p0, Lm70/k0;->g:Ljava/lang/String;

    .line 48
    .line 49
    if-nez v3, :cond_1

    .line 50
    .line 51
    move v3, v2

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    :goto_1
    add-int/2addr v0, v3

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-object v3, p0, Lm70/k0;->h:Ljava/lang/String;

    .line 60
    .line 61
    if-nez v3, :cond_2

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_2

    .line 65
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_2
    add-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v3, p0, Lm70/k0;->i:Ljava/lang/String;

    .line 72
    .line 73
    if-nez v3, :cond_3

    .line 74
    .line 75
    move v3, v2

    .line 76
    goto :goto_3

    .line 77
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    :goto_3
    add-int/2addr v0, v3

    .line 82
    mul-int/2addr v0, v1

    .line 83
    iget-object v3, p0, Lm70/k0;->j:Ljava/lang/String;

    .line 84
    .line 85
    if-nez v3, :cond_4

    .line 86
    .line 87
    move v3, v2

    .line 88
    goto :goto_4

    .line 89
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    :goto_4
    add-int/2addr v0, v3

    .line 94
    mul-int/2addr v0, v1

    .line 95
    iget-object v3, p0, Lm70/k0;->k:Ljava/lang/String;

    .line 96
    .line 97
    if-nez v3, :cond_5

    .line 98
    .line 99
    move v3, v2

    .line 100
    goto :goto_5

    .line 101
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    :goto_5
    add-int/2addr v0, v3

    .line 106
    mul-int/2addr v0, v1

    .line 107
    iget-object v3, p0, Lm70/k0;->l:Ljava/lang/String;

    .line 108
    .line 109
    if-nez v3, :cond_6

    .line 110
    .line 111
    move v3, v2

    .line 112
    goto :goto_6

    .line 113
    :cond_6
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    :goto_6
    add-int/2addr v0, v3

    .line 118
    mul-int/2addr v0, v1

    .line 119
    iget-object v3, p0, Lm70/k0;->m:Ljava/lang/String;

    .line 120
    .line 121
    if-nez v3, :cond_7

    .line 122
    .line 123
    move v3, v2

    .line 124
    goto :goto_7

    .line 125
    :cond_7
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    :goto_7
    add-int/2addr v0, v3

    .line 130
    mul-int/2addr v0, v1

    .line 131
    iget-object v3, p0, Lm70/k0;->n:Ljava/lang/String;

    .line 132
    .line 133
    if-nez v3, :cond_8

    .line 134
    .line 135
    move v3, v2

    .line 136
    goto :goto_8

    .line 137
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 138
    .line 139
    .line 140
    move-result v3

    .line 141
    :goto_8
    add-int/2addr v0, v3

    .line 142
    mul-int/2addr v0, v1

    .line 143
    iget-object v3, p0, Lm70/k0;->o:Ljava/lang/String;

    .line 144
    .line 145
    if-nez v3, :cond_9

    .line 146
    .line 147
    move v3, v2

    .line 148
    goto :goto_9

    .line 149
    :cond_9
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    :goto_9
    add-int/2addr v0, v3

    .line 154
    mul-int/2addr v0, v1

    .line 155
    iget-object v3, p0, Lm70/k0;->p:Ljava/lang/String;

    .line 156
    .line 157
    if-nez v3, :cond_a

    .line 158
    .line 159
    move v3, v2

    .line 160
    goto :goto_a

    .line 161
    :cond_a
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    :goto_a
    add-int/2addr v0, v3

    .line 166
    mul-int/2addr v0, v1

    .line 167
    iget-object v3, p0, Lm70/k0;->q:Ljava/lang/String;

    .line 168
    .line 169
    if-nez v3, :cond_b

    .line 170
    .line 171
    move v3, v2

    .line 172
    goto :goto_b

    .line 173
    :cond_b
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    :goto_b
    add-int/2addr v0, v3

    .line 178
    mul-int/2addr v0, v1

    .line 179
    iget-object p0, p0, Lm70/k0;->r:Ljava/lang/String;

    .line 180
    .line 181
    if-nez p0, :cond_c

    .line 182
    .line 183
    goto :goto_c

    .line 184
    :cond_c
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    :goto_c
    add-int/2addr v0, v2

    .line 189
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", date="

    .line 2
    .line 3
    const-string v1, ", endTime="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-object v3, p0, Lm70/k0;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lm70/k0;->a:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v3, v1, v4}, La7/g0;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", duration="

    .line 16
    .line 17
    const-string v2, ", totalPrice="

    .line 18
    .line 19
    iget-object v3, p0, Lm70/k0;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lm70/k0;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", distance="

    .line 27
    .line 28
    const-string v2, ", averageSpeed="

    .line 29
    .line 30
    iget-object v3, p0, Lm70/k0;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Lm70/k0;->f:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", averageFuel="

    .line 38
    .line 39
    const-string v2, ", averageCng="

    .line 40
    .line 41
    iget-object v3, p0, Lm70/k0;->g:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v4, p0, Lm70/k0;->h:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v1, ", averageBattery="

    .line 49
    .line 50
    const-string v2, ", odometerStart="

    .line 51
    .line 52
    iget-object v3, p0, Lm70/k0;->i:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v4, p0, Lm70/k0;->j:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v1, ", odometerEnd="

    .line 60
    .line 61
    const-string v2, ", priceFuel="

    .line 62
    .line 63
    iget-object v3, p0, Lm70/k0;->k:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v4, p0, Lm70/k0;->l:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v1, ", priceFuelPerUnit="

    .line 71
    .line 72
    const-string v2, ", priceElectric="

    .line 73
    .line 74
    iget-object v3, p0, Lm70/k0;->m:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v4, p0, Lm70/k0;->n:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string v1, ", priceElectricPerUnit="

    .line 82
    .line 83
    const-string v2, ", priceCng="

    .line 84
    .line 85
    iget-object v3, p0, Lm70/k0;->o:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v4, p0, Lm70/k0;->p:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v1, ", priceCngPerUnit="

    .line 93
    .line 94
    const-string v2, ")"

    .line 95
    .line 96
    iget-object v3, p0, Lm70/k0;->q:Ljava/lang/String;

    .line 97
    .line 98
    iget-object p0, p0, Lm70/k0;->r:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method
