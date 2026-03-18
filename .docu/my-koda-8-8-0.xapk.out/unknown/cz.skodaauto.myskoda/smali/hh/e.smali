.class public final Lhh/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:Lgh/a;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:Z

.field public final n:Z

.field public final o:Z

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:Ljava/util/ArrayList;

.field public final v:Lzg/i2;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ZLgh/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZZZZLjava/util/ArrayList;Lzg/i2;)V
    .locals 1

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lhh/e;->a:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lhh/e;->b:Ljava/lang/String;

    .line 4
    iput-boolean p3, p0, Lhh/e;->c:Z

    .line 5
    iput-object p4, p0, Lhh/e;->d:Lgh/a;

    .line 6
    iput-object p5, p0, Lhh/e;->e:Ljava/lang/String;

    .line 7
    iput-object p6, p0, Lhh/e;->f:Ljava/lang/String;

    .line 8
    iput-object p7, p0, Lhh/e;->g:Ljava/lang/String;

    .line 9
    iput-object p8, p0, Lhh/e;->h:Ljava/lang/String;

    .line 10
    iput-object p9, p0, Lhh/e;->i:Ljava/lang/String;

    .line 11
    iput-boolean p10, p0, Lhh/e;->j:Z

    .line 12
    iput-boolean p11, p0, Lhh/e;->k:Z

    .line 13
    iput-boolean p12, p0, Lhh/e;->l:Z

    .line 14
    iput-boolean p13, p0, Lhh/e;->m:Z

    .line 15
    iput-boolean p14, p0, Lhh/e;->n:Z

    move/from16 p1, p15

    .line 16
    iput-boolean p1, p0, Lhh/e;->o:Z

    move/from16 p1, p16

    .line 17
    iput-boolean p1, p0, Lhh/e;->p:Z

    move/from16 p1, p17

    .line 18
    iput-boolean p1, p0, Lhh/e;->q:Z

    move/from16 p1, p18

    .line 19
    iput-boolean p1, p0, Lhh/e;->r:Z

    move/from16 p1, p19

    .line 20
    iput-boolean p1, p0, Lhh/e;->s:Z

    move/from16 p1, p20

    .line 21
    iput-boolean p1, p0, Lhh/e;->t:Z

    move-object/from16 p1, p21

    .line 22
    iput-object p1, p0, Lhh/e;->u:Ljava/util/ArrayList;

    move-object/from16 p1, p22

    .line 23
    iput-object p1, p0, Lhh/e;->v:Lzg/i2;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lhh/e;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lhh/e;

    .line 12
    .line 13
    iget-object v0, p0, Lhh/e;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Lhh/e;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Lhh/e;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v1, p1, Lhh/e;->b:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_3
    iget-boolean v0, p0, Lhh/e;->c:Z

    .line 38
    .line 39
    iget-boolean v1, p1, Lhh/e;->c:Z

    .line 40
    .line 41
    if-eq v0, v1, :cond_4

    .line 42
    .line 43
    goto/16 :goto_0

    .line 44
    .line 45
    :cond_4
    iget-object v0, p0, Lhh/e;->d:Lgh/a;

    .line 46
    .line 47
    iget-object v1, p1, Lhh/e;->d:Lgh/a;

    .line 48
    .line 49
    if-eq v0, v1, :cond_5

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :cond_5
    iget-object v0, p0, Lhh/e;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v1, p1, Lhh/e;->e:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-nez v0, :cond_6

    .line 62
    .line 63
    goto/16 :goto_0

    .line 64
    .line 65
    :cond_6
    iget-object v0, p0, Lhh/e;->f:Ljava/lang/String;

    .line 66
    .line 67
    iget-object v1, p1, Lhh/e;->f:Ljava/lang/String;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_7

    .line 74
    .line 75
    goto/16 :goto_0

    .line 76
    .line 77
    :cond_7
    iget-object v0, p0, Lhh/e;->g:Ljava/lang/String;

    .line 78
    .line 79
    iget-object v1, p1, Lhh/e;->g:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-nez v0, :cond_8

    .line 86
    .line 87
    goto/16 :goto_0

    .line 88
    .line 89
    :cond_8
    iget-object v0, p0, Lhh/e;->h:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v1, p1, Lhh/e;->h:Ljava/lang/String;

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-nez v0, :cond_9

    .line 98
    .line 99
    goto/16 :goto_0

    .line 100
    .line 101
    :cond_9
    iget-object v0, p0, Lhh/e;->i:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v1, p1, Lhh/e;->i:Ljava/lang/String;

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-nez v0, :cond_a

    .line 110
    .line 111
    goto/16 :goto_0

    .line 112
    .line 113
    :cond_a
    iget-boolean v0, p0, Lhh/e;->j:Z

    .line 114
    .line 115
    iget-boolean v1, p1, Lhh/e;->j:Z

    .line 116
    .line 117
    if-eq v0, v1, :cond_b

    .line 118
    .line 119
    goto/16 :goto_0

    .line 120
    .line 121
    :cond_b
    iget-boolean v0, p0, Lhh/e;->k:Z

    .line 122
    .line 123
    iget-boolean v1, p1, Lhh/e;->k:Z

    .line 124
    .line 125
    if-eq v0, v1, :cond_c

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_c
    iget-boolean v0, p0, Lhh/e;->l:Z

    .line 129
    .line 130
    iget-boolean v1, p1, Lhh/e;->l:Z

    .line 131
    .line 132
    if-eq v0, v1, :cond_d

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_d
    iget-boolean v0, p0, Lhh/e;->m:Z

    .line 136
    .line 137
    iget-boolean v1, p1, Lhh/e;->m:Z

    .line 138
    .line 139
    if-eq v0, v1, :cond_e

    .line 140
    .line 141
    goto :goto_0

    .line 142
    :cond_e
    iget-boolean v0, p0, Lhh/e;->n:Z

    .line 143
    .line 144
    iget-boolean v1, p1, Lhh/e;->n:Z

    .line 145
    .line 146
    if-eq v0, v1, :cond_f

    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_f
    iget-boolean v0, p0, Lhh/e;->o:Z

    .line 150
    .line 151
    iget-boolean v1, p1, Lhh/e;->o:Z

    .line 152
    .line 153
    if-eq v0, v1, :cond_10

    .line 154
    .line 155
    goto :goto_0

    .line 156
    :cond_10
    iget-boolean v0, p0, Lhh/e;->p:Z

    .line 157
    .line 158
    iget-boolean v1, p1, Lhh/e;->p:Z

    .line 159
    .line 160
    if-eq v0, v1, :cond_11

    .line 161
    .line 162
    goto :goto_0

    .line 163
    :cond_11
    iget-boolean v0, p0, Lhh/e;->q:Z

    .line 164
    .line 165
    iget-boolean v1, p1, Lhh/e;->q:Z

    .line 166
    .line 167
    if-eq v0, v1, :cond_12

    .line 168
    .line 169
    goto :goto_0

    .line 170
    :cond_12
    iget-boolean v0, p0, Lhh/e;->r:Z

    .line 171
    .line 172
    iget-boolean v1, p1, Lhh/e;->r:Z

    .line 173
    .line 174
    if-eq v0, v1, :cond_13

    .line 175
    .line 176
    goto :goto_0

    .line 177
    :cond_13
    iget-boolean v0, p0, Lhh/e;->s:Z

    .line 178
    .line 179
    iget-boolean v1, p1, Lhh/e;->s:Z

    .line 180
    .line 181
    if-eq v0, v1, :cond_14

    .line 182
    .line 183
    goto :goto_0

    .line 184
    :cond_14
    iget-boolean v0, p0, Lhh/e;->t:Z

    .line 185
    .line 186
    iget-boolean v1, p1, Lhh/e;->t:Z

    .line 187
    .line 188
    if-eq v0, v1, :cond_15

    .line 189
    .line 190
    goto :goto_0

    .line 191
    :cond_15
    iget-object v0, p0, Lhh/e;->u:Ljava/util/ArrayList;

    .line 192
    .line 193
    iget-object v1, p1, Lhh/e;->u:Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    if-nez v0, :cond_16

    .line 200
    .line 201
    goto :goto_0

    .line 202
    :cond_16
    iget-object p0, p0, Lhh/e;->v:Lzg/i2;

    .line 203
    .line 204
    iget-object p1, p1, Lhh/e;->v:Lzg/i2;

    .line 205
    .line 206
    invoke-virtual {p0, p1}, Lzg/i2;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    if-nez p0, :cond_17

    .line 211
    .line 212
    :goto_0
    const/4 p0, 0x0

    .line 213
    return p0

    .line 214
    :cond_17
    :goto_1
    const/4 p0, 0x1

    .line 215
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lhh/e;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lhh/e;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lhh/e;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lhh/e;->d:Lgh/a;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-object v0, p0, Lhh/e;->e:Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lhh/e;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-object v2, p0, Lhh/e;->g:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-object v2, p0, Lhh/e;->h:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object v2, p0, Lhh/e;->i:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-boolean v2, p0, Lhh/e;->j:Z

    .line 61
    .line 62
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iget-boolean v2, p0, Lhh/e;->k:Z

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iget-boolean v2, p0, Lhh/e;->l:Z

    .line 73
    .line 74
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-boolean v2, p0, Lhh/e;->m:Z

    .line 79
    .line 80
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    iget-boolean v2, p0, Lhh/e;->n:Z

    .line 85
    .line 86
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    iget-boolean v2, p0, Lhh/e;->o:Z

    .line 91
    .line 92
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    iget-boolean v2, p0, Lhh/e;->p:Z

    .line 97
    .line 98
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    iget-boolean v2, p0, Lhh/e;->q:Z

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    iget-boolean v2, p0, Lhh/e;->r:Z

    .line 109
    .line 110
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    iget-boolean v2, p0, Lhh/e;->s:Z

    .line 115
    .line 116
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    iget-boolean v2, p0, Lhh/e;->t:Z

    .line 121
    .line 122
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    iget-object v2, p0, Lhh/e;->u:Ljava/util/ArrayList;

    .line 127
    .line 128
    invoke-static {v2, v0, v1}, Lkx/a;->b(Ljava/util/ArrayList;II)I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    iget-object p0, p0, Lhh/e;->v:Lzg/i2;

    .line 133
    .line 134
    invoke-virtual {p0}, Lzg/i2;->hashCode()I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    add-int/2addr p0, v0

    .line 139
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", name="

    .line 2
    .line 3
    const-string v1, ", isAuthorizeStopChargingSectionVisible="

    .line 4
    .line 5
    const-string v2, "WallBoxDetailUIState(id="

    .line 6
    .line 7
    iget-object v3, p0, Lhh/e;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lhh/e;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Lhh/e;->c:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", authorizeChargingButtonStatus="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lhh/e;->d:Lgh/a;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", sessionID="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", amountCharged="

    .line 36
    .line 37
    const-string v2, ", formattedStartDateTime="

    .line 38
    .line 39
    iget-object v3, p0, Lhh/e;->e:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v4, p0, Lhh/e;->f:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", chargingTime="

    .line 47
    .line 48
    const-string v2, ", formattedAuthentication="

    .line 49
    .line 50
    iget-object v3, p0, Lhh/e;->g:Ljava/lang/String;

    .line 51
    .line 52
    iget-object v4, p0, Lhh/e;->h:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v1, ", isChargingInProgress="

    .line 58
    .line 59
    const-string v2, ", isChargingPaused="

    .line 60
    .line 61
    iget-object v3, p0, Lhh/e;->i:Ljava/lang/String;

    .line 62
    .line 63
    iget-boolean v4, p0, Lhh/e;->j:Z

    .line 64
    .line 65
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 66
    .line 67
    .line 68
    const-string v1, ", isChargingNotPossible="

    .line 69
    .line 70
    const-string v2, ", isWaitingForAuthorization="

    .line 71
    .line 72
    iget-boolean v3, p0, Lhh/e;->k:Z

    .line 73
    .line 74
    iget-boolean v4, p0, Lhh/e;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-string v1, ", isStartDateTimeVisible="

    .line 80
    .line 81
    const-string v2, ", isSessionIdVisible="

    .line 82
    .line 83
    iget-boolean v3, p0, Lhh/e;->m:Z

    .line 84
    .line 85
    iget-boolean v4, p0, Lhh/e;->n:Z

    .line 86
    .line 87
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string v1, ", isEnergyAvailable="

    .line 91
    .line 92
    const-string v2, ", isDurationAvailable="

    .line 93
    .line 94
    iget-boolean v3, p0, Lhh/e;->o:Z

    .line 95
    .line 96
    iget-boolean v4, p0, Lhh/e;->p:Z

    .line 97
    .line 98
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string v1, ", isAuthenticationVisible="

    .line 102
    .line 103
    const-string v2, ", isChargingSessionLabelVisible="

    .line 104
    .line 105
    iget-boolean v3, p0, Lhh/e;->q:Z

    .line 106
    .line 107
    iget-boolean v4, p0, Lhh/e;->r:Z

    .line 108
    .line 109
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string v1, ", isPollingLoading="

    .line 113
    .line 114
    const-string v2, ", imageRequests="

    .line 115
    .line 116
    iget-boolean v3, p0, Lhh/e;->s:Z

    .line 117
    .line 118
    iget-boolean v4, p0, Lhh/e;->t:Z

    .line 119
    .line 120
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 121
    .line 122
    .line 123
    iget-object v1, p0, Lhh/e;->u:Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", wallBoxStatus="

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    iget-object p0, p0, Lhh/e;->v:Lzg/i2;

    .line 134
    .line 135
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string p0, ")"

    .line 139
    .line 140
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0
.end method
