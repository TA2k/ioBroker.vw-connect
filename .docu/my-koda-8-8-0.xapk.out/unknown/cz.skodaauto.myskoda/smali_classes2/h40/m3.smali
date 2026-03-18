.class public final Lh40/m3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/util/List;

.field public final f:Z

.field public final g:Z

.field public final h:Lg40/g0;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/Integer;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Lg40/e0;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZLg40/g0;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Lg40/e0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "name"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "description"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "organizer"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "consentUrl"

    .line 22
    .line 23
    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lh40/m3;->a:Ljava/lang/String;

    .line 30
    .line 31
    iput-object p2, p0, Lh40/m3;->b:Ljava/lang/String;

    .line 32
    .line 33
    iput-object p3, p0, Lh40/m3;->c:Ljava/lang/String;

    .line 34
    .line 35
    iput-object p4, p0, Lh40/m3;->d:Ljava/lang/String;

    .line 36
    .line 37
    iput-object p5, p0, Lh40/m3;->e:Ljava/util/List;

    .line 38
    .line 39
    iput-boolean p6, p0, Lh40/m3;->f:Z

    .line 40
    .line 41
    iput-boolean p7, p0, Lh40/m3;->g:Z

    .line 42
    .line 43
    iput-object p8, p0, Lh40/m3;->h:Lg40/g0;

    .line 44
    .line 45
    iput-object p9, p0, Lh40/m3;->i:Ljava/lang/String;

    .line 46
    .line 47
    iput-object p10, p0, Lh40/m3;->j:Ljava/lang/Integer;

    .line 48
    .line 49
    iput-object p11, p0, Lh40/m3;->k:Ljava/lang/String;

    .line 50
    .line 51
    iput-object p12, p0, Lh40/m3;->l:Ljava/lang/String;

    .line 52
    .line 53
    iput-object p13, p0, Lh40/m3;->m:Lg40/e0;

    .line 54
    .line 55
    iput-object p14, p0, Lh40/m3;->n:Ljava/lang/String;

    .line 56
    .line 57
    move-object/from16 p1, p15

    .line 58
    .line 59
    iput-object p1, p0, Lh40/m3;->o:Ljava/lang/String;

    .line 60
    .line 61
    move-object/from16 p1, p16

    .line 62
    .line 63
    iput-object p1, p0, Lh40/m3;->p:Ljava/lang/String;

    .line 64
    .line 65
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
    instance-of v1, p1, Lh40/m3;

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
    check-cast p1, Lh40/m3;

    .line 12
    .line 13
    iget-object v1, p0, Lh40/m3;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lh40/m3;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m3;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lh40/m3;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m3;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lh40/m3;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m3;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lh40/m3;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lh40/m3;->e:Ljava/util/List;

    .line 58
    .line 59
    iget-object v3, p1, Lh40/m3;->e:Ljava/util/List;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-boolean v1, p0, Lh40/m3;->f:Z

    .line 69
    .line 70
    iget-boolean v3, p1, Lh40/m3;->f:Z

    .line 71
    .line 72
    if-eq v1, v3, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-boolean v1, p0, Lh40/m3;->g:Z

    .line 76
    .line 77
    iget-boolean v3, p1, Lh40/m3;->g:Z

    .line 78
    .line 79
    if-eq v1, v3, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Lh40/m3;->h:Lg40/g0;

    .line 83
    .line 84
    iget-object v3, p1, Lh40/m3;->h:Lg40/g0;

    .line 85
    .line 86
    if-eq v1, v3, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-object v1, p0, Lh40/m3;->i:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v3, p1, Lh40/m3;->i:Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-nez v1, :cond_a

    .line 98
    .line 99
    return v2

    .line 100
    :cond_a
    iget-object v1, p0, Lh40/m3;->j:Ljava/lang/Integer;

    .line 101
    .line 102
    iget-object v3, p1, Lh40/m3;->j:Ljava/lang/Integer;

    .line 103
    .line 104
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    if-nez v1, :cond_b

    .line 109
    .line 110
    return v2

    .line 111
    :cond_b
    iget-object v1, p0, Lh40/m3;->k:Ljava/lang/String;

    .line 112
    .line 113
    iget-object v3, p1, Lh40/m3;->k:Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    if-nez v1, :cond_c

    .line 120
    .line 121
    return v2

    .line 122
    :cond_c
    iget-object v1, p0, Lh40/m3;->l:Ljava/lang/String;

    .line 123
    .line 124
    iget-object v3, p1, Lh40/m3;->l:Ljava/lang/String;

    .line 125
    .line 126
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-nez v1, :cond_d

    .line 131
    .line 132
    return v2

    .line 133
    :cond_d
    iget-object v1, p0, Lh40/m3;->m:Lg40/e0;

    .line 134
    .line 135
    iget-object v3, p1, Lh40/m3;->m:Lg40/e0;

    .line 136
    .line 137
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-nez v1, :cond_e

    .line 142
    .line 143
    return v2

    .line 144
    :cond_e
    iget-object v1, p0, Lh40/m3;->n:Ljava/lang/String;

    .line 145
    .line 146
    iget-object v3, p1, Lh40/m3;->n:Ljava/lang/String;

    .line 147
    .line 148
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-nez v1, :cond_f

    .line 153
    .line 154
    return v2

    .line 155
    :cond_f
    iget-object v1, p0, Lh40/m3;->o:Ljava/lang/String;

    .line 156
    .line 157
    iget-object v3, p1, Lh40/m3;->o:Ljava/lang/String;

    .line 158
    .line 159
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    if-nez v1, :cond_10

    .line 164
    .line 165
    return v2

    .line 166
    :cond_10
    iget-object p0, p0, Lh40/m3;->p:Ljava/lang/String;

    .line 167
    .line 168
    iget-object p1, p1, Lh40/m3;->p:Ljava/lang/String;

    .line 169
    .line 170
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    if-nez p0, :cond_11

    .line 175
    .line 176
    return v2

    .line 177
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lh40/m3;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lh40/m3;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lh40/m3;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lh40/m3;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lh40/m3;->e:Ljava/util/List;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lh40/m3;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lh40/m3;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lh40/m3;->h:Lg40/g0;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    add-int/2addr v2, v0

    .line 53
    mul-int/2addr v2, v1

    .line 54
    iget-object v0, p0, Lh40/m3;->i:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    const/4 v2, 0x0

    .line 61
    iget-object v3, p0, Lh40/m3;->j:Ljava/lang/Integer;

    .line 62
    .line 63
    if-nez v3, :cond_0

    .line 64
    .line 65
    move v3, v2

    .line 66
    goto :goto_0

    .line 67
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_0
    add-int/2addr v0, v3

    .line 72
    mul-int/2addr v0, v1

    .line 73
    iget-object v3, p0, Lh40/m3;->k:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v3, :cond_1

    .line 76
    .line 77
    move v3, v2

    .line 78
    goto :goto_1

    .line 79
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    :goto_1
    add-int/2addr v0, v3

    .line 84
    mul-int/2addr v0, v1

    .line 85
    iget-object v3, p0, Lh40/m3;->l:Ljava/lang/String;

    .line 86
    .line 87
    if-nez v3, :cond_2

    .line 88
    .line 89
    move v3, v2

    .line 90
    goto :goto_2

    .line 91
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_2
    add-int/2addr v0, v3

    .line 96
    mul-int/2addr v0, v1

    .line 97
    iget-object v3, p0, Lh40/m3;->m:Lg40/e0;

    .line 98
    .line 99
    invoke-virtual {v3}, Lg40/e0;->hashCode()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    add-int/2addr v3, v0

    .line 104
    mul-int/2addr v3, v1

    .line 105
    iget-object v0, p0, Lh40/m3;->n:Ljava/lang/String;

    .line 106
    .line 107
    if-nez v0, :cond_3

    .line 108
    .line 109
    move v0, v2

    .line 110
    goto :goto_3

    .line 111
    :cond_3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    :goto_3
    add-int/2addr v3, v0

    .line 116
    mul-int/2addr v3, v1

    .line 117
    iget-object v0, p0, Lh40/m3;->o:Ljava/lang/String;

    .line 118
    .line 119
    if-nez v0, :cond_4

    .line 120
    .line 121
    move v0, v2

    .line 122
    goto :goto_4

    .line 123
    :cond_4
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    :goto_4
    add-int/2addr v3, v0

    .line 128
    mul-int/2addr v3, v1

    .line 129
    iget-object p0, p0, Lh40/m3;->p:Ljava/lang/String;

    .line 130
    .line 131
    if-nez p0, :cond_5

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_5
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    :goto_5
    add-int/2addr v3, v2

    .line 139
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", name="

    .line 2
    .line 3
    const-string v1, ", description="

    .line 4
    .line 5
    const-string v2, "LuckyDrawState(id="

    .line 6
    .line 7
    iget-object v3, p0, Lh40/m3;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lh40/m3;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", organizer="

    .line 16
    .line 17
    const-string v2, ", imageUrls="

    .line 18
    .line 19
    iget-object v3, p0, Lh40/m3;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lh40/m3;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isEnrolled="

    .line 27
    .line 28
    const-string v2, ", isUnlocked="

    .line 29
    .line 30
    iget-object v3, p0, Lh40/m3;->e:Ljava/util/List;

    .line 31
    .line 32
    iget-boolean v4, p0, Lh40/m3;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-boolean v1, p0, Lh40/m3;->g:Z

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", status="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Lh40/m3;->h:Lg40/g0;

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v1, ", consentUrl="

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lh40/m3;->i:Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", statusIconResId="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Lh40/m3;->j:Ljava/lang/Integer;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", statusText="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ", detailStatusText="

    .line 78
    .line 79
    const-string v2, ", reward="

    .line 80
    .line 81
    iget-object v3, p0, Lh40/m3;->k:Ljava/lang/String;

    .line 82
    .line 83
    iget-object v4, p0, Lh40/m3;->l:Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lh40/m3;->m:Lg40/e0;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", winnerAnnouncementDateText="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lh40/m3;->n:Ljava/lang/String;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", unlockCriteria="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v1, ", consentText="

    .line 109
    .line 110
    const-string v2, ")"

    .line 111
    .line 112
    iget-object v3, p0, Lh40/m3;->o:Ljava/lang/String;

    .line 113
    .line 114
    iget-object p0, p0, Lh40/m3;->p:Ljava/lang/String;

    .line 115
    .line 116
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0
.end method
