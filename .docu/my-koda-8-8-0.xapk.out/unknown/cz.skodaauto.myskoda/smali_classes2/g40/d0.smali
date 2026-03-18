.class public final Lg40/d0;
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

.field public final j:Lg40/h0;

.field public final k:Ljava/time/LocalDate;

.field public final l:Ljava/time/LocalDate;

.field public final m:Ljava/time/LocalDate;

.field public final n:Lg40/e0;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZLg40/g0;Ljava/lang/String;Lg40/h0;Ljava/time/LocalDate;Ljava/time/LocalDate;Ljava/time/LocalDate;Lg40/e0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    .line 1
    move-object v0, p11

    .line 2
    move-object/from16 v1, p12

    .line 3
    .line 4
    move-object/from16 v2, p13

    .line 5
    .line 6
    const-string v3, "id"

    .line 7
    .line 8
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v3, "name"

    .line 12
    .line 13
    invoke-static {p2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v3, "description"

    .line 17
    .line 18
    invoke-static {p3, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v3, "organizer"

    .line 22
    .line 23
    invoke-static {p4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v3, "imageUrls"

    .line 27
    .line 28
    invoke-static {p5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v3, "consentUrl"

    .line 32
    .line 33
    invoke-static {p9, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v3, "startDate"

    .line 37
    .line 38
    invoke-static {p11, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v3, "endDate"

    .line 42
    .line 43
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v3, "winnerAnnouncementDate"

    .line 47
    .line 48
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 52
    .line 53
    .line 54
    iput-object p1, p0, Lg40/d0;->a:Ljava/lang/String;

    .line 55
    .line 56
    iput-object p2, p0, Lg40/d0;->b:Ljava/lang/String;

    .line 57
    .line 58
    iput-object p3, p0, Lg40/d0;->c:Ljava/lang/String;

    .line 59
    .line 60
    iput-object p4, p0, Lg40/d0;->d:Ljava/lang/String;

    .line 61
    .line 62
    iput-object p5, p0, Lg40/d0;->e:Ljava/util/List;

    .line 63
    .line 64
    iput-boolean p6, p0, Lg40/d0;->f:Z

    .line 65
    .line 66
    iput-boolean p7, p0, Lg40/d0;->g:Z

    .line 67
    .line 68
    iput-object p8, p0, Lg40/d0;->h:Lg40/g0;

    .line 69
    .line 70
    iput-object p9, p0, Lg40/d0;->i:Ljava/lang/String;

    .line 71
    .line 72
    iput-object p10, p0, Lg40/d0;->j:Lg40/h0;

    .line 73
    .line 74
    iput-object v0, p0, Lg40/d0;->k:Ljava/time/LocalDate;

    .line 75
    .line 76
    iput-object v1, p0, Lg40/d0;->l:Ljava/time/LocalDate;

    .line 77
    .line 78
    iput-object v2, p0, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 79
    .line 80
    move-object/from16 p1, p14

    .line 81
    .line 82
    iput-object p1, p0, Lg40/d0;->n:Lg40/e0;

    .line 83
    .line 84
    move-object/from16 p1, p15

    .line 85
    .line 86
    iput-object p1, p0, Lg40/d0;->o:Ljava/lang/String;

    .line 87
    .line 88
    move-object/from16 p1, p16

    .line 89
    .line 90
    iput-object p1, p0, Lg40/d0;->p:Ljava/lang/String;

    .line 91
    .line 92
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
    instance-of v1, p1, Lg40/d0;

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
    check-cast p1, Lg40/d0;

    .line 12
    .line 13
    iget-object v1, p0, Lg40/d0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lg40/d0;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lg40/d0;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lg40/d0;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lg40/d0;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lg40/d0;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lg40/d0;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lg40/d0;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lg40/d0;->e:Ljava/util/List;

    .line 58
    .line 59
    iget-object v3, p1, Lg40/d0;->e:Ljava/util/List;

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
    iget-boolean v1, p0, Lg40/d0;->f:Z

    .line 69
    .line 70
    iget-boolean v3, p1, Lg40/d0;->f:Z

    .line 71
    .line 72
    if-eq v1, v3, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-boolean v1, p0, Lg40/d0;->g:Z

    .line 76
    .line 77
    iget-boolean v3, p1, Lg40/d0;->g:Z

    .line 78
    .line 79
    if-eq v1, v3, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Lg40/d0;->h:Lg40/g0;

    .line 83
    .line 84
    iget-object v3, p1, Lg40/d0;->h:Lg40/g0;

    .line 85
    .line 86
    if-eq v1, v3, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-object v1, p0, Lg40/d0;->i:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v3, p1, Lg40/d0;->i:Ljava/lang/String;

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
    iget-object v1, p0, Lg40/d0;->j:Lg40/h0;

    .line 101
    .line 102
    iget-object v3, p1, Lg40/d0;->j:Lg40/h0;

    .line 103
    .line 104
    if-eq v1, v3, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object v1, p0, Lg40/d0;->k:Ljava/time/LocalDate;

    .line 108
    .line 109
    iget-object v3, p1, Lg40/d0;->k:Ljava/time/LocalDate;

    .line 110
    .line 111
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-nez v1, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object v1, p0, Lg40/d0;->l:Ljava/time/LocalDate;

    .line 119
    .line 120
    iget-object v3, p1, Lg40/d0;->l:Ljava/time/LocalDate;

    .line 121
    .line 122
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-nez v1, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    iget-object v1, p0, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 130
    .line 131
    iget-object v3, p1, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 132
    .line 133
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-nez v1, :cond_e

    .line 138
    .line 139
    return v2

    .line 140
    :cond_e
    iget-object v1, p0, Lg40/d0;->n:Lg40/e0;

    .line 141
    .line 142
    iget-object v3, p1, Lg40/d0;->n:Lg40/e0;

    .line 143
    .line 144
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-nez v1, :cond_f

    .line 149
    .line 150
    return v2

    .line 151
    :cond_f
    iget-object v1, p0, Lg40/d0;->o:Ljava/lang/String;

    .line 152
    .line 153
    iget-object v3, p1, Lg40/d0;->o:Ljava/lang/String;

    .line 154
    .line 155
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    if-nez v1, :cond_10

    .line 160
    .line 161
    return v2

    .line 162
    :cond_10
    iget-object p0, p0, Lg40/d0;->p:Ljava/lang/String;

    .line 163
    .line 164
    iget-object p1, p1, Lg40/d0;->p:Ljava/lang/String;

    .line 165
    .line 166
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result p0

    .line 170
    if-nez p0, :cond_11

    .line 171
    .line 172
    return v2

    .line 173
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lg40/d0;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lg40/d0;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lg40/d0;->c:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lg40/d0;->d:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lg40/d0;->e:Ljava/util/List;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lg40/d0;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lg40/d0;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lg40/d0;->h:Lg40/g0;

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
    iget-object v0, p0, Lg40/d0;->i:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-object v2, p0, Lg40/d0;->j:Lg40/h0;

    .line 61
    .line 62
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    add-int/2addr v2, v0

    .line 67
    mul-int/2addr v2, v1

    .line 68
    iget-object v0, p0, Lg40/d0;->k:Ljava/time/LocalDate;

    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/time/LocalDate;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    add-int/2addr v0, v2

    .line 75
    mul-int/2addr v0, v1

    .line 76
    iget-object v2, p0, Lg40/d0;->l:Ljava/time/LocalDate;

    .line 77
    .line 78
    invoke-virtual {v2}, Ljava/time/LocalDate;->hashCode()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    add-int/2addr v2, v0

    .line 83
    mul-int/2addr v2, v1

    .line 84
    iget-object v0, p0, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/time/LocalDate;->hashCode()I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    add-int/2addr v0, v2

    .line 91
    mul-int/2addr v0, v1

    .line 92
    iget-object v2, p0, Lg40/d0;->n:Lg40/e0;

    .line 93
    .line 94
    invoke-virtual {v2}, Lg40/e0;->hashCode()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    add-int/2addr v2, v0

    .line 99
    mul-int/2addr v2, v1

    .line 100
    const/4 v0, 0x0

    .line 101
    iget-object v3, p0, Lg40/d0;->o:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v3, :cond_0

    .line 104
    .line 105
    move v3, v0

    .line 106
    goto :goto_0

    .line 107
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_0
    add-int/2addr v2, v3

    .line 112
    mul-int/2addr v2, v1

    .line 113
    iget-object p0, p0, Lg40/d0;->p:Ljava/lang/String;

    .line 114
    .line 115
    if-nez p0, :cond_1

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    :goto_1
    add-int/2addr v2, v0

    .line 123
    return v2
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
    const-string v2, "LoyaltyGame(id="

    .line 6
    .line 7
    iget-object v3, p0, Lg40/d0;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lg40/d0;->b:Ljava/lang/String;

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
    iget-object v3, p0, Lg40/d0;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lg40/d0;->d:Ljava/lang/String;

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
    iget-object v3, p0, Lg40/d0;->e:Ljava/util/List;

    .line 31
    .line 32
    iget-boolean v4, p0, Lg40/d0;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-boolean v1, p0, Lg40/d0;->g:Z

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
    iget-object v1, p0, Lg40/d0;->h:Lg40/g0;

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
    iget-object v1, p0, Lg40/d0;->i:Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
    iget-object v1, p0, Lg40/d0;->j:Lg40/h0;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", startDate="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lg40/d0;->k:Ljava/time/LocalDate;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", endDate="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-object v1, p0, Lg40/d0;->l:Ljava/time/LocalDate;

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", winnerAnnouncementDate="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    iget-object v1, p0, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v1, ", reward="

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    iget-object v1, p0, Lg40/d0;->n:Lg40/e0;

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", unlockCriteria="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v1, ", consentText="

    .line 118
    .line 119
    const-string v2, ")"

    .line 120
    .line 121
    iget-object v3, p0, Lg40/d0;->o:Ljava/lang/String;

    .line 122
    .line 123
    iget-object p0, p0, Lg40/d0;->p:Ljava/lang/String;

    .line 124
    .line 125
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0
.end method
