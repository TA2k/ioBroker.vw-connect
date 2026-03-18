.class public final Lce/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lkc/e;

.field public final f:Ljava/lang/String;

.field public final g:Z

.field public final h:Ljava/lang/String;

.field public final i:Lce/n;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Lce/n;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/lang/String;

.field public final p:Z

.field public final q:Z


# direct methods
.method public constructor <init>(ZZZZLkc/e;Ljava/lang/String;ZLjava/lang/String;Lce/n;Ljava/lang/String;Ljava/lang/String;Lce/n;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V
    .locals 2

    .line 1
    move-object v0, p13

    .line 2
    const-string v1, "displayName"

    .line 3
    .line 4
    invoke-static {p6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    const-string v1, "openingLabel"

    .line 8
    .line 9
    invoke-static {p8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "openingAdditionalInfo"

    .line 13
    .line 14
    invoke-static {p10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v1, "availability"

    .line 18
    .line 19
    invoke-static {p11, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v1, "maxPower"

    .line 23
    .line 24
    invoke-static {p13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-boolean p1, p0, Lce/m;->a:Z

    .line 31
    .line 32
    iput-boolean p2, p0, Lce/m;->b:Z

    .line 33
    .line 34
    iput-boolean p3, p0, Lce/m;->c:Z

    .line 35
    .line 36
    iput-boolean p4, p0, Lce/m;->d:Z

    .line 37
    .line 38
    iput-object p5, p0, Lce/m;->e:Lkc/e;

    .line 39
    .line 40
    iput-object p6, p0, Lce/m;->f:Ljava/lang/String;

    .line 41
    .line 42
    iput-boolean p7, p0, Lce/m;->g:Z

    .line 43
    .line 44
    iput-object p8, p0, Lce/m;->h:Ljava/lang/String;

    .line 45
    .line 46
    iput-object p9, p0, Lce/m;->i:Lce/n;

    .line 47
    .line 48
    iput-object p10, p0, Lce/m;->j:Ljava/lang/String;

    .line 49
    .line 50
    iput-object p11, p0, Lce/m;->k:Ljava/lang/String;

    .line 51
    .line 52
    iput-object p12, p0, Lce/m;->l:Lce/n;

    .line 53
    .line 54
    iput-object v0, p0, Lce/m;->m:Ljava/lang/String;

    .line 55
    .line 56
    move-object/from16 p1, p14

    .line 57
    .line 58
    iput-object p1, p0, Lce/m;->n:Ljava/lang/String;

    .line 59
    .line 60
    move-object/from16 p1, p15

    .line 61
    .line 62
    iput-object p1, p0, Lce/m;->o:Ljava/lang/String;

    .line 63
    .line 64
    move/from16 p1, p16

    .line 65
    .line 66
    iput-boolean p1, p0, Lce/m;->p:Z

    .line 67
    .line 68
    move/from16 p1, p17

    .line 69
    .line 70
    iput-boolean p1, p0, Lce/m;->q:Z

    .line 71
    .line 72
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
    instance-of v1, p1, Lce/m;

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
    check-cast p1, Lce/m;

    .line 12
    .line 13
    iget-boolean v1, p0, Lce/m;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lce/m;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lce/m;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lce/m;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lce/m;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lce/m;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lce/m;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lce/m;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lce/m;->e:Lkc/e;

    .line 42
    .line 43
    iget-object v3, p1, Lce/m;->e:Lkc/e;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object v1, p0, Lce/m;->f:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v3, p1, Lce/m;->f:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-boolean v1, p0, Lce/m;->g:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Lce/m;->g:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-object v1, p0, Lce/m;->h:Ljava/lang/String;

    .line 71
    .line 72
    iget-object v3, p1, Lce/m;->h:Ljava/lang/String;

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
    iget-object v1, p0, Lce/m;->i:Lce/n;

    .line 82
    .line 83
    iget-object v3, p1, Lce/m;->i:Lce/n;

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-object v1, p0, Lce/m;->j:Ljava/lang/String;

    .line 89
    .line 90
    iget-object v3, p1, Lce/m;->j:Ljava/lang/String;

    .line 91
    .line 92
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-nez v1, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-object v1, p0, Lce/m;->k:Ljava/lang/String;

    .line 100
    .line 101
    iget-object v3, p1, Lce/m;->k:Ljava/lang/String;

    .line 102
    .line 103
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    if-nez v1, :cond_c

    .line 108
    .line 109
    return v2

    .line 110
    :cond_c
    iget-object v1, p0, Lce/m;->l:Lce/n;

    .line 111
    .line 112
    iget-object v3, p1, Lce/m;->l:Lce/n;

    .line 113
    .line 114
    if-eq v1, v3, :cond_d

    .line 115
    .line 116
    return v2

    .line 117
    :cond_d
    iget-object v1, p0, Lce/m;->m:Ljava/lang/String;

    .line 118
    .line 119
    iget-object v3, p1, Lce/m;->m:Ljava/lang/String;

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
    iget-object v1, p0, Lce/m;->n:Ljava/lang/String;

    .line 129
    .line 130
    iget-object v3, p1, Lce/m;->n:Ljava/lang/String;

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
    iget-object v1, p0, Lce/m;->o:Ljava/lang/String;

    .line 140
    .line 141
    iget-object v3, p1, Lce/m;->o:Ljava/lang/String;

    .line 142
    .line 143
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v1

    .line 147
    if-nez v1, :cond_10

    .line 148
    .line 149
    return v2

    .line 150
    :cond_10
    iget-boolean v1, p0, Lce/m;->p:Z

    .line 151
    .line 152
    iget-boolean v3, p1, Lce/m;->p:Z

    .line 153
    .line 154
    if-eq v1, v3, :cond_11

    .line 155
    .line 156
    return v2

    .line 157
    :cond_11
    iget-boolean p0, p0, Lce/m;->q:Z

    .line 158
    .line 159
    iget-boolean p1, p1, Lce/m;->q:Z

    .line 160
    .line 161
    if-eq p0, p1, :cond_12

    .line 162
    .line 163
    return v2

    .line 164
    :cond_12
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lce/m;->a:Z

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
    iget-boolean v2, p0, Lce/m;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lce/m;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lce/m;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lce/m;->e:Lkc/e;

    .line 29
    .line 30
    invoke-virtual {v2}, Lkc/e;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-object v0, p0, Lce/m;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-boolean v2, p0, Lce/m;->g:Z

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-object v2, p0, Lce/m;->h:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object v2, p0, Lce/m;->i:Lce/n;

    .line 55
    .line 56
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    add-int/2addr v2, v0

    .line 61
    mul-int/2addr v2, v1

    .line 62
    iget-object v0, p0, Lce/m;->j:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-object v2, p0, Lce/m;->k:Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-object v2, p0, Lce/m;->l:Lce/n;

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    add-int/2addr v2, v0

    .line 81
    mul-int/2addr v2, v1

    .line 82
    iget-object v0, p0, Lce/m;->m:Ljava/lang/String;

    .line 83
    .line 84
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    iget-object v2, p0, Lce/m;->n:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    iget-object v2, p0, Lce/m;->o:Ljava/lang/String;

    .line 95
    .line 96
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    iget-boolean v2, p0, Lce/m;->p:Z

    .line 101
    .line 102
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    iget-boolean p0, p0, Lce/m;->q:Z

    .line 107
    .line 108
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    add-int/2addr p0, v0

    .line 113
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", showIonity="

    .line 2
    .line 3
    const-string v1, ", showSelectedPartner="

    .line 4
    .line 5
    const-string v2, "Header(showBadge="

    .line 6
    .line 7
    iget-boolean v3, p0, Lce/m;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lce/m;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", showLoyaltyProgram="

    .line 16
    .line 17
    const-string v2, ", loyaltyProgramIconRequest="

    .line 18
    .line 19
    iget-boolean v3, p0, Lce/m;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lce/m;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lce/m;->e:Lkc/e;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", displayName="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lce/m;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", showOpeningInformation="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ", openingLabel="

    .line 47
    .line 48
    const-string v2, ", openingStatus="

    .line 49
    .line 50
    iget-object v3, p0, Lce/m;->h:Ljava/lang/String;

    .line 51
    .line 52
    iget-boolean v4, p0, Lce/m;->g:Z

    .line 53
    .line 54
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lce/m;->i:Lce/n;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", openingAdditionalInfo="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Lce/m;->j:Ljava/lang/String;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", availability="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lce/m;->k:Ljava/lang/String;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", availabilityStatus="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-object v1, p0, Lce/m;->l:Lce/n;

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", maxPower="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", ratingAverage="

    .line 98
    .line 99
    const-string v2, ", ratingCount="

    .line 100
    .line 101
    iget-object v3, p0, Lce/m;->m:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v4, p0, Lce/m;->n:Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string v1, ", isRatingVisible="

    .line 109
    .line 110
    const-string v2, ", showSeePlansCta="

    .line 111
    .line 112
    iget-object v3, p0, Lce/m;->o:Ljava/lang/String;

    .line 113
    .line 114
    iget-boolean v4, p0, Lce/m;->p:Z

    .line 115
    .line 116
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 117
    .line 118
    .line 119
    const-string v1, ")"

    .line 120
    .line 121
    iget-boolean p0, p0, Lce/m;->q:Z

    .line 122
    .line 123
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0
.end method
