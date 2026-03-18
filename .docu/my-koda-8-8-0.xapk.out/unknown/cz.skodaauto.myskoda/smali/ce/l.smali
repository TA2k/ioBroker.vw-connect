.class public final Lce/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Z

.field public final c:Ljava/util/List;

.field public final d:Z

.field public final e:Lce/w;

.field public final f:Z

.field public final g:Ljava/lang/String;

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Lce/x;

.field public final m:Lce/z;

.field public final n:Z

.field public final o:Z


# direct methods
.method public constructor <init>(Ljava/util/List;ZLjava/util/List;ZLce/w;ZLjava/lang/String;ZZZZLce/x;Lce/z;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lce/l;->a:Ljava/util/List;

    .line 5
    .line 6
    iput-boolean p2, p0, Lce/l;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lce/l;->c:Ljava/util/List;

    .line 9
    .line 10
    iput-boolean p4, p0, Lce/l;->d:Z

    .line 11
    .line 12
    iput-object p5, p0, Lce/l;->e:Lce/w;

    .line 13
    .line 14
    iput-boolean p6, p0, Lce/l;->f:Z

    .line 15
    .line 16
    iput-object p7, p0, Lce/l;->g:Ljava/lang/String;

    .line 17
    .line 18
    iput-boolean p8, p0, Lce/l;->h:Z

    .line 19
    .line 20
    iput-boolean p9, p0, Lce/l;->i:Z

    .line 21
    .line 22
    iput-boolean p10, p0, Lce/l;->j:Z

    .line 23
    .line 24
    iput-boolean p11, p0, Lce/l;->k:Z

    .line 25
    .line 26
    iput-object p12, p0, Lce/l;->l:Lce/x;

    .line 27
    .line 28
    iput-object p13, p0, Lce/l;->m:Lce/z;

    .line 29
    .line 30
    iput-boolean p14, p0, Lce/l;->n:Z

    .line 31
    .line 32
    iput-boolean p15, p0, Lce/l;->o:Z

    .line 33
    .line 34
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
    instance-of v1, p1, Lce/l;

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
    check-cast p1, Lce/l;

    .line 12
    .line 13
    iget-object v1, p0, Lce/l;->a:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lce/l;->a:Ljava/util/List;

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
    iget-boolean v1, p0, Lce/l;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lce/l;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lce/l;->c:Ljava/util/List;

    .line 32
    .line 33
    iget-object v3, p1, Lce/l;->c:Ljava/util/List;

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
    iget-boolean v1, p0, Lce/l;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Lce/l;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Lce/l;->e:Lce/w;

    .line 50
    .line 51
    iget-object v3, p1, Lce/l;->e:Lce/w;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-boolean v1, p0, Lce/l;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Lce/l;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-object v1, p0, Lce/l;->g:Ljava/lang/String;

    .line 68
    .line 69
    iget-object v3, p1, Lce/l;->g:Ljava/lang/String;

    .line 70
    .line 71
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-boolean v1, p0, Lce/l;->h:Z

    .line 79
    .line 80
    iget-boolean v3, p1, Lce/l;->h:Z

    .line 81
    .line 82
    if-eq v1, v3, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-boolean v1, p0, Lce/l;->i:Z

    .line 86
    .line 87
    iget-boolean v3, p1, Lce/l;->i:Z

    .line 88
    .line 89
    if-eq v1, v3, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-boolean v1, p0, Lce/l;->j:Z

    .line 93
    .line 94
    iget-boolean v3, p1, Lce/l;->j:Z

    .line 95
    .line 96
    if-eq v1, v3, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-boolean v1, p0, Lce/l;->k:Z

    .line 100
    .line 101
    iget-boolean v3, p1, Lce/l;->k:Z

    .line 102
    .line 103
    if-eq v1, v3, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    iget-object v1, p0, Lce/l;->l:Lce/x;

    .line 107
    .line 108
    iget-object v3, p1, Lce/l;->l:Lce/x;

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
    iget-object v1, p0, Lce/l;->m:Lce/z;

    .line 118
    .line 119
    iget-object v3, p1, Lce/l;->m:Lce/z;

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
    iget-boolean v1, p0, Lce/l;->n:Z

    .line 129
    .line 130
    iget-boolean v3, p1, Lce/l;->n:Z

    .line 131
    .line 132
    if-eq v1, v3, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-boolean p0, p0, Lce/l;->o:Z

    .line 136
    .line 137
    iget-boolean p1, p1, Lce/l;->o:Z

    .line 138
    .line 139
    if-eq p0, p1, :cond_10

    .line 140
    .line 141
    return v2

    .line 142
    :cond_10
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lce/l;->a:Ljava/util/List;

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
    iget-boolean v2, p0, Lce/l;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lce/l;->c:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lce/l;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lce/l;->e:Lce/w;

    .line 29
    .line 30
    invoke-virtual {v2}, Lce/w;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-boolean v0, p0, Lce/l;->f:Z

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-object v2, p0, Lce/l;->g:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-boolean v2, p0, Lce/l;->h:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-boolean v2, p0, Lce/l;->i:Z

    .line 55
    .line 56
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-boolean v2, p0, Lce/l;->j:Z

    .line 61
    .line 62
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iget-boolean v2, p0, Lce/l;->k:Z

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iget-object v2, p0, Lce/l;->l:Lce/x;

    .line 73
    .line 74
    invoke-virtual {v2}, Lce/x;->hashCode()I

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    add-int/2addr v2, v0

    .line 79
    mul-int/2addr v2, v1

    .line 80
    iget-object v0, p0, Lce/l;->m:Lce/z;

    .line 81
    .line 82
    invoke-virtual {v0}, Lce/z;->hashCode()I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    add-int/2addr v0, v2

    .line 87
    mul-int/2addr v0, v1

    .line 88
    iget-boolean v2, p0, Lce/l;->n:Z

    .line 89
    .line 90
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    iget-boolean p0, p0, Lce/l;->o:Z

    .line 95
    .line 96
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    add-int/2addr p0, v0

    .line 101
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Details(connectorGroups="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lce/l;->a:Ljava/util/List;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", showAuthenticationOptions="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lce/l;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", authenticationOptions="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", showAddress="

    .line 29
    .line 30
    const-string v2, ", address="

    .line 31
    .line 32
    iget-object v3, p0, Lce/l;->c:Ljava/util/List;

    .line 33
    .line 34
    iget-boolean v4, p0, Lce/l;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lce/l;->e:Lce/w;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", showAccessPin="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-boolean v1, p0, Lce/l;->f:Z

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", accessPin="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", showHowChargingWorksModal="

    .line 60
    .line 61
    const-string v2, ", showLoyaltyProgramInformationModal="

    .line 62
    .line 63
    iget-object v3, p0, Lce/l;->g:Ljava/lang/String;

    .line 64
    .line 65
    iget-boolean v4, p0, Lce/l;->h:Z

    .line 66
    .line 67
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 68
    .line 69
    .line 70
    const-string v1, ", showOpeningHours="

    .line 71
    .line 72
    const-string v2, ", showLoyaltyProgram="

    .line 73
    .line 74
    iget-boolean v3, p0, Lce/l;->i:Z

    .line 75
    .line 76
    iget-boolean v4, p0, Lce/l;->j:Z

    .line 77
    .line 78
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    iget-boolean v1, p0, Lce/l;->k:Z

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v1, ", loyaltyProgram="

    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    iget-object v1, p0, Lce/l;->l:Lce/x;

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v1, ", openingHours="

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    iget-object v1, p0, Lce/l;->m:Lce/z;

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string v1, ", showElli="

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    iget-boolean v1, p0, Lce/l;->n:Z

    .line 112
    .line 113
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    const-string v1, ", showSeePlansCta="

    .line 117
    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    const-string v1, ")"

    .line 122
    .line 123
    iget-boolean p0, p0, Lce/l;->o:Z

    .line 124
    .line 125
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0
.end method
