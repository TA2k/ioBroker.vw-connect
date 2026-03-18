.class public final Lai/b;
.super Ljp/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:Lgh/a;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:Ljava/lang/String;

.field public final n:Ljava/util/ArrayList;

.field public final o:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ZLgh/a;Ljava/lang/String;Ljava/lang/String;ZZZZZZLjava/lang/String;Ljava/util/ArrayList;Z)V
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
    const-string v0, "statusDescription"

    .line 12
    .line 13
    invoke-static {p13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lai/b;->a:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Lai/b;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-boolean p3, p0, Lai/b;->c:Z

    .line 24
    .line 25
    iput-object p4, p0, Lai/b;->d:Lgh/a;

    .line 26
    .line 27
    iput-object p5, p0, Lai/b;->e:Ljava/lang/String;

    .line 28
    .line 29
    iput-object p6, p0, Lai/b;->f:Ljava/lang/String;

    .line 30
    .line 31
    iput-boolean p7, p0, Lai/b;->g:Z

    .line 32
    .line 33
    iput-boolean p8, p0, Lai/b;->h:Z

    .line 34
    .line 35
    iput-boolean p9, p0, Lai/b;->i:Z

    .line 36
    .line 37
    iput-boolean p10, p0, Lai/b;->j:Z

    .line 38
    .line 39
    iput-boolean p11, p0, Lai/b;->k:Z

    .line 40
    .line 41
    iput-boolean p12, p0, Lai/b;->l:Z

    .line 42
    .line 43
    iput-object p13, p0, Lai/b;->m:Ljava/lang/String;

    .line 44
    .line 45
    move-object p1, p14

    .line 46
    iput-object p1, p0, Lai/b;->n:Ljava/util/ArrayList;

    .line 47
    .line 48
    move/from16 p1, p15

    .line 49
    .line 50
    iput-boolean p1, p0, Lai/b;->o:Z

    .line 51
    .line 52
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
    instance-of v0, p1, Lai/b;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lai/b;

    .line 12
    .line 13
    iget-object v0, p0, Lai/b;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Lai/b;->a:Ljava/lang/String;

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
    iget-object v0, p0, Lai/b;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v1, p1, Lai/b;->b:Ljava/lang/String;

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
    iget-boolean v0, p0, Lai/b;->c:Z

    .line 38
    .line 39
    iget-boolean v1, p1, Lai/b;->c:Z

    .line 40
    .line 41
    if-eq v0, v1, :cond_4

    .line 42
    .line 43
    goto/16 :goto_0

    .line 44
    .line 45
    :cond_4
    iget-object v0, p0, Lai/b;->d:Lgh/a;

    .line 46
    .line 47
    iget-object v1, p1, Lai/b;->d:Lgh/a;

    .line 48
    .line 49
    if-eq v0, v1, :cond_5

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_5
    iget-object v0, p0, Lai/b;->e:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v1, p1, Lai/b;->e:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-nez v0, :cond_6

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_6
    iget-object v0, p0, Lai/b;->f:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v1, p1, Lai/b;->f:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-nez v0, :cond_7

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_7
    iget-boolean v0, p0, Lai/b;->g:Z

    .line 75
    .line 76
    iget-boolean v1, p1, Lai/b;->g:Z

    .line 77
    .line 78
    if-eq v0, v1, :cond_8

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_8
    iget-boolean v0, p0, Lai/b;->h:Z

    .line 82
    .line 83
    iget-boolean v1, p1, Lai/b;->h:Z

    .line 84
    .line 85
    if-eq v0, v1, :cond_9

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_9
    iget-boolean v0, p0, Lai/b;->i:Z

    .line 89
    .line 90
    iget-boolean v1, p1, Lai/b;->i:Z

    .line 91
    .line 92
    if-eq v0, v1, :cond_a

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_a
    iget-boolean v0, p0, Lai/b;->j:Z

    .line 96
    .line 97
    iget-boolean v1, p1, Lai/b;->j:Z

    .line 98
    .line 99
    if-eq v0, v1, :cond_b

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_b
    iget-boolean v0, p0, Lai/b;->k:Z

    .line 103
    .line 104
    iget-boolean v1, p1, Lai/b;->k:Z

    .line 105
    .line 106
    if-eq v0, v1, :cond_c

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_c
    iget-boolean v0, p0, Lai/b;->l:Z

    .line 110
    .line 111
    iget-boolean v1, p1, Lai/b;->l:Z

    .line 112
    .line 113
    if-eq v0, v1, :cond_d

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_d
    iget-object v0, p0, Lai/b;->m:Ljava/lang/String;

    .line 117
    .line 118
    iget-object v1, p1, Lai/b;->m:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    if-nez v0, :cond_e

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_e
    iget-object v0, p0, Lai/b;->n:Ljava/util/ArrayList;

    .line 128
    .line 129
    iget-object v1, p1, Lai/b;->n:Ljava/util/ArrayList;

    .line 130
    .line 131
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-nez v0, :cond_f

    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_f
    iget-boolean p0, p0, Lai/b;->o:Z

    .line 139
    .line 140
    iget-boolean p1, p1, Lai/b;->o:Z

    .line 141
    .line 142
    if-eq p0, p1, :cond_10

    .line 143
    .line 144
    :goto_0
    const/4 p0, 0x0

    .line 145
    return p0

    .line 146
    :cond_10
    :goto_1
    const/4 p0, 0x1

    .line 147
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lai/b;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lai/b;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lai/b;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lai/b;->d:Lgh/a;

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
    iget-object v0, p0, Lai/b;->e:Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lai/b;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-boolean v2, p0, Lai/b;->g:Z

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-boolean v2, p0, Lai/b;->h:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-boolean v2, p0, Lai/b;->i:Z

    .line 55
    .line 56
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-boolean v2, p0, Lai/b;->j:Z

    .line 61
    .line 62
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iget-boolean v2, p0, Lai/b;->k:Z

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iget-boolean v2, p0, Lai/b;->l:Z

    .line 73
    .line 74
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-object v2, p0, Lai/b;->m:Ljava/lang/String;

    .line 79
    .line 80
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    iget-object v2, p0, Lai/b;->n:Ljava/util/ArrayList;

    .line 85
    .line 86
    invoke-static {v2, v0, v1}, Lkx/a;->b(Ljava/util/ArrayList;II)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    iget-boolean p0, p0, Lai/b;->o:Z

    .line 91
    .line 92
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    add-int/2addr p0, v0

    .line 97
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
    const-string v2, "Wallbox(id="

    .line 6
    .line 7
    iget-object v3, p0, Lai/b;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lai/b;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Lai/b;->c:Z

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
    iget-object v1, p0, Lai/b;->d:Lgh/a;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", formattedDuration="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", formattedEnergy="

    .line 36
    .line 37
    const-string v2, ", isEnergyAvailable="

    .line 38
    .line 39
    iget-object v3, p0, Lai/b;->e:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v4, p0, Lai/b;->f:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", isDurationAvailable="

    .line 47
    .line 48
    const-string v2, ", isChargingInProgress="

    .line 49
    .line 50
    iget-boolean v3, p0, Lai/b;->g:Z

    .line 51
    .line 52
    iget-boolean v4, p0, Lai/b;->h:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v1, ", isChargingPaused="

    .line 58
    .line 59
    const-string v2, ", isWaitingForAuthorization="

    .line 60
    .line 61
    iget-boolean v3, p0, Lai/b;->i:Z

    .line 62
    .line 63
    iget-boolean v4, p0, Lai/b;->j:Z

    .line 64
    .line 65
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v1, ", isChargingNotPossible="

    .line 69
    .line 70
    const-string v2, ", statusDescription="

    .line 71
    .line 72
    iget-boolean v3, p0, Lai/b;->k:Z

    .line 73
    .line 74
    iget-boolean v4, p0, Lai/b;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lai/b;->m:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", imageRequests="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object v1, p0, Lai/b;->n:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v1, ", isButtonLoading="

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ")"

    .line 100
    .line 101
    iget-boolean p0, p0, Lai/b;->o:Z

    .line 102
    .line 103
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0
.end method
