.class public final Lvk0/d0;
.super Lvk0/e0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lvk0/d;

.field public final c:Ljava/net/URL;

.field public final d:Ljava/lang/Double;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Lon0/s;

.field public final j:Lon0/t;

.field public final k:Ljava/util/List;

.field public final l:Z

.field public final m:Z

.field public final n:Z


# direct methods
.method public constructor <init>(Lvk0/d;Ljava/net/URL;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/s;Lon0/t;Ljava/util/List;ZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lvk0/e0;-><init>(Lvk0/d;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvk0/d0;->b:Lvk0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lvk0/d0;->c:Ljava/net/URL;

    .line 7
    .line 8
    iput-object p3, p0, Lvk0/d0;->d:Ljava/lang/Double;

    .line 9
    .line 10
    iput-object p4, p0, Lvk0/d0;->e:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lvk0/d0;->f:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lvk0/d0;->g:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lvk0/d0;->h:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lvk0/d0;->i:Lon0/s;

    .line 19
    .line 20
    iput-object p9, p0, Lvk0/d0;->j:Lon0/t;

    .line 21
    .line 22
    iput-object p10, p0, Lvk0/d0;->k:Ljava/util/List;

    .line 23
    .line 24
    iput-boolean p11, p0, Lvk0/d0;->l:Z

    .line 25
    .line 26
    iput-boolean p12, p0, Lvk0/d0;->m:Z

    .line 27
    .line 28
    iput-boolean p13, p0, Lvk0/d0;->n:Z

    .line 29
    .line 30
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
    instance-of v1, p1, Lvk0/d0;

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
    check-cast p1, Lvk0/d0;

    .line 12
    .line 13
    iget-object v1, p0, Lvk0/d0;->b:Lvk0/d;

    .line 14
    .line 15
    iget-object v3, p1, Lvk0/d0;->b:Lvk0/d;

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
    iget-object v1, p0, Lvk0/d0;->c:Ljava/net/URL;

    .line 25
    .line 26
    iget-object v3, p1, Lvk0/d0;->c:Ljava/net/URL;

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
    iget-object v1, p0, Lvk0/d0;->d:Ljava/lang/Double;

    .line 36
    .line 37
    iget-object v3, p1, Lvk0/d0;->d:Ljava/lang/Double;

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
    iget-object v1, p0, Lvk0/d0;->e:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lvk0/d0;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lvk0/d0;->f:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lvk0/d0;->f:Ljava/lang/String;

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
    iget-object v1, p0, Lvk0/d0;->g:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v3, p1, Lvk0/d0;->g:Ljava/lang/String;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lvk0/d0;->h:Ljava/lang/String;

    .line 80
    .line 81
    iget-object v3, p1, Lvk0/d0;->h:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Lvk0/d0;->i:Lon0/s;

    .line 91
    .line 92
    iget-object v3, p1, Lvk0/d0;->i:Lon0/s;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lvk0/d0;->j:Lon0/t;

    .line 102
    .line 103
    iget-object v3, p1, Lvk0/d0;->j:Lon0/t;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object v1, p0, Lvk0/d0;->k:Ljava/util/List;

    .line 113
    .line 114
    iget-object v3, p1, Lvk0/d0;->k:Ljava/util/List;

    .line 115
    .line 116
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    iget-boolean v1, p0, Lvk0/d0;->l:Z

    .line 124
    .line 125
    iget-boolean v3, p1, Lvk0/d0;->l:Z

    .line 126
    .line 127
    if-eq v1, v3, :cond_c

    .line 128
    .line 129
    return v2

    .line 130
    :cond_c
    iget-boolean v1, p0, Lvk0/d0;->m:Z

    .line 131
    .line 132
    iget-boolean v3, p1, Lvk0/d0;->m:Z

    .line 133
    .line 134
    if-eq v1, v3, :cond_d

    .line 135
    .line 136
    return v2

    .line 137
    :cond_d
    iget-boolean p0, p0, Lvk0/d0;->n:Z

    .line 138
    .line 139
    iget-boolean p1, p1, Lvk0/d0;->n:Z

    .line 140
    .line 141
    if-eq p0, p1, :cond_e

    .line 142
    .line 143
    return v2

    .line 144
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lvk0/d0;->b:Lvk0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lvk0/d;->hashCode()I

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
    iget-object v3, p0, Lvk0/d0;->c:Ljava/net/URL;

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
    invoke-virtual {v3}, Ljava/net/URL;->hashCode()I

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
    iget-object v3, p0, Lvk0/d0;->d:Ljava/lang/Double;

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
    iget-object v3, p0, Lvk0/d0;->e:Ljava/lang/String;

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
    iget-object v3, p0, Lvk0/d0;->f:Ljava/lang/String;

    .line 48
    .line 49
    if-nez v3, :cond_3

    .line 50
    .line 51
    move v3, v2

    .line 52
    goto :goto_3

    .line 53
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    :goto_3
    add-int/2addr v0, v3

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-object v3, p0, Lvk0/d0;->g:Ljava/lang/String;

    .line 60
    .line 61
    if-nez v3, :cond_4

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_4

    .line 65
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_4
    add-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v3, p0, Lvk0/d0;->h:Ljava/lang/String;

    .line 72
    .line 73
    if-nez v3, :cond_5

    .line 74
    .line 75
    move v3, v2

    .line 76
    goto :goto_5

    .line 77
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    :goto_5
    add-int/2addr v0, v3

    .line 82
    mul-int/2addr v0, v1

    .line 83
    iget-object v3, p0, Lvk0/d0;->i:Lon0/s;

    .line 84
    .line 85
    if-nez v3, :cond_6

    .line 86
    .line 87
    move v3, v2

    .line 88
    goto :goto_6

    .line 89
    :cond_6
    invoke-virtual {v3}, Lon0/s;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    :goto_6
    add-int/2addr v0, v3

    .line 94
    mul-int/2addr v0, v1

    .line 95
    iget-object v3, p0, Lvk0/d0;->j:Lon0/t;

    .line 96
    .line 97
    if-nez v3, :cond_7

    .line 98
    .line 99
    goto :goto_7

    .line 100
    :cond_7
    invoke-virtual {v3}, Lon0/t;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    :goto_7
    add-int/2addr v0, v2

    .line 105
    mul-int/2addr v0, v1

    .line 106
    iget-object v2, p0, Lvk0/d0;->k:Ljava/util/List;

    .line 107
    .line 108
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget-boolean v2, p0, Lvk0/d0;->l:Z

    .line 113
    .line 114
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    iget-boolean v2, p0, Lvk0/d0;->m:Z

    .line 119
    .line 120
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    iget-boolean p0, p0, Lvk0/d0;->n:Z

    .line 125
    .line 126
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    add-int/2addr p0, v0

    .line 131
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Paid(detail="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lvk0/d0;->b:Lvk0/d;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", termsUrl="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lvk0/d0;->c:Ljava/net/URL;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", pricePerHour="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lvk0/d0;->d:Ljava/lang/Double;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", currencyCode="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lvk0/d0;->e:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", providerName="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v1, ", additionalInfo="

    .line 49
    .line 50
    const-string v2, ", capacity="

    .line 51
    .line 52
    iget-object v3, p0, Lvk0/d0;->f:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v4, p0, Lvk0/d0;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Lvk0/d0;->h:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", providerInfo="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lvk0/d0;->i:Lon0/s;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", parkingSession="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lvk0/d0;->j:Lon0/t;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", rateTables="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object v1, p0, Lvk0/d0;->k:Ljava/util/List;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v1, ", freeOutsideParkingHours="

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ", isOpen24h="

    .line 100
    .line 101
    const-string v2, ", isParkingZone="

    .line 102
    .line 103
    iget-boolean v3, p0, Lvk0/d0;->l:Z

    .line 104
    .line 105
    iget-boolean v4, p0, Lvk0/d0;->m:Z

    .line 106
    .line 107
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 108
    .line 109
    .line 110
    const-string v1, ")"

    .line 111
    .line 112
    iget-boolean p0, p0, Lvk0/d0;->n:Z

    .line 113
    .line 114
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0
.end method
