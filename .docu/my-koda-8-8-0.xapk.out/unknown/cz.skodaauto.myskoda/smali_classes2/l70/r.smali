.class public final Ll70/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/time/OffsetDateTime;

.field public final b:Ljava/util/List;

.field public final c:D

.field public final d:I

.field public final e:D

.field public final f:D

.field public final g:D

.field public final h:D

.field public final i:Ll70/u;


# direct methods
.method public constructor <init>(Ljava/time/OffsetDateTime;Ljava/util/List;DIDDDDLl70/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 5
    .line 6
    iput-object p2, p0, Ll70/r;->b:Ljava/util/List;

    .line 7
    .line 8
    iput-wide p3, p0, Ll70/r;->c:D

    .line 9
    .line 10
    iput p5, p0, Ll70/r;->d:I

    .line 11
    .line 12
    iput-wide p6, p0, Ll70/r;->e:D

    .line 13
    .line 14
    iput-wide p8, p0, Ll70/r;->f:D

    .line 15
    .line 16
    iput-wide p10, p0, Ll70/r;->g:D

    .line 17
    .line 18
    iput-wide p12, p0, Ll70/r;->h:D

    .line 19
    .line 20
    iput-object p14, p0, Ll70/r;->i:Ll70/u;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Ll70/r;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_1
    check-cast p1, Ll70/r;

    .line 11
    .line 12
    iget-object v0, p0, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 13
    .line 14
    iget-object v2, p1, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_2
    iget-object v0, p0, Ll70/r;->b:Ljava/util/List;

    .line 24
    .line 25
    iget-object v2, p1, Ll70/r;->b:Ljava/util/List;

    .line 26
    .line 27
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_3

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_3
    iget-wide v2, p0, Ll70/r;->c:D

    .line 35
    .line 36
    iget-wide v4, p1, Ll70/r;->c:D

    .line 37
    .line 38
    invoke-static {v2, v3, v4, v5}, Lqr0/d;->a(DD)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-nez v0, :cond_4

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_4
    iget v0, p0, Ll70/r;->d:I

    .line 46
    .line 47
    iget v2, p1, Ll70/r;->d:I

    .line 48
    .line 49
    if-eq v0, v2, :cond_5

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_5
    iget-wide v2, p0, Ll70/r;->e:D

    .line 53
    .line 54
    iget-wide v4, p1, Ll70/r;->e:D

    .line 55
    .line 56
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Double;->compare(DD)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-nez v0, :cond_7

    .line 61
    .line 62
    iget-wide v2, p0, Ll70/r;->f:D

    .line 63
    .line 64
    iget-wide v4, p1, Ll70/r;->f:D

    .line 65
    .line 66
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Double;->compare(DD)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-nez v0, :cond_7

    .line 71
    .line 72
    iget-wide v2, p0, Ll70/r;->g:D

    .line 73
    .line 74
    iget-wide v4, p1, Ll70/r;->g:D

    .line 75
    .line 76
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Double;->compare(DD)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-nez v0, :cond_7

    .line 81
    .line 82
    iget-wide v2, p0, Ll70/r;->h:D

    .line 83
    .line 84
    iget-wide v4, p1, Ll70/r;->h:D

    .line 85
    .line 86
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Double;->compare(DD)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-nez v0, :cond_7

    .line 91
    .line 92
    iget-object p0, p0, Ll70/r;->i:Ll70/u;

    .line 93
    .line 94
    iget-object p1, p1, Ll70/r;->i:Ll70/u;

    .line 95
    .line 96
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-nez p0, :cond_6

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_6
    :goto_0
    const/4 p0, 0x1

    .line 104
    return p0

    .line 105
    :cond_7
    :goto_1
    return v1
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/time/OffsetDateTime;->hashCode()I

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
    iget-object v2, p0, Ll70/r;->b:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-wide v2, p0, Ll70/r;->c:D

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Ll70/r;->d:I

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-wide v2, p0, Ll70/r;->e:D

    .line 29
    .line 30
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-wide v2, p0, Ll70/r;->f:D

    .line 35
    .line 36
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-wide v2, p0, Ll70/r;->g:D

    .line 41
    .line 42
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-wide v2, p0, Ll70/r;->h:D

    .line 47
    .line 48
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object p0, p0, Ll70/r;->i:Ll70/u;

    .line 53
    .line 54
    if-nez p0, :cond_0

    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    goto :goto_0

    .line 58
    :cond_0
    invoke-virtual {p0}, Ll70/u;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    :goto_0
    add-int/2addr v0, p0

    .line 63
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 10

    .line 1
    iget-wide v0, p0, Ll70/r;->c:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Lqr0/d;->b(D)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "FuelConsumption(litPer100km="

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-wide v2, p0, Ll70/r;->e:D

    .line 15
    .line 16
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v2, ")"

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    new-instance v3, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v4, "ElectricConsumption(kWhPer100km="

    .line 31
    .line 32
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-wide v4, p0, Ll70/r;->f:D

    .line 36
    .line 37
    invoke-virtual {v3, v4, v5}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    new-instance v4, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v5, "GasConsumption(kgPer100km="

    .line 50
    .line 51
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-wide v5, p0, Ll70/r;->g:D

    .line 55
    .line 56
    invoke-virtual {v4, v5, v6}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    iget-wide v5, p0, Ll70/r;->h:D

    .line 67
    .line 68
    invoke-static {v5, v6}, Lqr0/p;->a(D)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    new-instance v6, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    const-string v7, "TripStatisticsDetail(date="

    .line 75
    .line 76
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v7, p0, Ll70/r;->a:Ljava/time/OffsetDateTime;

    .line 80
    .line 81
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v7, ", tripIds="

    .line 85
    .line 86
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object v7, p0, Ll70/r;->b:Ljava/util/List;

    .line 90
    .line 91
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v7, ", mileage="

    .line 95
    .line 96
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v7, ", travelTimeInMin="

    .line 100
    .line 101
    const-string v8, ", averageFuelConsumption="

    .line 102
    .line 103
    iget v9, p0, Ll70/r;->d:I

    .line 104
    .line 105
    invoke-static {v6, v0, v7, v9, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string v0, ", averageElectricConsumption="

    .line 109
    .line 110
    const-string v7, ", averageGasConsumption="

    .line 111
    .line 112
    invoke-static {v6, v1, v0, v3, v7}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string v0, ", averageSpeed="

    .line 116
    .line 117
    const-string v1, ", fuelCosts="

    .line 118
    .line 119
    invoke-static {v6, v4, v0, v5, v1}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object p0, p0, Ll70/r;->i:Ll70/u;

    .line 123
    .line 124
    invoke-virtual {v6, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0
.end method
