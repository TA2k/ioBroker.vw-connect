.class public final Ll70/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ll70/u;

.field public final b:D

.field public final c:I

.field public final d:D

.field public final e:I

.field public final f:Lqr0/i;

.field public final g:Lqr0/g;

.field public final h:Lqr0/j;

.field public final i:D

.field public final j:Ll70/a0;

.field public final k:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ll70/u;DIDILqr0/i;Lqr0/g;Lqr0/j;DLl70/a0;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll70/p;->a:Ll70/u;

    .line 5
    .line 6
    iput-wide p2, p0, Ll70/p;->b:D

    .line 7
    .line 8
    iput p4, p0, Ll70/p;->c:I

    .line 9
    .line 10
    iput-wide p5, p0, Ll70/p;->d:D

    .line 11
    .line 12
    iput p7, p0, Ll70/p;->e:I

    .line 13
    .line 14
    iput-object p8, p0, Ll70/p;->f:Lqr0/i;

    .line 15
    .line 16
    iput-object p9, p0, Ll70/p;->g:Lqr0/g;

    .line 17
    .line 18
    iput-object p10, p0, Ll70/p;->h:Lqr0/j;

    .line 19
    .line 20
    iput-wide p11, p0, Ll70/p;->i:D

    .line 21
    .line 22
    iput-object p13, p0, Ll70/p;->j:Ll70/a0;

    .line 23
    .line 24
    iput-object p14, p0, Ll70/p;->k:Ljava/lang/Object;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Ll70/p;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    goto/16 :goto_0

    .line 11
    .line 12
    :cond_1
    check-cast p1, Ll70/p;

    .line 13
    .line 14
    iget-object v0, p0, Ll70/p;->a:Ll70/u;

    .line 15
    .line 16
    iget-object v2, p1, Ll70/p;->a:Ll70/u;

    .line 17
    .line 18
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-nez v0, :cond_2

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_2
    iget-wide v2, p0, Ll70/p;->b:D

    .line 26
    .line 27
    iget-wide v4, p1, Ll70/p;->b:D

    .line 28
    .line 29
    invoke-static {v2, v3, v4, v5}, Lqr0/d;->a(DD)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_3
    iget v0, p0, Ll70/p;->c:I

    .line 37
    .line 38
    iget v2, p1, Ll70/p;->c:I

    .line 39
    .line 40
    if-eq v0, v2, :cond_4

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_4
    iget-wide v2, p0, Ll70/p;->d:D

    .line 44
    .line 45
    iget-wide v4, p1, Ll70/p;->d:D

    .line 46
    .line 47
    invoke-static {v2, v3, v4, v5}, Lqr0/d;->a(DD)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_5

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_5
    iget v0, p0, Ll70/p;->e:I

    .line 55
    .line 56
    iget v2, p1, Ll70/p;->e:I

    .line 57
    .line 58
    if-eq v0, v2, :cond_6

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_6
    iget-object v0, p0, Ll70/p;->f:Lqr0/i;

    .line 62
    .line 63
    iget-object v2, p1, Ll70/p;->f:Lqr0/i;

    .line 64
    .line 65
    invoke-virtual {v0, v2}, Lqr0/i;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-nez v0, :cond_7

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_7
    iget-object v0, p0, Ll70/p;->g:Lqr0/g;

    .line 73
    .line 74
    iget-object v2, p1, Ll70/p;->g:Lqr0/g;

    .line 75
    .line 76
    invoke-virtual {v0, v2}, Lqr0/g;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-nez v0, :cond_8

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_8
    iget-object v0, p0, Ll70/p;->h:Lqr0/j;

    .line 84
    .line 85
    iget-object v2, p1, Ll70/p;->h:Lqr0/j;

    .line 86
    .line 87
    invoke-virtual {v0, v2}, Lqr0/j;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-nez v0, :cond_9

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_9
    iget-wide v2, p0, Ll70/p;->i:D

    .line 95
    .line 96
    iget-wide v4, p1, Ll70/p;->i:D

    .line 97
    .line 98
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Double;->compare(DD)I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-nez v0, :cond_c

    .line 103
    .line 104
    iget-object v0, p0, Ll70/p;->j:Ll70/a0;

    .line 105
    .line 106
    iget-object v2, p1, Ll70/p;->j:Ll70/a0;

    .line 107
    .line 108
    if-eq v0, v2, :cond_a

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_a
    iget-object p0, p0, Ll70/p;->k:Ljava/lang/Object;

    .line 112
    .line 113
    iget-object p1, p1, Ll70/p;->k:Ljava/lang/Object;

    .line 114
    .line 115
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-nez p0, :cond_b

    .line 120
    .line 121
    :goto_0
    return v1

    .line 122
    :cond_b
    :goto_1
    const/4 p0, 0x1

    .line 123
    return p0

    .line 124
    :cond_c
    return v1
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ll70/p;->a:Ll70/u;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {v0}, Ll70/u;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-wide v2, p0, Ll70/p;->b:D

    .line 15
    .line 16
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget v2, p0, Ll70/p;->c:I

    .line 21
    .line 22
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-wide v2, p0, Ll70/p;->d:D

    .line 27
    .line 28
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget v2, p0, Ll70/p;->e:I

    .line 33
    .line 34
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-object v2, p0, Ll70/p;->f:Lqr0/i;

    .line 39
    .line 40
    iget-wide v2, v2, Lqr0/i;->a:D

    .line 41
    .line 42
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Ll70/p;->g:Lqr0/g;

    .line 47
    .line 48
    iget-wide v2, v2, Lqr0/g;->a:D

    .line 49
    .line 50
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object v2, p0, Ll70/p;->h:Lqr0/j;

    .line 55
    .line 56
    iget-wide v2, v2, Lqr0/j;->a:D

    .line 57
    .line 58
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-wide v2, p0, Ll70/p;->i:D

    .line 63
    .line 64
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-object v2, p0, Ll70/p;->j:Ll70/a0;

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    add-int/2addr v2, v0

    .line 75
    mul-int/2addr v2, v1

    .line 76
    iget-object p0, p0, Ll70/p;->k:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    add-int/2addr p0, v2

    .line 83
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-wide v0, p0, Ll70/p;->b:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Lqr0/d;->b(D)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-wide v1, p0, Ll70/p;->d:D

    .line 8
    .line 9
    invoke-static {v1, v2}, Lqr0/d;->b(D)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-wide v2, p0, Ll70/p;->i:D

    .line 14
    .line 15
    invoke-static {v2, v3}, Lqr0/p;->a(D)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    new-instance v3, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v4, "TripStatistics(overallFuelCosts="

    .line 22
    .line 23
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v4, p0, Ll70/p;->a:Ll70/u;

    .line 27
    .line 28
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v4, ", overallMileage="

    .line 32
    .line 33
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", overallTravelTime="

    .line 40
    .line 41
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget v0, p0, Ll70/p;->c:I

    .line 45
    .line 46
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v0, ", overallAverageMileage="

    .line 50
    .line 51
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v0, ", overallAverageTravelTimeInMin="

    .line 58
    .line 59
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget v0, p0, Ll70/p;->e:I

    .line 63
    .line 64
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v0, ", overallAverageFuelConsumption="

    .line 68
    .line 69
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Ll70/p;->f:Lqr0/i;

    .line 73
    .line 74
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v0, ", overallAverageElectricConsumption="

    .line 78
    .line 79
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget-object v0, p0, Ll70/p;->g:Lqr0/g;

    .line 83
    .line 84
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v0, ", overallAverageGasConsumption="

    .line 88
    .line 89
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    iget-object v0, p0, Ll70/p;->h:Lqr0/j;

    .line 93
    .line 94
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v0, ", overallAverageSpeed="

    .line 98
    .line 99
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v0, ", vehicleType="

    .line 106
    .line 107
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    iget-object v0, p0, Ll70/p;->j:Ll70/a0;

    .line 111
    .line 112
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v0, ", detailedStatistics="

    .line 116
    .line 117
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string v0, ")"

    .line 121
    .line 122
    iget-object p0, p0, Ll70/p;->k:Ljava/lang/Object;

    .line 123
    .line 124
    invoke-static {v3, p0, v0}, Lf2/m0;->k(Ljava/lang/StringBuilder;Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    return-object p0
.end method
