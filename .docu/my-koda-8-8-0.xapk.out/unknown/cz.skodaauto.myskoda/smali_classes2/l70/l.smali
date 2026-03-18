.class public final Ll70/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxj0/f;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Ljava/time/OffsetDateTime;

.field public final f:Ljava/time/OffsetDateTime;

.field public final g:Lqr0/l;

.field public final h:Lqr0/l;

.field public final i:Lqr0/d;

.field public final j:Lmy0/c;


# direct methods
.method public constructor <init>(Lxj0/f;Ljava/lang/String;Ljava/lang/String;ZLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Lqr0/l;Lqr0/l;Lqr0/d;Lmy0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll70/l;->a:Lxj0/f;

    .line 5
    .line 6
    iput-object p2, p0, Ll70/l;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Ll70/l;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p4, p0, Ll70/l;->d:Z

    .line 11
    .line 12
    iput-object p5, p0, Ll70/l;->e:Ljava/time/OffsetDateTime;

    .line 13
    .line 14
    iput-object p6, p0, Ll70/l;->f:Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    iput-object p7, p0, Ll70/l;->g:Lqr0/l;

    .line 17
    .line 18
    iput-object p8, p0, Ll70/l;->h:Lqr0/l;

    .line 19
    .line 20
    iput-object p9, p0, Ll70/l;->i:Lqr0/d;

    .line 21
    .line 22
    iput-object p10, p0, Ll70/l;->j:Lmy0/c;

    .line 23
    .line 24
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
    instance-of v1, p1, Ll70/l;

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
    check-cast p1, Ll70/l;

    .line 12
    .line 13
    iget-object v1, p0, Ll70/l;->a:Lxj0/f;

    .line 14
    .line 15
    iget-object v3, p1, Ll70/l;->a:Lxj0/f;

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
    iget-object v1, p0, Ll70/l;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ll70/l;->b:Ljava/lang/String;

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
    iget-object v1, p0, Ll70/l;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Ll70/l;->c:Ljava/lang/String;

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
    iget-boolean v1, p0, Ll70/l;->d:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Ll70/l;->d:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Ll70/l;->e:Ljava/time/OffsetDateTime;

    .line 54
    .line 55
    iget-object v3, p1, Ll70/l;->e:Ljava/time/OffsetDateTime;

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
    iget-object v1, p0, Ll70/l;->f:Ljava/time/OffsetDateTime;

    .line 65
    .line 66
    iget-object v3, p1, Ll70/l;->f:Ljava/time/OffsetDateTime;

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
    iget-object v1, p0, Ll70/l;->g:Lqr0/l;

    .line 76
    .line 77
    iget-object v3, p1, Ll70/l;->g:Lqr0/l;

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
    iget-object v1, p0, Ll70/l;->h:Lqr0/l;

    .line 87
    .line 88
    iget-object v3, p1, Ll70/l;->h:Lqr0/l;

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
    iget-object v1, p0, Ll70/l;->i:Lqr0/d;

    .line 98
    .line 99
    iget-object v3, p1, Ll70/l;->i:Lqr0/d;

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
    iget-object p0, p0, Ll70/l;->j:Lmy0/c;

    .line 109
    .line 110
    iget-object p1, p1, Ll70/l;->j:Lmy0/c;

    .line 111
    .line 112
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-nez p0, :cond_b

    .line 117
    .line 118
    return v2

    .line 119
    :cond_b
    return v0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ll70/l;->a:Lxj0/f;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Lxj0/f;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const/16 v2, 0x1f

    .line 13
    .line 14
    mul-int/2addr v1, v2

    .line 15
    iget-object v3, p0, Ll70/l;->b:Ljava/lang/String;

    .line 16
    .line 17
    if-nez v3, :cond_1

    .line 18
    .line 19
    move v3, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    :goto_1
    add-int/2addr v1, v3

    .line 26
    mul-int/2addr v1, v2

    .line 27
    iget-object v3, p0, Ll70/l;->c:Ljava/lang/String;

    .line 28
    .line 29
    if-nez v3, :cond_2

    .line 30
    .line 31
    move v3, v0

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    :goto_2
    add-int/2addr v1, v3

    .line 38
    mul-int/2addr v1, v2

    .line 39
    iget-boolean v3, p0, Ll70/l;->d:Z

    .line 40
    .line 41
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    iget-object v3, p0, Ll70/l;->e:Ljava/time/OffsetDateTime;

    .line 46
    .line 47
    if-nez v3, :cond_3

    .line 48
    .line 49
    move v3, v0

    .line 50
    goto :goto_3

    .line 51
    :cond_3
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    :goto_3
    add-int/2addr v1, v3

    .line 56
    mul-int/2addr v1, v2

    .line 57
    iget-object v3, p0, Ll70/l;->f:Ljava/time/OffsetDateTime;

    .line 58
    .line 59
    if-nez v3, :cond_4

    .line 60
    .line 61
    move v3, v0

    .line 62
    goto :goto_4

    .line 63
    :cond_4
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    :goto_4
    add-int/2addr v1, v3

    .line 68
    mul-int/2addr v1, v2

    .line 69
    iget-object v3, p0, Ll70/l;->g:Lqr0/l;

    .line 70
    .line 71
    if-nez v3, :cond_5

    .line 72
    .line 73
    move v3, v0

    .line 74
    goto :goto_5

    .line 75
    :cond_5
    iget v3, v3, Lqr0/l;->d:I

    .line 76
    .line 77
    invoke-static {v3}, Ljava/lang/Integer;->hashCode(I)I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    :goto_5
    add-int/2addr v1, v3

    .line 82
    mul-int/2addr v1, v2

    .line 83
    iget-object v3, p0, Ll70/l;->h:Lqr0/l;

    .line 84
    .line 85
    if-nez v3, :cond_6

    .line 86
    .line 87
    move v3, v0

    .line 88
    goto :goto_6

    .line 89
    :cond_6
    iget v3, v3, Lqr0/l;->d:I

    .line 90
    .line 91
    invoke-static {v3}, Ljava/lang/Integer;->hashCode(I)I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_6
    add-int/2addr v1, v3

    .line 96
    mul-int/2addr v1, v2

    .line 97
    iget-object v3, p0, Ll70/l;->i:Lqr0/d;

    .line 98
    .line 99
    if-nez v3, :cond_7

    .line 100
    .line 101
    move v3, v0

    .line 102
    goto :goto_7

    .line 103
    :cond_7
    iget-wide v3, v3, Lqr0/d;->a:D

    .line 104
    .line 105
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    :goto_7
    add-int/2addr v1, v3

    .line 110
    mul-int/2addr v1, v2

    .line 111
    iget-object p0, p0, Ll70/l;->j:Lmy0/c;

    .line 112
    .line 113
    if-nez p0, :cond_8

    .line 114
    .line 115
    goto :goto_8

    .line 116
    :cond_8
    iget-wide v2, p0, Lmy0/c;->d:J

    .line 117
    .line 118
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    :goto_8
    add-int/2addr v1, v0

    .line 123
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SingleTripWaypoint(location="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ll70/l;->a:Lxj0/f;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", name="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ll70/l;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", formattedAddress="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", chargedHere="

    .line 29
    .line 30
    const-string v2, ", departureTime="

    .line 31
    .line 32
    iget-object v3, p0, Ll70/l;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean v4, p0, Ll70/l;->d:Z

    .line 35
    .line 36
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Ll70/l;->e:Ljava/time/OffsetDateTime;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", arrivalTime="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Ll70/l;->f:Ljava/time/OffsetDateTime;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", arrivalStateOfCharge="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Ll70/l;->g:Lqr0/l;

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", departureStateOfCharge="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Ll70/l;->h:Lqr0/l;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", distanceToNextWaypoint="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Ll70/l;->i:Lqr0/d;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", timeToNextWaypoint="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Ll70/l;->j:Lmy0/c;

    .line 90
    .line 91
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string p0, ")"

    .line 95
    .line 96
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method
