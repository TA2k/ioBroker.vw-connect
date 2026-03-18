.class public final Lqp0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Ljava/lang/String;

.field public final c:D

.field public final d:J

.field public final e:Lmy0/c;

.field public final f:Lmy0/c;

.field public final g:Z

.field public final h:Z

.field public final i:Ljava/lang/String;

.field public final j:Z


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Ljava/lang/String;DJLmy0/c;Lmy0/c;ZZLjava/lang/String;I)V
    .locals 14

    move/from16 v0, p12

    and-int/lit16 v0, v0, 0x100

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    move-object v12, v0

    goto :goto_0

    :cond_0
    move-object/from16 v12, p11

    :goto_0
    const/4 v13, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object/from16 v3, p2

    move-wide/from16 v4, p3

    move-wide/from16 v6, p5

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    move/from16 v10, p9

    move/from16 v11, p10

    .line 1
    invoke-direct/range {v1 .. v13}, Lqp0/o;-><init>(Ljava/util/List;Ljava/lang/String;DJLmy0/c;Lmy0/c;ZZLjava/lang/String;Z)V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Ljava/lang/String;DJLmy0/c;Lmy0/c;ZZLjava/lang/String;Z)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lqp0/o;->a:Ljava/util/List;

    .line 4
    iput-object p2, p0, Lqp0/o;->b:Ljava/lang/String;

    .line 5
    iput-wide p3, p0, Lqp0/o;->c:D

    .line 6
    iput-wide p5, p0, Lqp0/o;->d:J

    .line 7
    iput-object p7, p0, Lqp0/o;->e:Lmy0/c;

    .line 8
    iput-object p8, p0, Lqp0/o;->f:Lmy0/c;

    .line 9
    iput-boolean p9, p0, Lqp0/o;->g:Z

    .line 10
    iput-boolean p10, p0, Lqp0/o;->h:Z

    .line 11
    iput-object p11, p0, Lqp0/o;->i:Ljava/lang/String;

    .line 12
    iput-boolean p12, p0, Lqp0/o;->j:Z

    return-void
.end method

.method public static a(Lqp0/o;Ljava/util/ArrayList;I)Lqp0/o;
    .locals 13

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lqp0/o;->a:Ljava/util/List;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    iget-object v2, p0, Lqp0/o;->b:Ljava/lang/String;

    .line 9
    .line 10
    iget-wide v3, p0, Lqp0/o;->c:D

    .line 11
    .line 12
    iget-wide v5, p0, Lqp0/o;->d:J

    .line 13
    .line 14
    iget-object v7, p0, Lqp0/o;->e:Lmy0/c;

    .line 15
    .line 16
    iget-object v8, p0, Lqp0/o;->f:Lmy0/c;

    .line 17
    .line 18
    and-int/lit8 p1, p2, 0x40

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    iget-boolean p1, p0, Lqp0/o;->g:Z

    .line 24
    .line 25
    move v9, p1

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    move v9, v0

    .line 28
    :goto_0
    and-int/lit16 p1, p2, 0x80

    .line 29
    .line 30
    if-eqz p1, :cond_2

    .line 31
    .line 32
    iget-boolean p1, p0, Lqp0/o;->h:Z

    .line 33
    .line 34
    move v10, p1

    .line 35
    goto :goto_1

    .line 36
    :cond_2
    move v10, v0

    .line 37
    :goto_1
    iget-object v11, p0, Lqp0/o;->i:Ljava/lang/String;

    .line 38
    .line 39
    and-int/lit16 p1, p2, 0x200

    .line 40
    .line 41
    if-eqz p1, :cond_3

    .line 42
    .line 43
    iget-boolean v0, p0, Lqp0/o;->j:Z

    .line 44
    .line 45
    :cond_3
    move v12, v0

    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const-string p0, "waypoints"

    .line 50
    .line 51
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    const-string p0, "$v$c$cz-skodaauto-myskoda-library-route-model-EncodedPolyline$-encodedPolyline$0"

    .line 55
    .line 56
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lqp0/o;

    .line 60
    .line 61
    invoke-direct/range {v0 .. v12}, Lqp0/o;-><init>(Ljava/util/List;Ljava/lang/String;DJLmy0/c;Lmy0/c;ZZLjava/lang/String;Z)V

    .line 62
    .line 63
    .line 64
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lqp0/o;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lqp0/o;

    .line 12
    .line 13
    iget-object v0, p0, Lqp0/o;->a:Ljava/util/List;

    .line 14
    .line 15
    iget-object v1, p1, Lqp0/o;->a:Ljava/util/List;

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
    goto :goto_0

    .line 24
    :cond_2
    iget-object v0, p0, Lqp0/o;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v1, p1, Lqp0/o;->b:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_3

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_3
    iget-wide v0, p0, Lqp0/o;->c:D

    .line 36
    .line 37
    iget-wide v2, p1, Lqp0/o;->c:D

    .line 38
    .line 39
    invoke-static {v0, v1, v2, v3}, Lqr0/d;->a(DD)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_4

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    iget-wide v0, p0, Lqp0/o;->d:J

    .line 47
    .line 48
    iget-wide v2, p1, Lqp0/o;->d:J

    .line 49
    .line 50
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->d(JJ)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_5

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_5
    iget-object v0, p0, Lqp0/o;->e:Lmy0/c;

    .line 58
    .line 59
    iget-object v1, p1, Lqp0/o;->e:Lmy0/c;

    .line 60
    .line 61
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_6

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_6
    iget-object v0, p0, Lqp0/o;->f:Lmy0/c;

    .line 69
    .line 70
    iget-object v1, p1, Lqp0/o;->f:Lmy0/c;

    .line 71
    .line 72
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-nez v0, :cond_7

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_7
    iget-boolean v0, p0, Lqp0/o;->g:Z

    .line 80
    .line 81
    iget-boolean v1, p1, Lqp0/o;->g:Z

    .line 82
    .line 83
    if-eq v0, v1, :cond_8

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_8
    iget-boolean v0, p0, Lqp0/o;->h:Z

    .line 87
    .line 88
    iget-boolean v1, p1, Lqp0/o;->h:Z

    .line 89
    .line 90
    if-eq v0, v1, :cond_9

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_9
    iget-object v0, p0, Lqp0/o;->i:Ljava/lang/String;

    .line 94
    .line 95
    iget-object v1, p1, Lqp0/o;->i:Ljava/lang/String;

    .line 96
    .line 97
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    if-nez v0, :cond_a

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_a
    iget-boolean p0, p0, Lqp0/o;->j:Z

    .line 105
    .line 106
    iget-boolean p1, p1, Lqp0/o;->j:Z

    .line 107
    .line 108
    if-eq p0, p1, :cond_b

    .line 109
    .line 110
    :goto_0
    const/4 p0, 0x0

    .line 111
    return p0

    .line 112
    :cond_b
    :goto_1
    const/4 p0, 0x1

    .line 113
    return p0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Lqp0/o;->a:Ljava/util/List;

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
    iget-object v2, p0, Lqp0/o;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-wide v2, p0, Lqp0/o;->c:D

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    sget v2, Lmy0/c;->g:I

    .line 23
    .line 24
    iget-wide v2, p0, Lqp0/o;->d:J

    .line 25
    .line 26
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    iget-object v3, p0, Lqp0/o;->e:Lmy0/c;

    .line 32
    .line 33
    if-nez v3, :cond_0

    .line 34
    .line 35
    move v3, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iget-wide v3, v3, Lmy0/c;->d:J

    .line 38
    .line 39
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    :goto_0
    add-int/2addr v0, v3

    .line 44
    mul-int/2addr v0, v1

    .line 45
    iget-object v3, p0, Lqp0/o;->f:Lmy0/c;

    .line 46
    .line 47
    if-nez v3, :cond_1

    .line 48
    .line 49
    move v3, v2

    .line 50
    goto :goto_1

    .line 51
    :cond_1
    iget-wide v3, v3, Lmy0/c;->d:J

    .line 52
    .line 53
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    :goto_1
    add-int/2addr v0, v3

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-boolean v3, p0, Lqp0/o;->g:Z

    .line 60
    .line 61
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    iget-boolean v3, p0, Lqp0/o;->h:Z

    .line 66
    .line 67
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    iget-object v3, p0, Lqp0/o;->i:Ljava/lang/String;

    .line 72
    .line 73
    if-nez v3, :cond_2

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    :goto_2
    add-int/2addr v0, v2

    .line 81
    mul-int/2addr v0, v1

    .line 82
    iget-boolean p0, p0, Lqp0/o;->j:Z

    .line 83
    .line 84
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    add-int/2addr p0, v0

    .line 89
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "EncodedPolyline(encoded="

    .line 2
    .line 3
    iget-object v1, p0, Lqp0/o;->b:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, ")"

    .line 6
    .line 7
    invoke-static {v0, v1, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-wide v3, p0, Lqp0/o;->c:D

    .line 12
    .line 13
    invoke-static {v3, v4}, Lqr0/d;->b(D)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-wide v3, p0, Lqp0/o;->d:J

    .line 18
    .line 19
    invoke-static {v3, v4}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    new-instance v4, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v5, "Route(waypoints="

    .line 26
    .line 27
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v5, p0, Lqp0/o;->a:Ljava/util/List;

    .line 31
    .line 32
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v5, ", encodedPolyline="

    .line 36
    .line 37
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v0, ", distance="

    .line 44
    .line 45
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v0, ", duration="

    .line 49
    .line 50
    const-string v5, ", chargingDuration="

    .line 51
    .line 52
    invoke-static {v4, v1, v0, v3, v5}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object v0, p0, Lqp0/o;->e:Lmy0/c;

    .line 56
    .line 57
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v0, ", drivingDuration="

    .line 61
    .line 62
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-object v0, p0, Lqp0/o;->f:Lmy0/c;

    .line 66
    .line 67
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v0, ", isAITrip="

    .line 71
    .line 72
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v0, ", isAIAssistant="

    .line 76
    .line 77
    const-string v1, ", aiSummary="

    .line 78
    .line 79
    iget-boolean v3, p0, Lqp0/o;->g:Z

    .line 80
    .line 81
    iget-boolean v5, p0, Lqp0/o;->h:Z

    .line 82
    .line 83
    invoke-static {v4, v3, v0, v5, v1}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const-string v0, ", isRecalculated="

    .line 87
    .line 88
    iget-object v1, p0, Lqp0/o;->i:Ljava/lang/String;

    .line 89
    .line 90
    iget-boolean p0, p0, Lqp0/o;->j:Z

    .line 91
    .line 92
    invoke-static {v1, v0, v2, v4, p0}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method
