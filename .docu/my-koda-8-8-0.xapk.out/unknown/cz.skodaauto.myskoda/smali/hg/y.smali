.class public final Lhg/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Lhg/c;

.field public final c:Z

.field public final d:Ljava/lang/String;

.field public final e:Ljava/util/List;

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Ljava/lang/String;

.field public final j:Z


# direct methods
.method public constructor <init>(ZLhg/c;ZLjava/lang/String;Ljava/util/List;ZZZLjava/lang/String;Z)V
    .locals 1

    .line 1
    const-string v0, "evseId"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "pricingList"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-boolean p1, p0, Lhg/y;->a:Z

    .line 15
    .line 16
    iput-object p2, p0, Lhg/y;->b:Lhg/c;

    .line 17
    .line 18
    iput-boolean p3, p0, Lhg/y;->c:Z

    .line 19
    .line 20
    iput-object p4, p0, Lhg/y;->d:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p5, p0, Lhg/y;->e:Ljava/util/List;

    .line 23
    .line 24
    iput-boolean p6, p0, Lhg/y;->f:Z

    .line 25
    .line 26
    iput-boolean p7, p0, Lhg/y;->g:Z

    .line 27
    .line 28
    iput-boolean p8, p0, Lhg/y;->h:Z

    .line 29
    .line 30
    iput-object p9, p0, Lhg/y;->i:Ljava/lang/String;

    .line 31
    .line 32
    iput-boolean p10, p0, Lhg/y;->j:Z

    .line 33
    .line 34
    return-void
.end method

.method public static a(Lhg/y;ZLhg/c;Ljava/util/ArrayList;ZZZLjava/lang/String;ZI)Lhg/y;
    .locals 11

    .line 1
    move/from16 v0, p9

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-boolean p1, p0, Lhg/y;->a:Z

    .line 8
    .line 9
    :cond_0
    move v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p1, p0, Lhg/y;->b:Lhg/c;

    .line 15
    .line 16
    move-object v2, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move-object v2, p2

    .line 19
    :goto_0
    and-int/lit8 p1, v0, 0x4

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-boolean p1, p0, Lhg/y;->c:Z

    .line 24
    .line 25
    :goto_1
    move v3, p1

    .line 26
    goto :goto_2

    .line 27
    :cond_2
    const/4 p1, 0x1

    .line 28
    goto :goto_1

    .line 29
    :goto_2
    iget-object v4, p0, Lhg/y;->d:Ljava/lang/String;

    .line 30
    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_3

    .line 34
    .line 35
    iget-object p1, p0, Lhg/y;->e:Ljava/util/List;

    .line 36
    .line 37
    move-object v5, p1

    .line 38
    goto :goto_3

    .line 39
    :cond_3
    move-object v5, p3

    .line 40
    :goto_3
    and-int/lit8 p1, v0, 0x20

    .line 41
    .line 42
    if-eqz p1, :cond_4

    .line 43
    .line 44
    iget-boolean p1, p0, Lhg/y;->f:Z

    .line 45
    .line 46
    move v6, p1

    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move v6, p4

    .line 49
    :goto_4
    and-int/lit8 p1, v0, 0x40

    .line 50
    .line 51
    if-eqz p1, :cond_5

    .line 52
    .line 53
    iget-boolean p1, p0, Lhg/y;->g:Z

    .line 54
    .line 55
    move v7, p1

    .line 56
    goto :goto_5

    .line 57
    :cond_5
    move/from16 v7, p5

    .line 58
    .line 59
    :goto_5
    and-int/lit16 p1, v0, 0x80

    .line 60
    .line 61
    if-eqz p1, :cond_6

    .line 62
    .line 63
    iget-boolean p1, p0, Lhg/y;->h:Z

    .line 64
    .line 65
    move v8, p1

    .line 66
    goto :goto_6

    .line 67
    :cond_6
    move/from16 v8, p6

    .line 68
    .line 69
    :goto_6
    and-int/lit16 p1, v0, 0x100

    .line 70
    .line 71
    if-eqz p1, :cond_7

    .line 72
    .line 73
    iget-object p1, p0, Lhg/y;->i:Ljava/lang/String;

    .line 74
    .line 75
    move-object v9, p1

    .line 76
    goto :goto_7

    .line 77
    :cond_7
    move-object/from16 v9, p7

    .line 78
    .line 79
    :goto_7
    and-int/lit16 p1, v0, 0x200

    .line 80
    .line 81
    if-eqz p1, :cond_8

    .line 82
    .line 83
    iget-boolean p1, p0, Lhg/y;->j:Z

    .line 84
    .line 85
    move v10, p1

    .line 86
    goto :goto_8

    .line 87
    :cond_8
    move/from16 v10, p8

    .line 88
    .line 89
    :goto_8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    const-string p0, "evseId"

    .line 93
    .line 94
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    const-string p0, "pricingList"

    .line 98
    .line 99
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    new-instance v0, Lhg/y;

    .line 103
    .line 104
    invoke-direct/range {v0 .. v10}, Lhg/y;-><init>(ZLhg/c;ZLjava/lang/String;Ljava/util/List;ZZZLjava/lang/String;Z)V

    .line 105
    .line 106
    .line 107
    return-object v0
.end method


# virtual methods
.method public final b()Lhg/m;
    .locals 11

    .line 1
    iget-boolean v0, p0, Lhg/y;->c:Z

    .line 2
    .line 3
    iget-object v1, p0, Lhg/y;->d:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lhg/y;->b:Lhg/c;

    .line 6
    .line 7
    iget-boolean v3, p0, Lhg/y;->a:Z

    .line 8
    .line 9
    if-nez v3, :cond_4

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    goto :goto_3

    .line 14
    :cond_0
    iget-object v2, p0, Lhg/y;->e:Ljava/util/List;

    .line 15
    .line 16
    check-cast v2, Ljava/lang/Iterable;

    .line 17
    .line 18
    new-instance v4, Ljava/util/ArrayList;

    .line 19
    .line 20
    const/16 v3, 0xa

    .line 21
    .line 22
    invoke-static {v2, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 27
    .line 28
    .line 29
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Lhg/a;

    .line 44
    .line 45
    new-instance v5, Lhg/a;

    .line 46
    .line 47
    iget-object v6, v3, Lhg/a;->a:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v3, v3, Lhg/a;->b:Ljava/lang/String;

    .line 50
    .line 51
    invoke-direct {v5, v6, v3}, Lhg/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    iget-object v2, p0, Lhg/y;->i:Ljava/lang/String;

    .line 59
    .line 60
    if-eqz v2, :cond_2

    .line 61
    .line 62
    const/4 v3, 0x1

    .line 63
    :goto_1
    move v8, v3

    .line 64
    goto :goto_2

    .line 65
    :cond_2
    const/4 v3, 0x0

    .line 66
    goto :goto_1

    .line 67
    :goto_2
    if-nez v2, :cond_3

    .line 68
    .line 69
    const-string v2, ""

    .line 70
    .line 71
    :cond_3
    move-object v9, v2

    .line 72
    new-instance v3, Lhg/b;

    .line 73
    .line 74
    iget-boolean v5, p0, Lhg/y;->f:Z

    .line 75
    .line 76
    iget-boolean v6, p0, Lhg/y;->g:Z

    .line 77
    .line 78
    iget-boolean v7, p0, Lhg/y;->h:Z

    .line 79
    .line 80
    iget-boolean v10, p0, Lhg/y;->j:Z

    .line 81
    .line 82
    invoke-direct/range {v3 .. v10}, Lhg/b;-><init>(Ljava/util/ArrayList;ZZZZLjava/lang/String;Z)V

    .line 83
    .line 84
    .line 85
    new-instance p0, Lhg/k;

    .line 86
    .line 87
    invoke-direct {p0, v1, v0, v3}, Lhg/k;-><init>(Ljava/lang/String;ZLhg/b;)V

    .line 88
    .line 89
    .line 90
    return-object p0

    .line 91
    :cond_4
    :goto_3
    new-instance p0, Lhg/l;

    .line 92
    .line 93
    invoke-direct {p0, v1, v0, v3, v2}, Lhg/l;-><init>(Ljava/lang/String;ZZLhg/c;)V

    .line 94
    .line 95
    .line 96
    return-object p0
.end method

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
    instance-of v1, p1, Lhg/y;

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
    check-cast p1, Lhg/y;

    .line 12
    .line 13
    iget-boolean v1, p0, Lhg/y;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lhg/y;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lhg/y;->b:Lhg/c;

    .line 21
    .line 22
    iget-object v3, p1, Lhg/y;->b:Lhg/c;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lhg/y;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lhg/y;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Lhg/y;->d:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v3, p1, Lhg/y;->d:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Lhg/y;->e:Ljava/util/List;

    .line 50
    .line 51
    iget-object v3, p1, Lhg/y;->e:Ljava/util/List;

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
    iget-boolean v1, p0, Lhg/y;->f:Z

    .line 61
    .line 62
    iget-boolean v3, p1, Lhg/y;->f:Z

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Lhg/y;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Lhg/y;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean v1, p0, Lhg/y;->h:Z

    .line 75
    .line 76
    iget-boolean v3, p1, Lhg/y;->h:Z

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-object v1, p0, Lhg/y;->i:Ljava/lang/String;

    .line 82
    .line 83
    iget-object v3, p1, Lhg/y;->i:Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-nez v1, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-boolean p0, p0, Lhg/y;->j:Z

    .line 93
    .line 94
    iget-boolean p1, p1, Lhg/y;->j:Z

    .line 95
    .line 96
    if-eq p0, p1, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lhg/y;->a:Z

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lhg/y;->b:Lhg/c;

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
    invoke-virtual {v3}, Lhg/c;->hashCode()I

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
    iget-boolean v3, p0, Lhg/y;->c:Z

    .line 24
    .line 25
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object v3, p0, Lhg/y;->d:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object v3, p0, Lhg/y;->e:Ljava/util/List;

    .line 36
    .line 37
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-boolean v3, p0, Lhg/y;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iget-boolean v3, p0, Lhg/y;->g:Z

    .line 48
    .line 49
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-boolean v3, p0, Lhg/y;->h:Z

    .line 54
    .line 55
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-object v3, p0, Lhg/y;->i:Ljava/lang/String;

    .line 60
    .line 61
    if-nez v3, :cond_1

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    :goto_1
    add-int/2addr v0, v2

    .line 69
    mul-int/2addr v0, v1

    .line 70
    iget-boolean p0, p0, Lhg/y;->j:Z

    .line 71
    .line 72
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    add-int/2addr p0, v0

    .line 77
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "RemoteStartViewModelState(isFetchingScreenInfo="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Lhg/y;->a:Z

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", error="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lhg/y;->b:Lhg/c;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", hasActiveChargingSession="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", evseId="

    .line 29
    .line 30
    const-string v2, ", pricingList="

    .line 31
    .line 32
    iget-object v3, p0, Lhg/y;->d:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean v4, p0, Lhg/y;->c:Z

    .line 35
    .line 36
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isRemoteStartPending="

    .line 40
    .line 41
    const-string v2, ", isStartCtaEnabled="

    .line 42
    .line 43
    iget-object v3, p0, Lhg/y;->e:Ljava/util/List;

    .line 44
    .line 45
    iget-boolean v4, p0, Lhg/y;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, ", isHowToChargeSheetVisible="

    .line 51
    .line 52
    const-string v2, ", priceExpiresAtText="

    .line 53
    .line 54
    iget-boolean v3, p0, Lhg/y;->g:Z

    .line 55
    .line 56
    iget-boolean v4, p0, Lhg/y;->h:Z

    .line 57
    .line 58
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v1, ", showPriceUpdatedToast="

    .line 62
    .line 63
    const-string v2, ")"

    .line 64
    .line 65
    iget-object v3, p0, Lhg/y;->i:Ljava/lang/String;

    .line 66
    .line 67
    iget-boolean p0, p0, Lhg/y;->j:Z

    .line 68
    .line 69
    invoke-static {v3, v1, v2, v0, p0}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method
