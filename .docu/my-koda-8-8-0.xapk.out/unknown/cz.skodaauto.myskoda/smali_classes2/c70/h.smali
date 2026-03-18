.class public final Lc70/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ler0/g;

.field public final b:Llf0/i;

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/Integer;

.field public final g:Lb70/c;

.field public final h:Llp/mb;

.field public final i:Lqr0/s;

.field public final j:Z

.field public final k:Ljava/time/OffsetDateTime;

.field public final l:Z

.field public final m:Z


# direct methods
.method public constructor <init>(Ler0/g;Llf0/i;ZZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;)V
    .locals 1

    .line 1
    const-string v0, "subscriptionLicenseState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewMode"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "preferredUnits"

    .line 12
    .line 13
    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lc70/h;->a:Ler0/g;

    .line 20
    .line 21
    iput-object p2, p0, Lc70/h;->b:Llf0/i;

    .line 22
    .line 23
    iput-boolean p3, p0, Lc70/h;->c:Z

    .line 24
    .line 25
    iput-boolean p4, p0, Lc70/h;->d:Z

    .line 26
    .line 27
    iput-object p5, p0, Lc70/h;->e:Ljava/lang/String;

    .line 28
    .line 29
    iput-object p6, p0, Lc70/h;->f:Ljava/lang/Integer;

    .line 30
    .line 31
    iput-object p7, p0, Lc70/h;->g:Lb70/c;

    .line 32
    .line 33
    iput-object p8, p0, Lc70/h;->h:Llp/mb;

    .line 34
    .line 35
    iput-object p9, p0, Lc70/h;->i:Lqr0/s;

    .line 36
    .line 37
    iput-boolean p10, p0, Lc70/h;->j:Z

    .line 38
    .line 39
    iput-object p11, p0, Lc70/h;->k:Ljava/time/OffsetDateTime;

    .line 40
    .line 41
    sget-object p1, Llf0/i;->h:Llf0/i;

    .line 42
    .line 43
    if-ne p2, p1, :cond_0

    .line 44
    .line 45
    const/4 p1, 0x1

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 p1, 0x0

    .line 48
    :goto_0
    iput-boolean p1, p0, Lc70/h;->l:Z

    .line 49
    .line 50
    invoke-static {p2}, Llp/tf;->d(Llf0/i;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    iput-boolean p1, p0, Lc70/h;->m:Z

    .line 55
    .line 56
    return-void
.end method

.method public static a(Lc70/h;Ler0/g;Llf0/i;ZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;I)Lc70/h;
    .locals 12

    .line 1
    move/from16 v0, p11

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lc70/h;->a:Ler0/g;

    .line 8
    .line 9
    :cond_0
    move-object v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p2, p0, Lc70/h;->b:Llf0/i;

    .line 15
    .line 16
    :cond_1
    move-object v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-boolean p1, p0, Lc70/h;->c:Z

    .line 22
    .line 23
    :goto_0
    move v3, p1

    .line 24
    goto :goto_1

    .line 25
    :cond_2
    const/4 p1, 0x0

    .line 26
    goto :goto_0

    .line 27
    :goto_1
    and-int/lit8 p1, v0, 0x8

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    iget-boolean p3, p0, Lc70/h;->d:Z

    .line 32
    .line 33
    :cond_3
    move v4, p3

    .line 34
    and-int/lit8 p1, v0, 0x10

    .line 35
    .line 36
    if-eqz p1, :cond_4

    .line 37
    .line 38
    iget-object p1, p0, Lc70/h;->e:Ljava/lang/String;

    .line 39
    .line 40
    move-object v5, p1

    .line 41
    goto :goto_2

    .line 42
    :cond_4
    move-object/from16 v5, p4

    .line 43
    .line 44
    :goto_2
    and-int/lit8 p1, v0, 0x20

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    iget-object p1, p0, Lc70/h;->f:Ljava/lang/Integer;

    .line 49
    .line 50
    move-object v6, p1

    .line 51
    goto :goto_3

    .line 52
    :cond_5
    move-object/from16 v6, p5

    .line 53
    .line 54
    :goto_3
    and-int/lit8 p1, v0, 0x40

    .line 55
    .line 56
    if-eqz p1, :cond_6

    .line 57
    .line 58
    iget-object p1, p0, Lc70/h;->g:Lb70/c;

    .line 59
    .line 60
    move-object v7, p1

    .line 61
    goto :goto_4

    .line 62
    :cond_6
    move-object/from16 v7, p6

    .line 63
    .line 64
    :goto_4
    and-int/lit16 p1, v0, 0x80

    .line 65
    .line 66
    if-eqz p1, :cond_7

    .line 67
    .line 68
    iget-object p1, p0, Lc70/h;->h:Llp/mb;

    .line 69
    .line 70
    move-object v8, p1

    .line 71
    goto :goto_5

    .line 72
    :cond_7
    move-object/from16 v8, p7

    .line 73
    .line 74
    :goto_5
    and-int/lit16 p1, v0, 0x100

    .line 75
    .line 76
    if-eqz p1, :cond_8

    .line 77
    .line 78
    iget-object p1, p0, Lc70/h;->i:Lqr0/s;

    .line 79
    .line 80
    move-object v9, p1

    .line 81
    goto :goto_6

    .line 82
    :cond_8
    move-object/from16 v9, p8

    .line 83
    .line 84
    :goto_6
    and-int/lit16 p1, v0, 0x200

    .line 85
    .line 86
    if-eqz p1, :cond_9

    .line 87
    .line 88
    iget-boolean p1, p0, Lc70/h;->j:Z

    .line 89
    .line 90
    move v10, p1

    .line 91
    goto :goto_7

    .line 92
    :cond_9
    move/from16 v10, p9

    .line 93
    .line 94
    :goto_7
    and-int/lit16 p1, v0, 0x400

    .line 95
    .line 96
    if-eqz p1, :cond_a

    .line 97
    .line 98
    iget-object p1, p0, Lc70/h;->k:Ljava/time/OffsetDateTime;

    .line 99
    .line 100
    move-object v11, p1

    .line 101
    goto :goto_8

    .line 102
    :cond_a
    move-object/from16 v11, p10

    .line 103
    .line 104
    :goto_8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    const-string p0, "subscriptionLicenseState"

    .line 108
    .line 109
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    const-string p0, "viewMode"

    .line 113
    .line 114
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string p0, "preferredUnits"

    .line 118
    .line 119
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    new-instance v0, Lc70/h;

    .line 123
    .line 124
    invoke-direct/range {v0 .. v11}, Lc70/h;-><init>(Ler0/g;Llf0/i;ZZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;)V

    .line 125
    .line 126
    .line 127
    return-object v0
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
    instance-of v1, p1, Lc70/h;

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
    check-cast p1, Lc70/h;

    .line 12
    .line 13
    iget-object v1, p0, Lc70/h;->a:Ler0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lc70/h;->a:Ler0/g;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lc70/h;->b:Llf0/i;

    .line 21
    .line 22
    iget-object v3, p1, Lc70/h;->b:Llf0/i;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lc70/h;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lc70/h;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lc70/h;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lc70/h;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lc70/h;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v3, p1, Lc70/h;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lc70/h;->f:Ljava/lang/Integer;

    .line 53
    .line 54
    iget-object v3, p1, Lc70/h;->f:Ljava/lang/Integer;

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
    iget-object v1, p0, Lc70/h;->g:Lb70/c;

    .line 64
    .line 65
    iget-object v3, p1, Lc70/h;->g:Lb70/c;

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-object v1, p0, Lc70/h;->h:Llp/mb;

    .line 71
    .line 72
    iget-object v3, p1, Lc70/h;->h:Llp/mb;

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
    iget-object v1, p0, Lc70/h;->i:Lqr0/s;

    .line 82
    .line 83
    iget-object v3, p1, Lc70/h;->i:Lqr0/s;

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-boolean v1, p0, Lc70/h;->j:Z

    .line 89
    .line 90
    iget-boolean v3, p1, Lc70/h;->j:Z

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-object p0, p0, Lc70/h;->k:Ljava/time/OffsetDateTime;

    .line 96
    .line 97
    iget-object p1, p1, Lc70/h;->k:Ljava/time/OffsetDateTime;

    .line 98
    .line 99
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    if-nez p0, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lc70/h;->a:Ler0/g;

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
    iget-object v2, p0, Lc70/h;->b:Llf0/i;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-boolean v0, p0, Lc70/h;->c:Z

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-boolean v2, p0, Lc70/h;->d:Z

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    iget-object v3, p0, Lc70/h;->e:Ljava/lang/String;

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
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_0
    add-int/2addr v0, v3

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-object v3, p0, Lc70/h;->f:Ljava/lang/Integer;

    .line 44
    .line 45
    if-nez v3, :cond_1

    .line 46
    .line 47
    move v3, v2

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_1
    add-int/2addr v0, v3

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object v3, p0, Lc70/h;->g:Lb70/c;

    .line 56
    .line 57
    if-nez v3, :cond_2

    .line 58
    .line 59
    move v3, v2

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    :goto_2
    add-int/2addr v0, v3

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-object v3, p0, Lc70/h;->h:Llp/mb;

    .line 68
    .line 69
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    add-int/2addr v3, v0

    .line 74
    mul-int/2addr v3, v1

    .line 75
    iget-object v0, p0, Lc70/h;->i:Lqr0/s;

    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    add-int/2addr v0, v3

    .line 82
    mul-int/2addr v0, v1

    .line 83
    iget-boolean v3, p0, Lc70/h;->j:Z

    .line 84
    .line 85
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    iget-object p0, p0, Lc70/h;->k:Ljava/time/OffsetDateTime;

    .line 90
    .line 91
    if-nez p0, :cond_3

    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_3
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    :goto_3
    add-int/2addr v0, v2

    .line 99
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(subscriptionLicenseState="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc70/h;->a:Ler0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", viewMode="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lc70/h;->b:Llf0/i;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isRangeIceLoading="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isRefreshing="

    .line 29
    .line 30
    const-string v2, ", statusInfoText="

    .line 31
    .line 32
    iget-boolean v3, p0, Lc70/h;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lc70/h;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lc70/h;->e:Ljava/lang/String;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", goToMapSearchTitleId="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Lc70/h;->f:Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", goToMapSearchFeature="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Lc70/h;->g:Lb70/c;

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", gaugeState="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lc70/h;->h:Llp/mb;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", preferredUnits="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lc70/h;->i:Lqr0/s;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", cantMove="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-boolean v1, p0, Lc70/h;->j:Z

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v1, ", lastUpdateTimestamp="

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    iget-object p0, p0, Lc70/h;->k:Ljava/time/OffsetDateTime;

    .line 100
    .line 101
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string p0, ")"

    .line 105
    .line 106
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0
.end method
