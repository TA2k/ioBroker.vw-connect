.class public final Lr80/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z

.field public final m:Ljava/lang/String;

.field public final n:Z

.field public final o:Z

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z


# direct methods
.method public constructor <init>(Lql0/g;ZZZZZZZZZZZLjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr80/e;->a:Lql0/g;

    .line 5
    .line 6
    iput-boolean p2, p0, Lr80/e;->b:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lr80/e;->c:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lr80/e;->d:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lr80/e;->e:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lr80/e;->f:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Lr80/e;->g:Z

    .line 17
    .line 18
    iput-boolean p8, p0, Lr80/e;->h:Z

    .line 19
    .line 20
    iput-boolean p9, p0, Lr80/e;->i:Z

    .line 21
    .line 22
    iput-boolean p10, p0, Lr80/e;->j:Z

    .line 23
    .line 24
    iput-boolean p11, p0, Lr80/e;->k:Z

    .line 25
    .line 26
    iput-boolean p12, p0, Lr80/e;->l:Z

    .line 27
    .line 28
    iput-object p13, p0, Lr80/e;->m:Ljava/lang/String;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    const/4 p13, 0x1

    .line 32
    if-eqz p3, :cond_0

    .line 33
    .line 34
    if-eqz p10, :cond_2

    .line 35
    .line 36
    :cond_0
    if-eqz p4, :cond_1

    .line 37
    .line 38
    if-eqz p11, :cond_2

    .line 39
    .line 40
    :cond_1
    if-eqz p5, :cond_3

    .line 41
    .line 42
    :cond_2
    move p5, p13

    .line 43
    goto :goto_0

    .line 44
    :cond_3
    move p5, p2

    .line 45
    :goto_0
    if-nez p6, :cond_5

    .line 46
    .line 47
    if-nez p7, :cond_5

    .line 48
    .line 49
    if-eqz p8, :cond_4

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_4
    move p6, p2

    .line 53
    goto :goto_2

    .line 54
    :cond_5
    :goto_1
    move p6, p13

    .line 55
    :goto_2
    iput-boolean p6, p0, Lr80/e;->n:Z

    .line 56
    .line 57
    if-eqz p3, :cond_7

    .line 58
    .line 59
    if-eqz p10, :cond_6

    .line 60
    .line 61
    if-eqz p5, :cond_7

    .line 62
    .line 63
    :cond_6
    move p3, p13

    .line 64
    goto :goto_3

    .line 65
    :cond_7
    move p3, p2

    .line 66
    :goto_3
    iput-boolean p3, p0, Lr80/e;->o:Z

    .line 67
    .line 68
    if-eqz p4, :cond_9

    .line 69
    .line 70
    if-eqz p11, :cond_8

    .line 71
    .line 72
    if-eqz p5, :cond_9

    .line 73
    .line 74
    :cond_8
    move p4, p13

    .line 75
    goto :goto_4

    .line 76
    :cond_9
    move p4, p2

    .line 77
    :goto_4
    iput-boolean p4, p0, Lr80/e;->p:Z

    .line 78
    .line 79
    if-nez p3, :cond_a

    .line 80
    .line 81
    if-nez p4, :cond_a

    .line 82
    .line 83
    if-nez p12, :cond_a

    .line 84
    .line 85
    move p3, p13

    .line 86
    goto :goto_5

    .line 87
    :cond_a
    move p3, p2

    .line 88
    :goto_5
    iput-boolean p3, p0, Lr80/e;->q:Z

    .line 89
    .line 90
    if-eqz p1, :cond_b

    .line 91
    .line 92
    if-nez p6, :cond_b

    .line 93
    .line 94
    if-eqz p3, :cond_b

    .line 95
    .line 96
    move p2, p13

    .line 97
    :cond_b
    iput-boolean p2, p0, Lr80/e;->r:Z

    .line 98
    .line 99
    xor-int/lit8 p1, p9, 0x1

    .line 100
    .line 101
    iput-boolean p1, p0, Lr80/e;->s:Z

    .line 102
    .line 103
    return-void
.end method

.method public static a(Lr80/e;Lql0/g;ZZZZZZZZZZZLjava/lang/String;I)Lr80/e;
    .locals 14

    .line 1
    move/from16 v0, p14

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lr80/e;->a:Lql0/g;

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
    iget-boolean p1, p0, Lr80/e;->b:Z

    .line 15
    .line 16
    move v2, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move/from16 v2, p2

    .line 19
    .line 20
    :goto_0
    and-int/lit8 p1, v0, 0x4

    .line 21
    .line 22
    if-eqz p1, :cond_2

    .line 23
    .line 24
    iget-boolean p1, p0, Lr80/e;->c:Z

    .line 25
    .line 26
    move v3, p1

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    move/from16 v3, p3

    .line 29
    .line 30
    :goto_1
    and-int/lit8 p1, v0, 0x8

    .line 31
    .line 32
    if-eqz p1, :cond_3

    .line 33
    .line 34
    iget-boolean p1, p0, Lr80/e;->d:Z

    .line 35
    .line 36
    move v4, p1

    .line 37
    goto :goto_2

    .line 38
    :cond_3
    move/from16 v4, p4

    .line 39
    .line 40
    :goto_2
    and-int/lit8 p1, v0, 0x10

    .line 41
    .line 42
    if-eqz p1, :cond_4

    .line 43
    .line 44
    iget-boolean p1, p0, Lr80/e;->e:Z

    .line 45
    .line 46
    move v5, p1

    .line 47
    goto :goto_3

    .line 48
    :cond_4
    move/from16 v5, p5

    .line 49
    .line 50
    :goto_3
    and-int/lit8 p1, v0, 0x20

    .line 51
    .line 52
    if-eqz p1, :cond_5

    .line 53
    .line 54
    iget-boolean p1, p0, Lr80/e;->f:Z

    .line 55
    .line 56
    move v6, p1

    .line 57
    goto :goto_4

    .line 58
    :cond_5
    move/from16 v6, p6

    .line 59
    .line 60
    :goto_4
    and-int/lit8 p1, v0, 0x40

    .line 61
    .line 62
    if-eqz p1, :cond_6

    .line 63
    .line 64
    iget-boolean p1, p0, Lr80/e;->g:Z

    .line 65
    .line 66
    move v7, p1

    .line 67
    goto :goto_5

    .line 68
    :cond_6
    move/from16 v7, p7

    .line 69
    .line 70
    :goto_5
    and-int/lit16 p1, v0, 0x80

    .line 71
    .line 72
    if-eqz p1, :cond_7

    .line 73
    .line 74
    iget-boolean p1, p0, Lr80/e;->h:Z

    .line 75
    .line 76
    move v8, p1

    .line 77
    goto :goto_6

    .line 78
    :cond_7
    move/from16 v8, p8

    .line 79
    .line 80
    :goto_6
    and-int/lit16 p1, v0, 0x100

    .line 81
    .line 82
    if-eqz p1, :cond_8

    .line 83
    .line 84
    iget-boolean p1, p0, Lr80/e;->i:Z

    .line 85
    .line 86
    move v9, p1

    .line 87
    goto :goto_7

    .line 88
    :cond_8
    move/from16 v9, p9

    .line 89
    .line 90
    :goto_7
    and-int/lit16 p1, v0, 0x200

    .line 91
    .line 92
    if-eqz p1, :cond_9

    .line 93
    .line 94
    iget-boolean p1, p0, Lr80/e;->j:Z

    .line 95
    .line 96
    move v10, p1

    .line 97
    goto :goto_8

    .line 98
    :cond_9
    move/from16 v10, p10

    .line 99
    .line 100
    :goto_8
    and-int/lit16 p1, v0, 0x400

    .line 101
    .line 102
    if-eqz p1, :cond_a

    .line 103
    .line 104
    iget-boolean p1, p0, Lr80/e;->k:Z

    .line 105
    .line 106
    move v11, p1

    .line 107
    goto :goto_9

    .line 108
    :cond_a
    move/from16 v11, p11

    .line 109
    .line 110
    :goto_9
    and-int/lit16 p1, v0, 0x800

    .line 111
    .line 112
    if-eqz p1, :cond_b

    .line 113
    .line 114
    iget-boolean p1, p0, Lr80/e;->l:Z

    .line 115
    .line 116
    move v12, p1

    .line 117
    goto :goto_a

    .line 118
    :cond_b
    move/from16 v12, p12

    .line 119
    .line 120
    :goto_a
    and-int/lit16 p1, v0, 0x1000

    .line 121
    .line 122
    if-eqz p1, :cond_c

    .line 123
    .line 124
    iget-object p1, p0, Lr80/e;->m:Ljava/lang/String;

    .line 125
    .line 126
    move-object v13, p1

    .line 127
    goto :goto_b

    .line 128
    :cond_c
    move-object/from16 v13, p13

    .line 129
    .line 130
    :goto_b
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    const-string p0, "webShopUrl"

    .line 134
    .line 135
    invoke-static {v13, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    new-instance v0, Lr80/e;

    .line 139
    .line 140
    invoke-direct/range {v0 .. v13}, Lr80/e;-><init>(Lql0/g;ZZZZZZZZZZZLjava/lang/String;)V

    .line 141
    .line 142
    .line 143
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
    instance-of v1, p1, Lr80/e;

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
    check-cast p1, Lr80/e;

    .line 12
    .line 13
    iget-object v1, p0, Lr80/e;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lr80/e;->a:Lql0/g;

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
    iget-boolean v1, p0, Lr80/e;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lr80/e;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lr80/e;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lr80/e;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Lr80/e;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lr80/e;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-boolean v1, p0, Lr80/e;->e:Z

    .line 46
    .line 47
    iget-boolean v3, p1, Lr80/e;->e:Z

    .line 48
    .line 49
    if-eq v1, v3, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-boolean v1, p0, Lr80/e;->f:Z

    .line 53
    .line 54
    iget-boolean v3, p1, Lr80/e;->f:Z

    .line 55
    .line 56
    if-eq v1, v3, :cond_7

    .line 57
    .line 58
    return v2

    .line 59
    :cond_7
    iget-boolean v1, p0, Lr80/e;->g:Z

    .line 60
    .line 61
    iget-boolean v3, p1, Lr80/e;->g:Z

    .line 62
    .line 63
    if-eq v1, v3, :cond_8

    .line 64
    .line 65
    return v2

    .line 66
    :cond_8
    iget-boolean v1, p0, Lr80/e;->h:Z

    .line 67
    .line 68
    iget-boolean v3, p1, Lr80/e;->h:Z

    .line 69
    .line 70
    if-eq v1, v3, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-boolean v1, p0, Lr80/e;->i:Z

    .line 74
    .line 75
    iget-boolean v3, p1, Lr80/e;->i:Z

    .line 76
    .line 77
    if-eq v1, v3, :cond_a

    .line 78
    .line 79
    return v2

    .line 80
    :cond_a
    iget-boolean v1, p0, Lr80/e;->j:Z

    .line 81
    .line 82
    iget-boolean v3, p1, Lr80/e;->j:Z

    .line 83
    .line 84
    if-eq v1, v3, :cond_b

    .line 85
    .line 86
    return v2

    .line 87
    :cond_b
    iget-boolean v1, p0, Lr80/e;->k:Z

    .line 88
    .line 89
    iget-boolean v3, p1, Lr80/e;->k:Z

    .line 90
    .line 91
    if-eq v1, v3, :cond_c

    .line 92
    .line 93
    return v2

    .line 94
    :cond_c
    iget-boolean v1, p0, Lr80/e;->l:Z

    .line 95
    .line 96
    iget-boolean v3, p1, Lr80/e;->l:Z

    .line 97
    .line 98
    if-eq v1, v3, :cond_d

    .line 99
    .line 100
    return v2

    .line 101
    :cond_d
    iget-object p0, p0, Lr80/e;->m:Ljava/lang/String;

    .line 102
    .line 103
    iget-object p1, p1, Lr80/e;->m:Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    if-nez p0, :cond_e

    .line 110
    .line 111
    return v2

    .line 112
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lr80/e;->a:Lql0/g;

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
    invoke-virtual {v0}, Lql0/g;->hashCode()I

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
    iget-boolean v2, p0, Lr80/e;->b:Z

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-boolean v2, p0, Lr80/e;->c:Z

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-boolean v2, p0, Lr80/e;->d:Z

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-boolean v2, p0, Lr80/e;->e:Z

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-boolean v2, p0, Lr80/e;->f:Z

    .line 39
    .line 40
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-boolean v2, p0, Lr80/e;->g:Z

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget-boolean v2, p0, Lr80/e;->h:Z

    .line 51
    .line 52
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget-boolean v2, p0, Lr80/e;->i:Z

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-boolean v2, p0, Lr80/e;->j:Z

    .line 63
    .line 64
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-boolean v2, p0, Lr80/e;->k:Z

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-boolean v2, p0, Lr80/e;->l:Z

    .line 75
    .line 76
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget-object p0, p0, Lr80/e;->m:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    add-int/2addr p0, v0

    .line 87
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isRefreshing="

    .line 2
    .line 3
    const-string v1, ", isSkodaServicesEnabled="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Lr80/e;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Lr80/e;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isCareAndInsuranceEnabled="

    .line 16
    .line 17
    const-string v2, ", isDataServicesEnabled="

    .line 18
    .line 19
    iget-boolean v3, p0, Lr80/e;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lr80/e;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", isSkodaServicesLoading="

    .line 27
    .line 28
    const-string v2, ", isCareAndInsuranceLoading="

    .line 29
    .line 30
    iget-boolean v3, p0, Lr80/e;->e:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Lr80/e;->f:Z

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", isPowerpassSubscriptionLoading="

    .line 38
    .line 39
    const-string v2, ", isPowerpassSubscriptionUnavailable="

    .line 40
    .line 41
    iget-boolean v3, p0, Lr80/e;->g:Z

    .line 42
    .line 43
    iget-boolean v4, p0, Lr80/e;->h:Z

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v1, ", isSkodaServicesDataUnavailable="

    .line 49
    .line 50
    const-string v2, ", isCareAndInsuranceDataUnavailable="

    .line 51
    .line 52
    iget-boolean v3, p0, Lr80/e;->i:Z

    .line 53
    .line 54
    iget-boolean v4, p0, Lr80/e;->j:Z

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const-string v1, ", isDataServicesVisible="

    .line 60
    .line 61
    const-string v2, ", webShopUrl="

    .line 62
    .line 63
    iget-boolean v3, p0, Lr80/e;->k:Z

    .line 64
    .line 65
    iget-boolean v4, p0, Lr80/e;->l:Z

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v1, ")"

    .line 71
    .line 72
    iget-object p0, p0, Lr80/e;->m:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0
.end method
