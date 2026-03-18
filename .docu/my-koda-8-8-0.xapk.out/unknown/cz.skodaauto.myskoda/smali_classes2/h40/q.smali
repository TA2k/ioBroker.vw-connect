.class public final Lh40/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:I

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Ljava/util/List;

.field public final i:Ljava/util/List;

.field public final j:Ljava/util/List;

.field public final k:Z

.field public final l:Z


# direct methods
.method public constructor <init>(IZZZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;ZZ)V
    .locals 1

    const-string v0, "inProgressChallenges"

    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "toBeCompletedChallenges"

    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "accomplishedChallenges"

    invoke-static {p10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lh40/q;->a:I

    .line 3
    iput-boolean p2, p0, Lh40/q;->b:Z

    .line 4
    iput-boolean p3, p0, Lh40/q;->c:Z

    .line 5
    iput-boolean p4, p0, Lh40/q;->d:Z

    .line 6
    iput-boolean p5, p0, Lh40/q;->e:Z

    .line 7
    iput-boolean p6, p0, Lh40/q;->f:Z

    .line 8
    iput-boolean p7, p0, Lh40/q;->g:Z

    .line 9
    iput-object p8, p0, Lh40/q;->h:Ljava/util/List;

    .line 10
    iput-object p9, p0, Lh40/q;->i:Ljava/util/List;

    .line 11
    iput-object p10, p0, Lh40/q;->j:Ljava/util/List;

    .line 12
    iput-boolean p11, p0, Lh40/q;->k:Z

    .line 13
    iput-boolean p12, p0, Lh40/q;->l:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/List;Ljava/util/ArrayList;I)V
    .locals 17

    move/from16 v0, p4

    and-int/lit8 v1, v0, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eqz v1, :cond_0

    move v6, v3

    goto :goto_0

    :cond_0
    move v6, v2

    :goto_0
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_1

    move v8, v3

    goto :goto_1

    :cond_1
    move v8, v2

    :goto_1
    and-int/lit16 v1, v0, 0x80

    .line 14
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    if-eqz v1, :cond_2

    move-object v12, v2

    goto :goto_2

    :cond_2
    move-object/from16 v12, p1

    :goto_2
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_3

    move-object v13, v2

    goto :goto_3

    :cond_3
    move-object/from16 v13, p2

    :goto_3
    and-int/lit16 v0, v0, 0x200

    if-eqz v0, :cond_4

    move-object v14, v2

    goto :goto_4

    :cond_4
    move-object/from16 v14, p3

    :goto_4
    const/4 v15, 0x0

    const/16 v16, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x1

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object/from16 v4, p0

    invoke-direct/range {v4 .. v16}, Lh40/q;-><init>(IZZZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;ZZ)V

    return-void
.end method

.method public static a(Lh40/q;IZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;ZZI)Lh40/q;
    .locals 13

    .line 1
    move/from16 v0, p13

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget p1, p0, Lh40/q;->a:I

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
    iget-boolean p2, p0, Lh40/q;->b:Z

    .line 15
    .line 16
    :cond_1
    move v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-boolean p1, p0, Lh40/q;->c:Z

    .line 22
    .line 23
    move v3, p1

    .line 24
    goto :goto_0

    .line 25
    :cond_2
    move/from16 v3, p3

    .line 26
    .line 27
    :goto_0
    and-int/lit8 p1, v0, 0x8

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    iget-boolean p1, p0, Lh40/q;->d:Z

    .line 32
    .line 33
    move v4, p1

    .line 34
    goto :goto_1

    .line 35
    :cond_3
    move/from16 v4, p4

    .line 36
    .line 37
    :goto_1
    and-int/lit8 p1, v0, 0x10

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-boolean p1, p0, Lh40/q;->e:Z

    .line 42
    .line 43
    move v5, p1

    .line 44
    goto :goto_2

    .line 45
    :cond_4
    move/from16 v5, p5

    .line 46
    .line 47
    :goto_2
    and-int/lit8 p1, v0, 0x20

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget-boolean p1, p0, Lh40/q;->f:Z

    .line 52
    .line 53
    move v6, p1

    .line 54
    goto :goto_3

    .line 55
    :cond_5
    move/from16 v6, p6

    .line 56
    .line 57
    :goto_3
    and-int/lit8 p1, v0, 0x40

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget-boolean p1, p0, Lh40/q;->g:Z

    .line 62
    .line 63
    move v7, p1

    .line 64
    goto :goto_4

    .line 65
    :cond_6
    move/from16 v7, p7

    .line 66
    .line 67
    :goto_4
    and-int/lit16 p1, v0, 0x80

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    iget-object p1, p0, Lh40/q;->h:Ljava/util/List;

    .line 72
    .line 73
    move-object v8, p1

    .line 74
    goto :goto_5

    .line 75
    :cond_7
    move-object/from16 v8, p8

    .line 76
    .line 77
    :goto_5
    and-int/lit16 p1, v0, 0x100

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-object p1, p0, Lh40/q;->i:Ljava/util/List;

    .line 82
    .line 83
    move-object v9, p1

    .line 84
    goto :goto_6

    .line 85
    :cond_8
    move-object/from16 v9, p9

    .line 86
    .line 87
    :goto_6
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-object p1, p0, Lh40/q;->j:Ljava/util/List;

    .line 92
    .line 93
    move-object v10, p1

    .line 94
    goto :goto_7

    .line 95
    :cond_9
    move-object/from16 v10, p10

    .line 96
    .line 97
    :goto_7
    and-int/lit16 p1, v0, 0x400

    .line 98
    .line 99
    if-eqz p1, :cond_a

    .line 100
    .line 101
    iget-boolean p1, p0, Lh40/q;->k:Z

    .line 102
    .line 103
    move v11, p1

    .line 104
    goto :goto_8

    .line 105
    :cond_a
    move/from16 v11, p11

    .line 106
    .line 107
    :goto_8
    and-int/lit16 p1, v0, 0x800

    .line 108
    .line 109
    if-eqz p1, :cond_b

    .line 110
    .line 111
    iget-boolean p1, p0, Lh40/q;->l:Z

    .line 112
    .line 113
    move v12, p1

    .line 114
    goto :goto_9

    .line 115
    :cond_b
    move/from16 v12, p12

    .line 116
    .line 117
    :goto_9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const-string p0, "inProgressChallenges"

    .line 121
    .line 122
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    const-string p0, "toBeCompletedChallenges"

    .line 126
    .line 127
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    const-string p0, "accomplishedChallenges"

    .line 131
    .line 132
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    new-instance v0, Lh40/q;

    .line 136
    .line 137
    invoke-direct/range {v0 .. v12}, Lh40/q;-><init>(IZZZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;ZZ)V

    .line 138
    .line 139
    .line 140
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
    instance-of v1, p1, Lh40/q;

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
    check-cast p1, Lh40/q;

    .line 12
    .line 13
    iget v1, p0, Lh40/q;->a:I

    .line 14
    .line 15
    iget v3, p1, Lh40/q;->a:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lh40/q;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lh40/q;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lh40/q;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lh40/q;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lh40/q;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lh40/q;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean v1, p0, Lh40/q;->e:Z

    .line 42
    .line 43
    iget-boolean v3, p1, Lh40/q;->e:Z

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Lh40/q;->f:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Lh40/q;->f:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-boolean v1, p0, Lh40/q;->g:Z

    .line 56
    .line 57
    iget-boolean v3, p1, Lh40/q;->g:Z

    .line 58
    .line 59
    if-eq v1, v3, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    iget-object v1, p0, Lh40/q;->h:Ljava/util/List;

    .line 63
    .line 64
    iget-object v3, p1, Lh40/q;->h:Ljava/util/List;

    .line 65
    .line 66
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-nez v1, :cond_9

    .line 71
    .line 72
    return v2

    .line 73
    :cond_9
    iget-object v1, p0, Lh40/q;->i:Ljava/util/List;

    .line 74
    .line 75
    iget-object v3, p1, Lh40/q;->i:Ljava/util/List;

    .line 76
    .line 77
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_a

    .line 82
    .line 83
    return v2

    .line 84
    :cond_a
    iget-object v1, p0, Lh40/q;->j:Ljava/util/List;

    .line 85
    .line 86
    iget-object v3, p1, Lh40/q;->j:Ljava/util/List;

    .line 87
    .line 88
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-nez v1, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-boolean v1, p0, Lh40/q;->k:Z

    .line 96
    .line 97
    iget-boolean v3, p1, Lh40/q;->k:Z

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget-boolean p0, p0, Lh40/q;->l:Z

    .line 103
    .line 104
    iget-boolean p1, p1, Lh40/q;->l:Z

    .line 105
    .line 106
    if-eq p0, p1, :cond_d

    .line 107
    .line 108
    return v2

    .line 109
    :cond_d
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lh40/q;->a:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

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
    iget-boolean v2, p0, Lh40/q;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lh40/q;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lh40/q;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Lh40/q;->e:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lh40/q;->f:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Lh40/q;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lh40/q;->h:Ljava/util/List;

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Lh40/q;->i:Ljava/util/List;

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object v2, p0, Lh40/q;->j:Ljava/util/List;

    .line 59
    .line 60
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    iget-boolean v2, p0, Lh40/q;->k:Z

    .line 65
    .line 66
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    iget-boolean p0, p0, Lh40/q;->l:Z

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
    const-string v1, "State(accountPointBalance="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lh40/q;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", isLoading="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lh40/q;->b:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isRefreshing="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isDataUnavailable="

    .line 29
    .line 30
    const-string v2, ", isToBeCompletedChallengesExpanded="

    .line 31
    .line 32
    iget-boolean v3, p0, Lh40/q;->c:Z

    .line 33
    .line 34
    iget-boolean v4, p0, Lh40/q;->d:Z

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ", isAccomplishedChallengesExpanded="

    .line 40
    .line 41
    const-string v2, ", isChallengeStarting="

    .line 42
    .line 43
    iget-boolean v3, p0, Lh40/q;->e:Z

    .line 44
    .line 45
    iget-boolean v4, p0, Lh40/q;->f:Z

    .line 46
    .line 47
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iget-boolean v1, p0, Lh40/q;->g:Z

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v1, ", inProgressChallenges="

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Lh40/q;->h:Ljava/util/List;

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string v1, ", toBeCompletedChallenges="

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, ", accomplishedChallenges="

    .line 71
    .line 72
    const-string v2, ", dailyCheckInCollected="

    .line 73
    .line 74
    iget-object v3, p0, Lh40/q;->i:Ljava/util/List;

    .line 75
    .line 76
    iget-object v4, p0, Lh40/q;->j:Ljava/util/List;

    .line 77
    .line 78
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string v1, ", isPreferredServicePartnerLoading="

    .line 82
    .line 83
    const-string v2, ")"

    .line 84
    .line 85
    iget-boolean v3, p0, Lh40/q;->k:Z

    .line 86
    .line 87
    iget-boolean p0, p0, Lh40/q;->l:Z

    .line 88
    .line 89
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method
