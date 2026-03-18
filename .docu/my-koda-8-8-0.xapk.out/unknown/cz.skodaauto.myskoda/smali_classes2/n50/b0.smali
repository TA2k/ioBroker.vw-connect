.class public final Ln50/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Lql0/g;

.field public final d:Ln50/a0;

.field public final e:Z

.field public final f:Z

.field public final g:Ln50/z;

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z


# direct methods
.method public synthetic constructor <init>(Ln50/a0;I)V
    .locals 14

    and-int/lit8 v0, p2, 0x1

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    :goto_0
    move v2, v0

    goto :goto_1

    :cond_0
    const/4 v0, 0x0

    goto :goto_0

    :goto_1
    and-int/lit8 v0, p2, 0x8

    if-eqz v0, :cond_1

    const/4 p1, 0x0

    :cond_1
    move-object v5, p1

    .line 14
    new-instance v8, Ln50/z;

    .line 15
    const-string p1, ""

    .line 16
    sget-object v0, Ler0/g;->d:Ler0/g;

    .line 17
    invoke-direct {v8, v0, p1, p1}, Ln50/z;-><init>(Ler0/g;Ljava/lang/String;Ljava/lang/String;)V

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object v1, p0

    .line 18
    invoke-direct/range {v1 .. v13}, Ln50/b0;-><init>(ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZZ)V

    return-void
.end method

.method public constructor <init>(ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Ln50/b0;->a:Z

    .line 3
    iput-boolean p2, p0, Ln50/b0;->b:Z

    .line 4
    iput-object p3, p0, Ln50/b0;->c:Lql0/g;

    .line 5
    iput-object p4, p0, Ln50/b0;->d:Ln50/a0;

    .line 6
    iput-boolean p5, p0, Ln50/b0;->e:Z

    .line 7
    iput-boolean p6, p0, Ln50/b0;->f:Z

    .line 8
    iput-object p7, p0, Ln50/b0;->g:Ln50/z;

    .line 9
    iput-boolean p8, p0, Ln50/b0;->h:Z

    .line 10
    iput-boolean p9, p0, Ln50/b0;->i:Z

    .line 11
    iput-boolean p10, p0, Ln50/b0;->j:Z

    .line 12
    iput-boolean p11, p0, Ln50/b0;->k:Z

    .line 13
    iput-boolean p12, p0, Ln50/b0;->l:Z

    return-void
.end method

.method public static a(Ln50/b0;ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZI)Ln50/b0;
    .locals 13

    .line 1
    move/from16 v0, p12

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-boolean p1, p0, Ln50/b0;->a:Z

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
    iget-boolean p2, p0, Ln50/b0;->b:Z

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
    iget-object p1, p0, Ln50/b0;->c:Lql0/g;

    .line 22
    .line 23
    move-object v3, p1

    .line 24
    goto :goto_0

    .line 25
    :cond_2
    move-object/from16 v3, p3

    .line 26
    .line 27
    :goto_0
    and-int/lit8 p1, v0, 0x8

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    iget-object p1, p0, Ln50/b0;->d:Ln50/a0;

    .line 32
    .line 33
    move-object v4, p1

    .line 34
    goto :goto_1

    .line 35
    :cond_3
    move-object/from16 v4, p4

    .line 36
    .line 37
    :goto_1
    and-int/lit8 p1, v0, 0x10

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-boolean p1, p0, Ln50/b0;->e:Z

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
    iget-boolean p1, p0, Ln50/b0;->f:Z

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
    iget-object p1, p0, Ln50/b0;->g:Ln50/z;

    .line 62
    .line 63
    move-object v7, p1

    .line 64
    goto :goto_4

    .line 65
    :cond_6
    move-object/from16 v7, p7

    .line 66
    .line 67
    :goto_4
    and-int/lit16 p1, v0, 0x80

    .line 68
    .line 69
    if-eqz p1, :cond_7

    .line 70
    .line 71
    iget-boolean p1, p0, Ln50/b0;->h:Z

    .line 72
    .line 73
    move v8, p1

    .line 74
    goto :goto_5

    .line 75
    :cond_7
    move/from16 v8, p8

    .line 76
    .line 77
    :goto_5
    and-int/lit16 p1, v0, 0x100

    .line 78
    .line 79
    if-eqz p1, :cond_8

    .line 80
    .line 81
    iget-boolean p1, p0, Ln50/b0;->i:Z

    .line 82
    .line 83
    :goto_6
    move v9, p1

    .line 84
    goto :goto_7

    .line 85
    :cond_8
    const/4 p1, 0x0

    .line 86
    goto :goto_6

    .line 87
    :goto_7
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-boolean p1, p0, Ln50/b0;->j:Z

    .line 92
    .line 93
    move v10, p1

    .line 94
    goto :goto_8

    .line 95
    :cond_9
    move/from16 v10, p9

    .line 96
    .line 97
    :goto_8
    and-int/lit16 p1, v0, 0x400

    .line 98
    .line 99
    if-eqz p1, :cond_a

    .line 100
    .line 101
    iget-boolean p1, p0, Ln50/b0;->k:Z

    .line 102
    .line 103
    move v11, p1

    .line 104
    goto :goto_9

    .line 105
    :cond_a
    move/from16 v11, p10

    .line 106
    .line 107
    :goto_9
    and-int/lit16 p1, v0, 0x800

    .line 108
    .line 109
    if-eqz p1, :cond_b

    .line 110
    .line 111
    iget-boolean p1, p0, Ln50/b0;->l:Z

    .line 112
    .line 113
    move v12, p1

    .line 114
    goto :goto_a

    .line 115
    :cond_b
    move/from16 v12, p11

    .line 116
    .line 117
    :goto_a
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const-string p0, "destinationsLicense"

    .line 121
    .line 122
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    new-instance v0, Ln50/b0;

    .line 126
    .line 127
    invoke-direct/range {v0 .. v12}, Ln50/b0;-><init>(ZZLql0/g;Ln50/a0;ZZLn50/z;ZZZZZ)V

    .line 128
    .line 129
    .line 130
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
    instance-of v1, p1, Ln50/b0;

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
    check-cast p1, Ln50/b0;

    .line 12
    .line 13
    iget-boolean v1, p0, Ln50/b0;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ln50/b0;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ln50/b0;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ln50/b0;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ln50/b0;->c:Lql0/g;

    .line 28
    .line 29
    iget-object v3, p1, Ln50/b0;->c:Lql0/g;

    .line 30
    .line 31
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Ln50/b0;->d:Ln50/a0;

    .line 39
    .line 40
    iget-object v3, p1, Ln50/b0;->d:Ln50/a0;

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
    iget-boolean v1, p0, Ln50/b0;->e:Z

    .line 50
    .line 51
    iget-boolean v3, p1, Ln50/b0;->e:Z

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-boolean v1, p0, Ln50/b0;->f:Z

    .line 57
    .line 58
    iget-boolean v3, p1, Ln50/b0;->f:Z

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Ln50/b0;->g:Ln50/z;

    .line 64
    .line 65
    iget-object v3, p1, Ln50/b0;->g:Ln50/z;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-boolean v1, p0, Ln50/b0;->h:Z

    .line 75
    .line 76
    iget-boolean v3, p1, Ln50/b0;->h:Z

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-boolean v1, p0, Ln50/b0;->i:Z

    .line 82
    .line 83
    iget-boolean v3, p1, Ln50/b0;->i:Z

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-boolean v1, p0, Ln50/b0;->j:Z

    .line 89
    .line 90
    iget-boolean v3, p1, Ln50/b0;->j:Z

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-boolean v1, p0, Ln50/b0;->k:Z

    .line 96
    .line 97
    iget-boolean v3, p1, Ln50/b0;->k:Z

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget-boolean p0, p0, Ln50/b0;->l:Z

    .line 103
    .line 104
    iget-boolean p1, p1, Ln50/b0;->l:Z

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
    .locals 4

    .line 1
    iget-boolean v0, p0, Ln50/b0;->a:Z

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
    iget-boolean v2, p0, Ln50/b0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Ln50/b0;->c:Lql0/g;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    move v3, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    add-int/2addr v0, v3

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object v3, p0, Ln50/b0;->d:Ln50/a0;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    invoke-virtual {v3}, Ln50/a0;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    :goto_1
    add-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget-boolean v2, p0, Ln50/b0;->e:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Ln50/b0;->f:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Ln50/b0;->g:Ln50/z;

    .line 53
    .line 54
    invoke-virtual {v2}, Ln50/z;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    add-int/2addr v2, v0

    .line 59
    mul-int/2addr v2, v1

    .line 60
    iget-boolean v0, p0, Ln50/b0;->h:Z

    .line 61
    .line 62
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iget-boolean v2, p0, Ln50/b0;->i:Z

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iget-boolean v2, p0, Ln50/b0;->j:Z

    .line 73
    .line 74
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-boolean v2, p0, Ln50/b0;->k:Z

    .line 79
    .line 80
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    iget-boolean p0, p0, Ln50/b0;->l:Z

    .line 85
    .line 86
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    add-int/2addr p0, v0

    .line 91
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isError="

    .line 2
    .line 3
    const-string v1, ", error="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Ln50/b0;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Ln50/b0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Ln50/b0;->c:Lql0/g;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", detail="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Ln50/b0;->d:Ln50/a0;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", isPrivateModeDialogVisible="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", isSendingPoiToCar="

    .line 36
    .line 37
    const-string v2, ", destinationsLicense="

    .line 38
    .line 39
    iget-boolean v3, p0, Ln50/b0;->e:Z

    .line 40
    .line 41
    iget-boolean v4, p0, Ln50/b0;->f:Z

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Ln50/b0;->g:Ln50/z;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", showBottomSheet="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-boolean v1, p0, Ln50/b0;->h:Z

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", hideBottomSheet="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", isRefreshing="

    .line 67
    .line 68
    const-string v2, ", isFavouriteAnimating="

    .line 69
    .line 70
    iget-boolean v3, p0, Ln50/b0;->i:Z

    .line 71
    .line 72
    iget-boolean v4, p0, Ln50/b0;->j:Z

    .line 73
    .line 74
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v1, ", isFavouriteEnabled="

    .line 78
    .line 79
    const-string v2, ")"

    .line 80
    .line 81
    iget-boolean v3, p0, Ln50/b0;->k:Z

    .line 82
    .line 83
    iget-boolean p0, p0, Ln50/b0;->l:Z

    .line 84
    .line 85
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0
.end method
