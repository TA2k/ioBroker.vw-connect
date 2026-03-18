.class public final Ltz/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lrd0/n;

.field public final f:Ljava/lang/String;

.field public final g:I

.field public final h:Ljava/util/List;

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Z


# direct methods
.method public constructor <init>(ZZZZLrd0/n;Ljava/lang/String;ILjava/util/List;ZZZZ)V
    .locals 1

    .line 1
    const-string v0, "chargingList"

    .line 2
    .line 3
    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-boolean p1, p0, Ltz/z0;->a:Z

    .line 10
    .line 11
    iput-boolean p2, p0, Ltz/z0;->b:Z

    .line 12
    .line 13
    iput-boolean p3, p0, Ltz/z0;->c:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Ltz/z0;->d:Z

    .line 16
    .line 17
    iput-object p5, p0, Ltz/z0;->e:Lrd0/n;

    .line 18
    .line 19
    iput-object p6, p0, Ltz/z0;->f:Ljava/lang/String;

    .line 20
    .line 21
    iput p7, p0, Ltz/z0;->g:I

    .line 22
    .line 23
    iput-object p8, p0, Ltz/z0;->h:Ljava/util/List;

    .line 24
    .line 25
    iput-boolean p9, p0, Ltz/z0;->i:Z

    .line 26
    .line 27
    iput-boolean p10, p0, Ltz/z0;->j:Z

    .line 28
    .line 29
    iput-boolean p11, p0, Ltz/z0;->k:Z

    .line 30
    .line 31
    iput-boolean p12, p0, Ltz/z0;->l:Z

    .line 32
    .line 33
    return-void
.end method

.method public static a(Ltz/z0;ZZZZLrd0/n;Ljava/lang/String;ILjava/util/List;ZZZZI)Ltz/z0;
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
    iget-boolean p1, p0, Ltz/z0;->a:Z

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
    iget-boolean p2, p0, Ltz/z0;->b:Z

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
    iget-boolean p1, p0, Ltz/z0;->c:Z

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
    iget-boolean p1, p0, Ltz/z0;->d:Z

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
    iget-object p1, p0, Ltz/z0;->e:Lrd0/n;

    .line 42
    .line 43
    move-object v5, p1

    .line 44
    goto :goto_2

    .line 45
    :cond_4
    move-object/from16 v5, p5

    .line 46
    .line 47
    :goto_2
    and-int/lit8 p1, v0, 0x20

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    iget-object p1, p0, Ltz/z0;->f:Ljava/lang/String;

    .line 52
    .line 53
    move-object v6, p1

    .line 54
    goto :goto_3

    .line 55
    :cond_5
    move-object/from16 v6, p6

    .line 56
    .line 57
    :goto_3
    and-int/lit8 p1, v0, 0x40

    .line 58
    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    iget p1, p0, Ltz/z0;->g:I

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
    iget-object p1, p0, Ltz/z0;->h:Ljava/util/List;

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
    iget-boolean p1, p0, Ltz/z0;->i:Z

    .line 82
    .line 83
    move v9, p1

    .line 84
    goto :goto_6

    .line 85
    :cond_8
    move/from16 v9, p9

    .line 86
    .line 87
    :goto_6
    and-int/lit16 p1, v0, 0x200

    .line 88
    .line 89
    if-eqz p1, :cond_9

    .line 90
    .line 91
    iget-boolean p1, p0, Ltz/z0;->j:Z

    .line 92
    .line 93
    move v10, p1

    .line 94
    goto :goto_7

    .line 95
    :cond_9
    move/from16 v10, p10

    .line 96
    .line 97
    :goto_7
    and-int/lit16 p1, v0, 0x400

    .line 98
    .line 99
    if-eqz p1, :cond_a

    .line 100
    .line 101
    iget-boolean p1, p0, Ltz/z0;->k:Z

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
    iget-boolean p1, p0, Ltz/z0;->l:Z

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
    const-string p0, "chargingList"

    .line 121
    .line 122
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    new-instance v0, Ltz/z0;

    .line 126
    .line 127
    invoke-direct/range {v0 .. v12}, Ltz/z0;-><init>(ZZZZLrd0/n;Ljava/lang/String;ILjava/util/List;ZZZZ)V

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
    instance-of v1, p1, Ltz/z0;

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
    check-cast p1, Ltz/z0;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltz/z0;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltz/z0;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltz/z0;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltz/z0;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Ltz/z0;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Ltz/z0;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Ltz/z0;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Ltz/z0;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Ltz/z0;->e:Lrd0/n;

    .line 42
    .line 43
    iget-object v3, p1, Ltz/z0;->e:Lrd0/n;

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
    iget-object v1, p0, Ltz/z0;->f:Ljava/lang/String;

    .line 53
    .line 54
    iget-object v3, p1, Ltz/z0;->f:Ljava/lang/String;

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
    iget v1, p0, Ltz/z0;->g:I

    .line 64
    .line 65
    iget v3, p1, Ltz/z0;->g:I

    .line 66
    .line 67
    if-eq v1, v3, :cond_8

    .line 68
    .line 69
    return v2

    .line 70
    :cond_8
    iget-object v1, p0, Ltz/z0;->h:Ljava/util/List;

    .line 71
    .line 72
    iget-object v3, p1, Ltz/z0;->h:Ljava/util/List;

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
    iget-boolean v1, p0, Ltz/z0;->i:Z

    .line 82
    .line 83
    iget-boolean v3, p1, Ltz/z0;->i:Z

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-boolean v1, p0, Ltz/z0;->j:Z

    .line 89
    .line 90
    iget-boolean v3, p1, Ltz/z0;->j:Z

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-boolean v1, p0, Ltz/z0;->k:Z

    .line 96
    .line 97
    iget-boolean v3, p1, Ltz/z0;->k:Z

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget-boolean p0, p0, Ltz/z0;->l:Z

    .line 103
    .line 104
    iget-boolean p1, p1, Ltz/z0;->l:Z

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
    iget-boolean v0, p0, Ltz/z0;->a:Z

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
    iget-boolean v2, p0, Ltz/z0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltz/z0;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ltz/z0;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v2, 0x0

    .line 29
    iget-object v3, p0, Ltz/z0;->e:Lrd0/n;

    .line 30
    .line 31
    if-nez v3, :cond_0

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v3}, Lrd0/n;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_0
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Ltz/z0;->f:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v3, :cond_1

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    :goto_1
    add-int/2addr v0, v2

    .line 51
    mul-int/2addr v0, v1

    .line 52
    iget v2, p0, Ltz/z0;->g:I

    .line 53
    .line 54
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object v2, p0, Ltz/z0;->h:Ljava/util/List;

    .line 59
    .line 60
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    iget-boolean v2, p0, Ltz/z0;->i:Z

    .line 65
    .line 66
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    iget-boolean v2, p0, Ltz/z0;->j:Z

    .line 71
    .line 72
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    iget-boolean v2, p0, Ltz/z0;->k:Z

    .line 77
    .line 78
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    iget-boolean p0, p0, Ltz/z0;->l:Z

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
    .locals 5

    .line 1
    const-string v0, ", isRefreshing="

    .line 2
    .line 3
    const-string v1, ", fetchingHistoryFailed="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Ltz/z0;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Ltz/z0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isAtEnd="

    .line 16
    .line 17
    const-string v2, ", filter="

    .line 18
    .line 19
    iget-boolean v3, p0, Ltz/z0;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Ltz/z0;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Ltz/z0;->e:Lrd0/n;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", dateFilterChipText="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Ltz/z0;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", dateFilterPickerNegativeButtonResId="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget v1, p0, Ltz/z0;->g:I

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", chargingList="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Ltz/z0;->h:Ljava/util/List;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", shouldShowHistoryDisclaimer="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", isContextMenuVisible="

    .line 67
    .line 68
    const-string v2, ", isDateFilterPickerVisible="

    .line 69
    .line 70
    iget-boolean v3, p0, Ltz/z0;->i:Z

    .line 71
    .line 72
    iget-boolean v4, p0, Ltz/z0;->j:Z

    .line 73
    .line 74
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v1, ", isHistoryDisclaimerDetailVisible="

    .line 78
    .line 79
    const-string v2, ")"

    .line 80
    .line 81
    iget-boolean v3, p0, Ltz/z0;->k:Z

    .line 82
    .line 83
    iget-boolean p0, p0, Ltz/z0;->l:Z

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
