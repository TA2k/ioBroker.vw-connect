.class public final Lx31/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lq41/a;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/util/List;

.field public final f:Ljava/util/List;

.field public final g:Ljava/util/List;

.field public final h:Ljava/util/List;

.field public final i:Ljava/util/List;

.field public final j:Ljava/util/List;

.field public final k:Ljava/util/List;

.field public final l:Ll4/v;

.field public final m:I

.field public final n:Ljava/lang/String;


# direct methods
.method public constructor <init>(ZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lx31/o;->a:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lx31/o;->b:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lx31/o;->c:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lx31/o;->d:Z

    .line 11
    .line 12
    iput-object p5, p0, Lx31/o;->e:Ljava/util/List;

    .line 13
    .line 14
    iput-object p6, p0, Lx31/o;->f:Ljava/util/List;

    .line 15
    .line 16
    iput-object p7, p0, Lx31/o;->g:Ljava/util/List;

    .line 17
    .line 18
    iput-object p8, p0, Lx31/o;->h:Ljava/util/List;

    .line 19
    .line 20
    iput-object p9, p0, Lx31/o;->i:Ljava/util/List;

    .line 21
    .line 22
    iput-object p10, p0, Lx31/o;->j:Ljava/util/List;

    .line 23
    .line 24
    iput-object p11, p0, Lx31/o;->k:Ljava/util/List;

    .line 25
    .line 26
    iput-object p12, p0, Lx31/o;->l:Ll4/v;

    .line 27
    .line 28
    iput p13, p0, Lx31/o;->m:I

    .line 29
    .line 30
    iput-object p14, p0, Lx31/o;->n:Ljava/lang/String;

    .line 31
    .line 32
    return-void
.end method

.method public static a(Lx31/o;ZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Ll4/v;Ljava/lang/String;I)Lx31/o;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p13

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-boolean v2, v0, Lx31/o;->a:Z

    .line 10
    .line 11
    move v4, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move/from16 v4, p1

    .line 14
    .line 15
    :goto_0
    and-int/lit8 v2, v1, 0x2

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget-boolean v2, v0, Lx31/o;->b:Z

    .line 20
    .line 21
    move v5, v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move/from16 v5, p2

    .line 24
    .line 25
    :goto_1
    and-int/lit8 v2, v1, 0x4

    .line 26
    .line 27
    if-eqz v2, :cond_2

    .line 28
    .line 29
    iget-boolean v2, v0, Lx31/o;->c:Z

    .line 30
    .line 31
    move v6, v2

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move/from16 v6, p3

    .line 34
    .line 35
    :goto_2
    and-int/lit8 v2, v1, 0x8

    .line 36
    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    iget-boolean v2, v0, Lx31/o;->d:Z

    .line 40
    .line 41
    move v7, v2

    .line 42
    goto :goto_3

    .line 43
    :cond_3
    move/from16 v7, p4

    .line 44
    .line 45
    :goto_3
    and-int/lit8 v2, v1, 0x10

    .line 46
    .line 47
    if-eqz v2, :cond_4

    .line 48
    .line 49
    iget-object v2, v0, Lx31/o;->e:Ljava/util/List;

    .line 50
    .line 51
    move-object v8, v2

    .line 52
    goto :goto_4

    .line 53
    :cond_4
    move-object/from16 v8, p5

    .line 54
    .line 55
    :goto_4
    and-int/lit8 v2, v1, 0x20

    .line 56
    .line 57
    if-eqz v2, :cond_5

    .line 58
    .line 59
    iget-object v2, v0, Lx31/o;->f:Ljava/util/List;

    .line 60
    .line 61
    move-object v9, v2

    .line 62
    goto :goto_5

    .line 63
    :cond_5
    move-object/from16 v9, p6

    .line 64
    .line 65
    :goto_5
    and-int/lit8 v2, v1, 0x40

    .line 66
    .line 67
    if-eqz v2, :cond_6

    .line 68
    .line 69
    iget-object v2, v0, Lx31/o;->g:Ljava/util/List;

    .line 70
    .line 71
    move-object v10, v2

    .line 72
    goto :goto_6

    .line 73
    :cond_6
    move-object/from16 v10, p7

    .line 74
    .line 75
    :goto_6
    and-int/lit16 v2, v1, 0x80

    .line 76
    .line 77
    if-eqz v2, :cond_7

    .line 78
    .line 79
    iget-object v2, v0, Lx31/o;->h:Ljava/util/List;

    .line 80
    .line 81
    move-object v11, v2

    .line 82
    goto :goto_7

    .line 83
    :cond_7
    move-object/from16 v11, p8

    .line 84
    .line 85
    :goto_7
    and-int/lit16 v2, v1, 0x100

    .line 86
    .line 87
    if-eqz v2, :cond_8

    .line 88
    .line 89
    iget-object v2, v0, Lx31/o;->i:Ljava/util/List;

    .line 90
    .line 91
    move-object v12, v2

    .line 92
    goto :goto_8

    .line 93
    :cond_8
    move-object/from16 v12, p9

    .line 94
    .line 95
    :goto_8
    and-int/lit16 v2, v1, 0x200

    .line 96
    .line 97
    if-eqz v2, :cond_9

    .line 98
    .line 99
    iget-object v2, v0, Lx31/o;->j:Ljava/util/List;

    .line 100
    .line 101
    move-object v13, v2

    .line 102
    goto :goto_9

    .line 103
    :cond_9
    move-object/from16 v13, p10

    .line 104
    .line 105
    :goto_9
    iget-object v14, v0, Lx31/o;->k:Ljava/util/List;

    .line 106
    .line 107
    and-int/lit16 v2, v1, 0x800

    .line 108
    .line 109
    if-eqz v2, :cond_a

    .line 110
    .line 111
    iget-object v2, v0, Lx31/o;->l:Ll4/v;

    .line 112
    .line 113
    move-object v15, v2

    .line 114
    goto :goto_a

    .line 115
    :cond_a
    move-object/from16 v15, p11

    .line 116
    .line 117
    :goto_a
    and-int/lit16 v2, v1, 0x1000

    .line 118
    .line 119
    if-eqz v2, :cond_b

    .line 120
    .line 121
    iget v2, v0, Lx31/o;->m:I

    .line 122
    .line 123
    :goto_b
    move/from16 v16, v2

    .line 124
    .line 125
    goto :goto_c

    .line 126
    :cond_b
    const/16 v2, 0x5dc

    .line 127
    .line 128
    goto :goto_b

    .line 129
    :goto_c
    and-int/lit16 v1, v1, 0x2000

    .line 130
    .line 131
    if-eqz v1, :cond_c

    .line 132
    .line 133
    iget-object v1, v0, Lx31/o;->n:Ljava/lang/String;

    .line 134
    .line 135
    move-object/from16 v17, v1

    .line 136
    .line 137
    goto :goto_d

    .line 138
    :cond_c
    move-object/from16 v17, p12

    .line 139
    .line 140
    :goto_d
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    const-string v0, "allCategories"

    .line 144
    .line 145
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    const-string v0, "selectableWarnings"

    .line 149
    .line 150
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    const-string v0, "selectablePredictions"

    .line 154
    .line 155
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    new-instance v3, Lx31/o;

    .line 159
    .line 160
    invoke-direct/range {v3 .. v17}, Lx31/o;-><init>(ZZZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;ILjava/lang/String;)V

    .line 161
    .line 162
    .line 163
    return-object v3
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
    instance-of v1, p1, Lx31/o;

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
    check-cast p1, Lx31/o;

    .line 12
    .line 13
    iget-boolean v1, p0, Lx31/o;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lx31/o;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lx31/o;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lx31/o;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lx31/o;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lx31/o;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lx31/o;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lx31/o;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lx31/o;->e:Ljava/util/List;

    .line 42
    .line 43
    iget-object v3, p1, Lx31/o;->e:Ljava/util/List;

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
    iget-object v1, p0, Lx31/o;->f:Ljava/util/List;

    .line 53
    .line 54
    iget-object v3, p1, Lx31/o;->f:Ljava/util/List;

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
    iget-object v1, p0, Lx31/o;->g:Ljava/util/List;

    .line 64
    .line 65
    iget-object v3, p1, Lx31/o;->g:Ljava/util/List;

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
    iget-object v1, p0, Lx31/o;->h:Ljava/util/List;

    .line 75
    .line 76
    iget-object v3, p1, Lx31/o;->h:Ljava/util/List;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object v1, p0, Lx31/o;->i:Ljava/util/List;

    .line 86
    .line 87
    iget-object v3, p1, Lx31/o;->i:Ljava/util/List;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-object v1, p0, Lx31/o;->j:Ljava/util/List;

    .line 97
    .line 98
    iget-object v3, p1, Lx31/o;->j:Ljava/util/List;

    .line 99
    .line 100
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_b

    .line 105
    .line 106
    return v2

    .line 107
    :cond_b
    iget-object v1, p0, Lx31/o;->k:Ljava/util/List;

    .line 108
    .line 109
    iget-object v3, p1, Lx31/o;->k:Ljava/util/List;

    .line 110
    .line 111
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-nez v1, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object v1, p0, Lx31/o;->l:Ll4/v;

    .line 119
    .line 120
    iget-object v3, p1, Lx31/o;->l:Ll4/v;

    .line 121
    .line 122
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-nez v1, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    iget v1, p0, Lx31/o;->m:I

    .line 130
    .line 131
    iget v3, p1, Lx31/o;->m:I

    .line 132
    .line 133
    if-eq v1, v3, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget-object p0, p0, Lx31/o;->n:Ljava/lang/String;

    .line 137
    .line 138
    iget-object p1, p1, Lx31/o;->n:Ljava/lang/String;

    .line 139
    .line 140
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-nez p0, :cond_f

    .line 145
    .line 146
    return v2

    .line 147
    :cond_f
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lx31/o;->a:Z

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
    iget-boolean v2, p0, Lx31/o;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lx31/o;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lx31/o;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lx31/o;->e:Ljava/util/List;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lx31/o;->f:Ljava/util/List;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lx31/o;->g:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v2, p0, Lx31/o;->h:Ljava/util/List;

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v2, p0, Lx31/o;->i:Ljava/util/List;

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-object v2, p0, Lx31/o;->j:Ljava/util/List;

    .line 59
    .line 60
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    iget-object v2, p0, Lx31/o;->k:Ljava/util/List;

    .line 65
    .line 66
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    iget-object v2, p0, Lx31/o;->l:Ll4/v;

    .line 71
    .line 72
    invoke-virtual {v2}, Ll4/v;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    add-int/2addr v2, v0

    .line 77
    mul-int/2addr v2, v1

    .line 78
    iget v0, p0, Lx31/o;->m:I

    .line 79
    .line 80
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    iget-object p0, p0, Lx31/o;->n:Ljava/lang/String;

    .line 85
    .line 86
    if-nez p0, :cond_0

    .line 87
    .line 88
    const/4 p0, 0x0

    .line 89
    goto :goto_0

    .line 90
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    :goto_0
    add-int/2addr v0, p0

    .line 95
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isLoadingPredictions="

    .line 2
    .line 3
    const-string v1, ", isLoadingServices="

    .line 4
    .line 5
    const-string v2, "SBONewRequestViewState(isLoadingWarnings="

    .line 6
    .line 7
    iget-boolean v3, p0, Lx31/o;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lx31/o;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isBottomSheetOpen="

    .line 16
    .line 17
    const-string v2, ", allCategories="

    .line 18
    .line 19
    iget-boolean v3, p0, Lx31/o;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lx31/o;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", selectableWarnings="

    .line 27
    .line 28
    const-string v2, ", selectablePredictions="

    .line 29
    .line 30
    iget-object v3, p0, Lx31/o;->e:Ljava/util/List;

    .line 31
    .line 32
    iget-object v4, p0, Lx31/o;->f:Ljava/util/List;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v1, ", selectableServices="

    .line 38
    .line 39
    const-string v2, ", allSelectableServices="

    .line 40
    .line 41
    iget-object v3, p0, Lx31/o;->g:Ljava/util/List;

    .line 42
    .line 43
    iget-object v4, p0, Lx31/o;->h:Ljava/util/List;

    .line 44
    .line 45
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v1, ", firstFiveSelectableServices="

    .line 49
    .line 50
    const-string v2, ", selectedBottomSheetServices="

    .line 51
    .line 52
    iget-object v3, p0, Lx31/o;->i:Ljava/util/List;

    .line 53
    .line 54
    iget-object v4, p0, Lx31/o;->j:Ljava/util/List;

    .line 55
    .line 56
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Lx31/o;->k:Ljava/util/List;

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v1, ", inputText="

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lx31/o;->l:Ll4/v;

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", charsLimit="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget v1, p0, Lx31/o;->m:I

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", remainingCharsLabel="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Lx31/o;->n:Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
