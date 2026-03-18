.class public final Lq40/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lon0/j;

.field public final b:Ljava/lang/String;

.field public final c:Lon0/x;

.field public final d:Lon0/z;

.field public final e:Lon0/w;

.field public final f:Ljava/util/List;

.field public final g:Ljava/util/List;

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:Lql0/g;

.field public final m:Ler0/g;

.field public final n:Lqr0/s;

.field public final o:Z


# direct methods
.method public constructor <init>(Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/List;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;)V
    .locals 1

    .line 1
    const-string v0, "subscriptionLicenseState"

    .line 2
    .line 3
    invoke-static {p13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lq40/d;->a:Lon0/j;

    .line 10
    .line 11
    iput-object p2, p0, Lq40/d;->b:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p3, p0, Lq40/d;->c:Lon0/x;

    .line 14
    .line 15
    iput-object p4, p0, Lq40/d;->d:Lon0/z;

    .line 16
    .line 17
    iput-object p5, p0, Lq40/d;->e:Lon0/w;

    .line 18
    .line 19
    iput-object p6, p0, Lq40/d;->f:Ljava/util/List;

    .line 20
    .line 21
    iput-object p7, p0, Lq40/d;->g:Ljava/util/List;

    .line 22
    .line 23
    iput-boolean p8, p0, Lq40/d;->h:Z

    .line 24
    .line 25
    iput-boolean p9, p0, Lq40/d;->i:Z

    .line 26
    .line 27
    iput-boolean p10, p0, Lq40/d;->j:Z

    .line 28
    .line 29
    iput-boolean p11, p0, Lq40/d;->k:Z

    .line 30
    .line 31
    iput-object p12, p0, Lq40/d;->l:Lql0/g;

    .line 32
    .line 33
    iput-object p13, p0, Lq40/d;->m:Ler0/g;

    .line 34
    .line 35
    iput-object p14, p0, Lq40/d;->n:Lqr0/s;

    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    if-nez p4, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    check-cast p7, Ljava/util/Collection;

    .line 42
    .line 43
    invoke-interface {p7}, Ljava/util/Collection;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-nez p2, :cond_1

    .line 48
    .line 49
    if-nez p5, :cond_1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    const/4 p1, 0x1

    .line 53
    :goto_0
    iput-boolean p1, p0, Lq40/d;->o:Z

    .line 54
    .line 55
    return-void
.end method

.method public static a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;
    .locals 14

    .line 1
    move/from16 v0, p15

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lq40/d;->a:Lon0/j;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v1, p1

    .line 11
    :goto_0
    and-int/lit8 v2, v0, 0x2

    .line 12
    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    iget-object v2, p0, Lq40/d;->b:Ljava/lang/String;

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    move-object/from16 v2, p2

    .line 19
    .line 20
    :goto_1
    and-int/lit8 v3, v0, 0x4

    .line 21
    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    iget-object v3, p0, Lq40/d;->c:Lon0/x;

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_2
    move-object/from16 v3, p3

    .line 28
    .line 29
    :goto_2
    and-int/lit8 v4, v0, 0x8

    .line 30
    .line 31
    if-eqz v4, :cond_3

    .line 32
    .line 33
    iget-object v4, p0, Lq40/d;->d:Lon0/z;

    .line 34
    .line 35
    goto :goto_3

    .line 36
    :cond_3
    move-object/from16 v4, p4

    .line 37
    .line 38
    :goto_3
    and-int/lit8 v5, v0, 0x10

    .line 39
    .line 40
    if-eqz v5, :cond_4

    .line 41
    .line 42
    iget-object v5, p0, Lq40/d;->e:Lon0/w;

    .line 43
    .line 44
    goto :goto_4

    .line 45
    :cond_4
    move-object/from16 v5, p5

    .line 46
    .line 47
    :goto_4
    and-int/lit8 v6, v0, 0x20

    .line 48
    .line 49
    if-eqz v6, :cond_5

    .line 50
    .line 51
    iget-object v6, p0, Lq40/d;->f:Ljava/util/List;

    .line 52
    .line 53
    goto :goto_5

    .line 54
    :cond_5
    move-object/from16 v6, p6

    .line 55
    .line 56
    :goto_5
    and-int/lit8 v7, v0, 0x40

    .line 57
    .line 58
    if-eqz v7, :cond_6

    .line 59
    .line 60
    iget-object v7, p0, Lq40/d;->g:Ljava/util/List;

    .line 61
    .line 62
    goto :goto_6

    .line 63
    :cond_6
    move-object/from16 v7, p7

    .line 64
    .line 65
    :goto_6
    and-int/lit16 v8, v0, 0x80

    .line 66
    .line 67
    if-eqz v8, :cond_7

    .line 68
    .line 69
    iget-boolean v8, p0, Lq40/d;->h:Z

    .line 70
    .line 71
    goto :goto_7

    .line 72
    :cond_7
    move/from16 v8, p8

    .line 73
    .line 74
    :goto_7
    and-int/lit16 v9, v0, 0x100

    .line 75
    .line 76
    if-eqz v9, :cond_8

    .line 77
    .line 78
    iget-boolean v9, p0, Lq40/d;->i:Z

    .line 79
    .line 80
    goto :goto_8

    .line 81
    :cond_8
    move/from16 v9, p9

    .line 82
    .line 83
    :goto_8
    and-int/lit16 v10, v0, 0x200

    .line 84
    .line 85
    if-eqz v10, :cond_9

    .line 86
    .line 87
    iget-boolean v10, p0, Lq40/d;->j:Z

    .line 88
    .line 89
    goto :goto_9

    .line 90
    :cond_9
    move/from16 v10, p10

    .line 91
    .line 92
    :goto_9
    and-int/lit16 v11, v0, 0x400

    .line 93
    .line 94
    if-eqz v11, :cond_a

    .line 95
    .line 96
    iget-boolean v11, p0, Lq40/d;->k:Z

    .line 97
    .line 98
    goto :goto_a

    .line 99
    :cond_a
    move/from16 v11, p11

    .line 100
    .line 101
    :goto_a
    and-int/lit16 v12, v0, 0x800

    .line 102
    .line 103
    if-eqz v12, :cond_b

    .line 104
    .line 105
    iget-object v12, p0, Lq40/d;->l:Lql0/g;

    .line 106
    .line 107
    goto :goto_b

    .line 108
    :cond_b
    move-object/from16 v12, p12

    .line 109
    .line 110
    :goto_b
    and-int/lit16 v13, v0, 0x1000

    .line 111
    .line 112
    if-eqz v13, :cond_c

    .line 113
    .line 114
    iget-object v13, p0, Lq40/d;->m:Ler0/g;

    .line 115
    .line 116
    goto :goto_c

    .line 117
    :cond_c
    move-object/from16 v13, p13

    .line 118
    .line 119
    :goto_c
    and-int/lit16 v0, v0, 0x2000

    .line 120
    .line 121
    if-eqz v0, :cond_d

    .line 122
    .line 123
    iget-object v0, p0, Lq40/d;->n:Lqr0/s;

    .line 124
    .line 125
    goto :goto_d

    .line 126
    :cond_d
    move-object/from16 v0, p14

    .line 127
    .line 128
    :goto_d
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    const-string p0, "standOptions"

    .line 132
    .line 133
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const-string p0, "fuelOptions"

    .line 137
    .line 138
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const-string p0, "subscriptionLicenseState"

    .line 142
    .line 143
    invoke-static {v13, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    const-string p0, "fuelUnitType"

    .line 147
    .line 148
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    new-instance p0, Lq40/d;

    .line 152
    .line 153
    move-object/from16 p14, v0

    .line 154
    .line 155
    move-object p1, v1

    .line 156
    move-object/from16 p2, v2

    .line 157
    .line 158
    move-object/from16 p3, v3

    .line 159
    .line 160
    move-object/from16 p4, v4

    .line 161
    .line 162
    move-object/from16 p5, v5

    .line 163
    .line 164
    move-object/from16 p6, v6

    .line 165
    .line 166
    move-object/from16 p7, v7

    .line 167
    .line 168
    move/from16 p8, v8

    .line 169
    .line 170
    move/from16 p9, v9

    .line 171
    .line 172
    move/from16 p10, v10

    .line 173
    .line 174
    move/from16 p11, v11

    .line 175
    .line 176
    move-object/from16 p12, v12

    .line 177
    .line 178
    move-object/from16 p13, v13

    .line 179
    .line 180
    invoke-direct/range {p0 .. p14}, Lq40/d;-><init>(Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/List;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;)V

    .line 181
    .line 182
    .line 183
    return-object p0
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
    instance-of v1, p1, Lq40/d;

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
    check-cast p1, Lq40/d;

    .line 12
    .line 13
    iget-object v1, p0, Lq40/d;->a:Lon0/j;

    .line 14
    .line 15
    iget-object v3, p1, Lq40/d;->a:Lon0/j;

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
    iget-object v1, p0, Lq40/d;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lq40/d;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lq40/d;->c:Lon0/x;

    .line 36
    .line 37
    iget-object v3, p1, Lq40/d;->c:Lon0/x;

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
    iget-object v1, p0, Lq40/d;->d:Lon0/z;

    .line 47
    .line 48
    iget-object v3, p1, Lq40/d;->d:Lon0/z;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lq40/d;->e:Lon0/w;

    .line 58
    .line 59
    iget-object v3, p1, Lq40/d;->e:Lon0/w;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lq40/d;->f:Ljava/util/List;

    .line 69
    .line 70
    iget-object v3, p1, Lq40/d;->f:Ljava/util/List;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lq40/d;->g:Ljava/util/List;

    .line 80
    .line 81
    iget-object v3, p1, Lq40/d;->g:Ljava/util/List;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-boolean v1, p0, Lq40/d;->h:Z

    .line 91
    .line 92
    iget-boolean v3, p1, Lq40/d;->h:Z

    .line 93
    .line 94
    if-eq v1, v3, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-boolean v1, p0, Lq40/d;->i:Z

    .line 98
    .line 99
    iget-boolean v3, p1, Lq40/d;->i:Z

    .line 100
    .line 101
    if-eq v1, v3, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-boolean v1, p0, Lq40/d;->j:Z

    .line 105
    .line 106
    iget-boolean v3, p1, Lq40/d;->j:Z

    .line 107
    .line 108
    if-eq v1, v3, :cond_b

    .line 109
    .line 110
    return v2

    .line 111
    :cond_b
    iget-boolean v1, p0, Lq40/d;->k:Z

    .line 112
    .line 113
    iget-boolean v3, p1, Lq40/d;->k:Z

    .line 114
    .line 115
    if-eq v1, v3, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object v1, p0, Lq40/d;->l:Lql0/g;

    .line 119
    .line 120
    iget-object v3, p1, Lq40/d;->l:Lql0/g;

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
    iget-object v1, p0, Lq40/d;->m:Ler0/g;

    .line 130
    .line 131
    iget-object v3, p1, Lq40/d;->m:Ler0/g;

    .line 132
    .line 133
    if-eq v1, v3, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget-object p0, p0, Lq40/d;->n:Lqr0/s;

    .line 137
    .line 138
    iget-object p1, p1, Lq40/d;->n:Lqr0/s;

    .line 139
    .line 140
    if-eq p0, p1, :cond_f

    .line 141
    .line 142
    return v2

    .line 143
    :cond_f
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lq40/d;->a:Lon0/j;

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
    invoke-virtual {v1}, Lon0/j;->hashCode()I

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
    iget-object v3, p0, Lq40/d;->b:Ljava/lang/String;

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
    iget-object v3, p0, Lq40/d;->c:Lon0/x;

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
    invoke-virtual {v3}, Lon0/x;->hashCode()I

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
    iget-object v3, p0, Lq40/d;->d:Lon0/z;

    .line 40
    .line 41
    if-nez v3, :cond_3

    .line 42
    .line 43
    move v3, v0

    .line 44
    goto :goto_3

    .line 45
    :cond_3
    invoke-virtual {v3}, Lon0/z;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    :goto_3
    add-int/2addr v1, v3

    .line 50
    mul-int/2addr v1, v2

    .line 51
    iget-object v3, p0, Lq40/d;->e:Lon0/w;

    .line 52
    .line 53
    if-nez v3, :cond_4

    .line 54
    .line 55
    move v3, v0

    .line 56
    goto :goto_4

    .line 57
    :cond_4
    invoke-virtual {v3}, Lon0/w;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    :goto_4
    add-int/2addr v1, v3

    .line 62
    mul-int/2addr v1, v2

    .line 63
    iget-object v3, p0, Lq40/d;->f:Ljava/util/List;

    .line 64
    .line 65
    invoke-static {v1, v2, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    iget-object v3, p0, Lq40/d;->g:Ljava/util/List;

    .line 70
    .line 71
    invoke-static {v1, v2, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    iget-boolean v3, p0, Lq40/d;->h:Z

    .line 76
    .line 77
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    iget-boolean v3, p0, Lq40/d;->i:Z

    .line 82
    .line 83
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    iget-boolean v3, p0, Lq40/d;->j:Z

    .line 88
    .line 89
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    iget-boolean v3, p0, Lq40/d;->k:Z

    .line 94
    .line 95
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    iget-object v3, p0, Lq40/d;->l:Lql0/g;

    .line 100
    .line 101
    if-nez v3, :cond_5

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_5
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    :goto_5
    add-int/2addr v1, v0

    .line 109
    mul-int/2addr v1, v2

    .line 110
    iget-object v0, p0, Lq40/d;->m:Ler0/g;

    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    add-int/2addr v0, v1

    .line 117
    mul-int/2addr v0, v2

    .line 118
    iget-object p0, p0, Lq40/d;->n:Lqr0/s;

    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result p0

    .line 124
    add-int/2addr p0, v0

    .line 125
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(address="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lq40/d;->a:Lon0/j;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", locationId="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lq40/d;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", station="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lq40/d;->c:Lon0/x;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", selectedStand="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lq40/d;->d:Lon0/z;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", selectedFuel="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lq40/d;->e:Lon0/w;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", standOptions="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lq40/d;->f:Ljava/util/List;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", fuelOptions="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ", showExpiredPaymentCardDialog="

    .line 69
    .line 70
    const-string v2, ", showStandSelect="

    .line 71
    .line 72
    iget-object v3, p0, Lq40/d;->g:Ljava/util/List;

    .line 73
    .line 74
    iget-boolean v4, p0, Lq40/d;->h:Z

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-string v1, ", showFuelSelect="

    .line 80
    .line 81
    const-string v2, ", loading="

    .line 82
    .line 83
    iget-boolean v3, p0, Lq40/d;->i:Z

    .line 84
    .line 85
    iget-boolean v4, p0, Lq40/d;->j:Z

    .line 86
    .line 87
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iget-boolean v1, p0, Lq40/d;->k:Z

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v1, ", error="

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    iget-object v1, p0, Lq40/d;->l:Lql0/g;

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", subscriptionLicenseState="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    iget-object v1, p0, Lq40/d;->m:Ler0/g;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v1, ", fuelUnitType="

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    iget-object p0, p0, Lq40/d;->n:Lqr0/s;

    .line 121
    .line 122
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    const-string p0, ")"

    .line 126
    .line 127
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0
.end method
