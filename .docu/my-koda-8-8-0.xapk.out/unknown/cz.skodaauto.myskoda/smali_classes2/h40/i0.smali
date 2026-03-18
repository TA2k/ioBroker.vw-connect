.class public final Lh40/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Ljava/lang/String;

.field public final d:Z

.field public final e:Ljava/net/URL;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Lg40/l;

.field public final j:Lg40/k;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/time/OffsetDateTime;

.field public final m:Ljava/lang/String;

.field public final n:Z

.field public final o:Ljava/lang/String;

.field public final p:Z

.field public final q:Z


# direct methods
.method public constructor <init>(Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh40/i0;->a:Lql0/g;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh40/i0;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh40/i0;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh40/i0;->d:Z

    .line 11
    .line 12
    iput-object p5, p0, Lh40/i0;->e:Ljava/net/URL;

    .line 13
    .line 14
    iput-object p6, p0, Lh40/i0;->f:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lh40/i0;->g:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lh40/i0;->h:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p9, p0, Lh40/i0;->i:Lg40/l;

    .line 21
    .line 22
    iput-object p10, p0, Lh40/i0;->j:Lg40/k;

    .line 23
    .line 24
    iput-object p11, p0, Lh40/i0;->k:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p12, p0, Lh40/i0;->l:Ljava/time/OffsetDateTime;

    .line 27
    .line 28
    iput-object p13, p0, Lh40/i0;->m:Ljava/lang/String;

    .line 29
    .line 30
    iput-boolean p14, p0, Lh40/i0;->n:Z

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    if-eqz p12, :cond_0

    .line 34
    .line 35
    invoke-static {p12}, Lvo/a;->g(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    move-object p2, p1

    .line 41
    :goto_0
    iput-object p2, p0, Lh40/i0;->o:Ljava/lang/String;

    .line 42
    .line 43
    const/4 p2, 0x0

    .line 44
    const/4 p3, 0x1

    .line 45
    if-eqz p11, :cond_2

    .line 46
    .line 47
    if-eqz p9, :cond_1

    .line 48
    .line 49
    iget-object p4, p9, Lg40/l;->a:Lg40/m;

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    move-object p4, p1

    .line 53
    :goto_1
    sget-object p5, Lg40/m;->d:Lg40/m;

    .line 54
    .line 55
    if-ne p4, p5, :cond_2

    .line 56
    .line 57
    move p4, p3

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    move p4, p2

    .line 60
    :goto_2
    iput-boolean p4, p0, Lh40/i0;->p:Z

    .line 61
    .line 62
    if-eqz p9, :cond_3

    .line 63
    .line 64
    iget-object p1, p9, Lg40/l;->a:Lg40/m;

    .line 65
    .line 66
    :cond_3
    sget-object p4, Lg40/m;->f:Lg40/m;

    .line 67
    .line 68
    if-ne p1, p4, :cond_4

    .line 69
    .line 70
    move p2, p3

    .line 71
    :cond_4
    iput-boolean p2, p0, Lh40/i0;->q:Z

    .line 72
    .line 73
    return-void
.end method

.method public static a(Lh40/i0;Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;ZI)Lh40/i0;
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
    iget-object v1, p0, Lh40/i0;->a:Lql0/g;

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
    iget-boolean v2, p0, Lh40/i0;->b:Z

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    move/from16 v2, p2

    .line 19
    .line 20
    :goto_1
    and-int/lit8 v3, v0, 0x4

    .line 21
    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    iget-object v3, p0, Lh40/i0;->c:Ljava/lang/String;

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
    iget-boolean v4, p0, Lh40/i0;->d:Z

    .line 34
    .line 35
    goto :goto_3

    .line 36
    :cond_3
    move/from16 v4, p4

    .line 37
    .line 38
    :goto_3
    and-int/lit8 v5, v0, 0x10

    .line 39
    .line 40
    if-eqz v5, :cond_4

    .line 41
    .line 42
    iget-object v5, p0, Lh40/i0;->e:Ljava/net/URL;

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
    iget-object v6, p0, Lh40/i0;->f:Ljava/lang/String;

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
    iget-object v7, p0, Lh40/i0;->g:Ljava/lang/String;

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
    iget-object v8, p0, Lh40/i0;->h:Ljava/lang/String;

    .line 70
    .line 71
    goto :goto_7

    .line 72
    :cond_7
    move-object/from16 v8, p8

    .line 73
    .line 74
    :goto_7
    and-int/lit16 v9, v0, 0x100

    .line 75
    .line 76
    if-eqz v9, :cond_8

    .line 77
    .line 78
    iget-object v9, p0, Lh40/i0;->i:Lg40/l;

    .line 79
    .line 80
    goto :goto_8

    .line 81
    :cond_8
    move-object/from16 v9, p9

    .line 82
    .line 83
    :goto_8
    and-int/lit16 v10, v0, 0x200

    .line 84
    .line 85
    if-eqz v10, :cond_9

    .line 86
    .line 87
    iget-object v10, p0, Lh40/i0;->j:Lg40/k;

    .line 88
    .line 89
    goto :goto_9

    .line 90
    :cond_9
    move-object/from16 v10, p10

    .line 91
    .line 92
    :goto_9
    and-int/lit16 v11, v0, 0x400

    .line 93
    .line 94
    if-eqz v11, :cond_a

    .line 95
    .line 96
    iget-object v11, p0, Lh40/i0;->k:Ljava/lang/String;

    .line 97
    .line 98
    goto :goto_a

    .line 99
    :cond_a
    move-object/from16 v11, p11

    .line 100
    .line 101
    :goto_a
    and-int/lit16 v12, v0, 0x800

    .line 102
    .line 103
    if-eqz v12, :cond_b

    .line 104
    .line 105
    iget-object v12, p0, Lh40/i0;->l:Ljava/time/OffsetDateTime;

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
    iget-object v13, p0, Lh40/i0;->m:Ljava/lang/String;

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
    iget-boolean v0, p0, Lh40/i0;->n:Z

    .line 124
    .line 125
    goto :goto_d

    .line 126
    :cond_d
    move/from16 v0, p14

    .line 127
    .line 128
    :goto_d
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    const-string p0, "badgeId"

    .line 132
    .line 133
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const-string p0, "title"

    .line 137
    .line 138
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const-string p0, "description"

    .line 142
    .line 143
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    const-string p0, "disclaimer"

    .line 147
    .line 148
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    new-instance p0, Lh40/i0;

    .line 152
    .line 153
    move/from16 p14, v0

    .line 154
    .line 155
    move-object p1, v1

    .line 156
    move/from16 p2, v2

    .line 157
    .line 158
    move-object/from16 p3, v3

    .line 159
    .line 160
    move/from16 p4, v4

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
    move-object/from16 p8, v8

    .line 169
    .line 170
    move-object/from16 p9, v9

    .line 171
    .line 172
    move-object/from16 p10, v10

    .line 173
    .line 174
    move-object/from16 p11, v11

    .line 175
    .line 176
    move-object/from16 p12, v12

    .line 177
    .line 178
    move-object/from16 p13, v13

    .line 179
    .line 180
    invoke-direct/range {p0 .. p14}, Lh40/i0;-><init>(Lql0/g;ZLjava/lang/String;ZLjava/net/URL;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/l;Lg40/k;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Z)V

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
    instance-of v1, p1, Lh40/i0;

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
    check-cast p1, Lh40/i0;

    .line 12
    .line 13
    iget-object v1, p0, Lh40/i0;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lh40/i0;->a:Lql0/g;

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
    iget-boolean v1, p0, Lh40/i0;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lh40/i0;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lh40/i0;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lh40/i0;->c:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-boolean v1, p0, Lh40/i0;->d:Z

    .line 43
    .line 44
    iget-boolean v3, p1, Lh40/i0;->d:Z

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Lh40/i0;->e:Ljava/net/URL;

    .line 50
    .line 51
    iget-object v3, p1, Lh40/i0;->e:Ljava/net/URL;

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
    iget-object v1, p0, Lh40/i0;->f:Ljava/lang/String;

    .line 61
    .line 62
    iget-object v3, p1, Lh40/i0;->f:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object v1, p0, Lh40/i0;->g:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v3, p1, Lh40/i0;->g:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-nez v1, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Lh40/i0;->h:Ljava/lang/String;

    .line 83
    .line 84
    iget-object v3, p1, Lh40/i0;->h:Ljava/lang/String;

    .line 85
    .line 86
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-nez v1, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-object v1, p0, Lh40/i0;->i:Lg40/l;

    .line 94
    .line 95
    iget-object v3, p1, Lh40/i0;->i:Lg40/l;

    .line 96
    .line 97
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-object v1, p0, Lh40/i0;->j:Lg40/k;

    .line 105
    .line 106
    iget-object v3, p1, Lh40/i0;->j:Lg40/k;

    .line 107
    .line 108
    if-eq v1, v3, :cond_b

    .line 109
    .line 110
    return v2

    .line 111
    :cond_b
    iget-object v1, p0, Lh40/i0;->k:Ljava/lang/String;

    .line 112
    .line 113
    iget-object v3, p1, Lh40/i0;->k:Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    if-nez v1, :cond_c

    .line 120
    .line 121
    return v2

    .line 122
    :cond_c
    iget-object v1, p0, Lh40/i0;->l:Ljava/time/OffsetDateTime;

    .line 123
    .line 124
    iget-object v3, p1, Lh40/i0;->l:Ljava/time/OffsetDateTime;

    .line 125
    .line 126
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-nez v1, :cond_d

    .line 131
    .line 132
    return v2

    .line 133
    :cond_d
    iget-object v1, p0, Lh40/i0;->m:Ljava/lang/String;

    .line 134
    .line 135
    iget-object v3, p1, Lh40/i0;->m:Ljava/lang/String;

    .line 136
    .line 137
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-nez v1, :cond_e

    .line 142
    .line 143
    return v2

    .line 144
    :cond_e
    iget-boolean p0, p0, Lh40/i0;->n:Z

    .line 145
    .line 146
    iget-boolean p1, p1, Lh40/i0;->n:Z

    .line 147
    .line 148
    if-eq p0, p1, :cond_f

    .line 149
    .line 150
    return v2

    .line 151
    :cond_f
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lh40/i0;->a:Lql0/g;

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
    invoke-virtual {v1}, Lql0/g;->hashCode()I

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
    iget-boolean v3, p0, Lh40/i0;->b:Z

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-object v3, p0, Lh40/i0;->c:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-boolean v3, p0, Lh40/i0;->d:Z

    .line 28
    .line 29
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    iget-object v3, p0, Lh40/i0;->e:Ljava/net/URL;

    .line 34
    .line 35
    if-nez v3, :cond_1

    .line 36
    .line 37
    move v3, v0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    invoke-virtual {v3}, Ljava/net/URL;->hashCode()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    :goto_1
    add-int/2addr v1, v3

    .line 44
    mul-int/2addr v1, v2

    .line 45
    iget-object v3, p0, Lh40/i0;->f:Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    iget-object v3, p0, Lh40/i0;->g:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget-object v3, p0, Lh40/i0;->h:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    iget-object v3, p0, Lh40/i0;->i:Lg40/l;

    .line 64
    .line 65
    if-nez v3, :cond_2

    .line 66
    .line 67
    move v3, v0

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    invoke-virtual {v3}, Lg40/l;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    :goto_2
    add-int/2addr v1, v3

    .line 74
    mul-int/2addr v1, v2

    .line 75
    iget-object v3, p0, Lh40/i0;->j:Lg40/k;

    .line 76
    .line 77
    if-nez v3, :cond_3

    .line 78
    .line 79
    move v3, v0

    .line 80
    goto :goto_3

    .line 81
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    :goto_3
    add-int/2addr v1, v3

    .line 86
    mul-int/2addr v1, v2

    .line 87
    iget-object v3, p0, Lh40/i0;->k:Ljava/lang/String;

    .line 88
    .line 89
    if-nez v3, :cond_4

    .line 90
    .line 91
    move v3, v0

    .line 92
    goto :goto_4

    .line 93
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    :goto_4
    add-int/2addr v1, v3

    .line 98
    mul-int/2addr v1, v2

    .line 99
    iget-object v3, p0, Lh40/i0;->l:Ljava/time/OffsetDateTime;

    .line 100
    .line 101
    if-nez v3, :cond_5

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_5
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

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
    iget-object v0, p0, Lh40/i0;->m:Ljava/lang/String;

    .line 111
    .line 112
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    iget-boolean p0, p0, Lh40/i0;->n:Z

    .line 117
    .line 118
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    add-int/2addr p0, v0

    .line 123
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", loading="

    .line 2
    .line 3
    const-string v1, ", badgeId="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Lh40/i0;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Lh40/i0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isCollectingBadge="

    .line 16
    .line 17
    const-string v2, ", imageUrl="

    .line 18
    .line 19
    iget-object v3, p0, Lh40/i0;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v4, p0, Lh40/i0;->d:Z

    .line 22
    .line 23
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lh40/i0;->e:Ljava/net/URL;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", title="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lh40/i0;->f:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", description="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ", disclaimer="

    .line 47
    .line 48
    const-string v2, ", progress="

    .line 49
    .line 50
    iget-object v3, p0, Lh40/i0;->g:Ljava/lang/String;

    .line 51
    .line 52
    iget-object v4, p0, Lh40/i0;->h:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lh40/i0;->i:Lg40/l;

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", action="

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Lh40/i0;->j:Lg40/k;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v1, ", buttonText="

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lh40/i0;->k:Ljava/lang/String;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", collectedAt="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-object v1, p0, Lh40/i0;->l:Ljava/time/OffsetDateTime;

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v1, ", clubName="

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", snapBadge="

    .line 98
    .line 99
    const-string v2, ")"

    .line 100
    .line 101
    iget-object v3, p0, Lh40/i0;->m:Ljava/lang/String;

    .line 102
    .line 103
    iget-boolean p0, p0, Lh40/i0;->n:Z

    .line 104
    .line 105
    invoke-static {v3, v1, v2, v0, p0}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0
.end method
