.class public final Lm70/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Ler0/g;

.field public final b:Ljava/util/Map;

.field public final c:Lqr0/s;

.field public final d:Ljava/util/List;

.field public final e:I

.field public final f:Ljava/lang/Integer;

.field public final g:Z

.field public final h:Lm70/f0;

.field public final i:Z

.field public final j:Ljava/lang/String;

.field public final k:Ljava/util/List;

.field public final l:Z

.field public final m:Llf0/i;

.field public final n:Z

.field public final o:Z

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Ll70/v;


# direct methods
.method public constructor <init>(Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/List;ZLlf0/i;)V
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
    invoke-static {p13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lm70/g0;->a:Ler0/g;

    .line 15
    .line 16
    iput-object p2, p0, Lm70/g0;->b:Ljava/util/Map;

    .line 17
    .line 18
    iput-object p3, p0, Lm70/g0;->c:Lqr0/s;

    .line 19
    .line 20
    iput-object p4, p0, Lm70/g0;->d:Ljava/util/List;

    .line 21
    .line 22
    iput p5, p0, Lm70/g0;->e:I

    .line 23
    .line 24
    iput-object p6, p0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 25
    .line 26
    iput-boolean p7, p0, Lm70/g0;->g:Z

    .line 27
    .line 28
    iput-object p8, p0, Lm70/g0;->h:Lm70/f0;

    .line 29
    .line 30
    iput-boolean p9, p0, Lm70/g0;->i:Z

    .line 31
    .line 32
    iput-object p10, p0, Lm70/g0;->j:Ljava/lang/String;

    .line 33
    .line 34
    iput-object p11, p0, Lm70/g0;->k:Ljava/util/List;

    .line 35
    .line 36
    iput-boolean p12, p0, Lm70/g0;->l:Z

    .line 37
    .line 38
    iput-object p13, p0, Lm70/g0;->m:Llf0/i;

    .line 39
    .line 40
    const/4 p1, 0x0

    .line 41
    const/4 p2, 0x1

    .line 42
    if-eqz p12, :cond_0

    .line 43
    .line 44
    if-nez p9, :cond_0

    .line 45
    .line 46
    move p3, p2

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move p3, p1

    .line 49
    :goto_0
    iput-boolean p3, p0, Lm70/g0;->n:Z

    .line 50
    .line 51
    if-eqz p3, :cond_1

    .line 52
    .line 53
    iget-object p5, p8, Lm70/f0;->a:Ljava/util/List;

    .line 54
    .line 55
    invoke-interface {p5}, Ljava/util/List;->isEmpty()Z

    .line 56
    .line 57
    .line 58
    move-result p5

    .line 59
    if-eqz p5, :cond_1

    .line 60
    .line 61
    move p5, p2

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    move p5, p1

    .line 64
    :goto_1
    iput-boolean p5, p0, Lm70/g0;->o:Z

    .line 65
    .line 66
    if-eqz p3, :cond_2

    .line 67
    .line 68
    invoke-interface {p4}, Ljava/util/List;->isEmpty()Z

    .line 69
    .line 70
    .line 71
    move-result p3

    .line 72
    if-eqz p3, :cond_2

    .line 73
    .line 74
    move p3, p2

    .line 75
    goto :goto_2

    .line 76
    :cond_2
    move p3, p1

    .line 77
    :goto_2
    iput-boolean p3, p0, Lm70/g0;->p:Z

    .line 78
    .line 79
    sget-object p3, Llf0/i;->h:Llf0/i;

    .line 80
    .line 81
    if-ne p13, p3, :cond_3

    .line 82
    .line 83
    move p1, p2

    .line 84
    :cond_3
    iput-boolean p1, p0, Lm70/g0;->q:Z

    .line 85
    .line 86
    invoke-static {p13}, Llp/tf;->d(Llf0/i;)Z

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    iput-boolean p1, p0, Lm70/g0;->r:Z

    .line 91
    .line 92
    check-cast p4, Ljava/lang/Iterable;

    .line 93
    .line 94
    invoke-interface {p4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result p3

    .line 102
    if-eqz p3, :cond_5

    .line 103
    .line 104
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p3

    .line 108
    move-object p4, p3

    .line 109
    check-cast p4, Ll70/v;

    .line 110
    .line 111
    iget-boolean p4, p4, Ll70/v;->b:Z

    .line 112
    .line 113
    if-eqz p4, :cond_4

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_5
    const/4 p3, 0x0

    .line 117
    :goto_3
    check-cast p3, Ll70/v;

    .line 118
    .line 119
    if-nez p3, :cond_6

    .line 120
    .line 121
    new-instance p3, Ll70/v;

    .line 122
    .line 123
    sget-object p1, Ll70/w;->d:Ll70/w;

    .line 124
    .line 125
    invoke-direct {p3, p1, p2}, Ll70/v;-><init>(Ll70/w;Z)V

    .line 126
    .line 127
    .line 128
    :cond_6
    iput-object p3, p0, Lm70/g0;->s:Ll70/v;

    .line 129
    .line 130
    return-void
.end method

.method public static a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;
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
    iget-object p1, p0, Lm70/g0;->a:Ler0/g;

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
    iget-object p1, p0, Lm70/g0;->b:Ljava/util/Map;

    .line 15
    .line 16
    move-object v2, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move-object/from16 v2, p2

    .line 19
    .line 20
    :goto_0
    and-int/lit8 p1, v0, 0x4

    .line 21
    .line 22
    if-eqz p1, :cond_2

    .line 23
    .line 24
    iget-object p1, p0, Lm70/g0;->c:Lqr0/s;

    .line 25
    .line 26
    move-object v3, p1

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    move-object/from16 v3, p3

    .line 29
    .line 30
    :goto_1
    and-int/lit8 p1, v0, 0x8

    .line 31
    .line 32
    if-eqz p1, :cond_3

    .line 33
    .line 34
    iget-object p1, p0, Lm70/g0;->d:Ljava/util/List;

    .line 35
    .line 36
    move-object v4, p1

    .line 37
    goto :goto_2

    .line 38
    :cond_3
    move-object/from16 v4, p4

    .line 39
    .line 40
    :goto_2
    and-int/lit8 p1, v0, 0x10

    .line 41
    .line 42
    if-eqz p1, :cond_4

    .line 43
    .line 44
    iget p1, p0, Lm70/g0;->e:I

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
    iget-object p1, p0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 55
    .line 56
    move-object v6, p1

    .line 57
    goto :goto_4

    .line 58
    :cond_5
    move-object/from16 v6, p6

    .line 59
    .line 60
    :goto_4
    and-int/lit8 p1, v0, 0x40

    .line 61
    .line 62
    if-eqz p1, :cond_6

    .line 63
    .line 64
    iget-boolean p1, p0, Lm70/g0;->g:Z

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
    iget-object p1, p0, Lm70/g0;->h:Lm70/f0;

    .line 75
    .line 76
    move-object v8, p1

    .line 77
    goto :goto_6

    .line 78
    :cond_7
    move-object/from16 v8, p8

    .line 79
    .line 80
    :goto_6
    and-int/lit16 p1, v0, 0x100

    .line 81
    .line 82
    if-eqz p1, :cond_8

    .line 83
    .line 84
    iget-boolean p1, p0, Lm70/g0;->i:Z

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
    iget-object p1, p0, Lm70/g0;->j:Ljava/lang/String;

    .line 95
    .line 96
    move-object v10, p1

    .line 97
    goto :goto_8

    .line 98
    :cond_9
    move-object/from16 v10, p10

    .line 99
    .line 100
    :goto_8
    and-int/lit16 p1, v0, 0x400

    .line 101
    .line 102
    if-eqz p1, :cond_a

    .line 103
    .line 104
    iget-object p1, p0, Lm70/g0;->k:Ljava/util/List;

    .line 105
    .line 106
    move-object v11, p1

    .line 107
    goto :goto_9

    .line 108
    :cond_a
    move-object/from16 v11, p11

    .line 109
    .line 110
    :goto_9
    and-int/lit16 p1, v0, 0x800

    .line 111
    .line 112
    if-eqz p1, :cond_b

    .line 113
    .line 114
    iget-boolean p1, p0, Lm70/g0;->l:Z

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
    iget-object p1, p0, Lm70/g0;->m:Llf0/i;

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
    const-string p0, "subscriptionLicenseState"

    .line 134
    .line 135
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    const-string p0, "tripStatistics"

    .line 139
    .line 140
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    const-string p0, "unitsType"

    .line 144
    .line 145
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    const-string p0, "intervals"

    .line 149
    .line 150
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    const-string p0, "filters"

    .line 154
    .line 155
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    const-string p0, "overviewTitle"

    .line 159
    .line 160
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    const-string p0, "overview"

    .line 164
    .line 165
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    const-string p0, "viewMode"

    .line 169
    .line 170
    invoke-static {v13, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    new-instance v0, Lm70/g0;

    .line 174
    .line 175
    invoke-direct/range {v0 .. v13}, Lm70/g0;-><init>(Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/List;ZLlf0/i;)V

    .line 176
    .line 177
    .line 178
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
    instance-of v1, p1, Lm70/g0;

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
    check-cast p1, Lm70/g0;

    .line 12
    .line 13
    iget-object v1, p0, Lm70/g0;->a:Ler0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lm70/g0;->a:Ler0/g;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lm70/g0;->b:Ljava/util/Map;

    .line 21
    .line 22
    iget-object v3, p1, Lm70/g0;->b:Ljava/util/Map;

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
    iget-object v1, p0, Lm70/g0;->c:Lqr0/s;

    .line 32
    .line 33
    iget-object v3, p1, Lm70/g0;->c:Lqr0/s;

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Lm70/g0;->d:Ljava/util/List;

    .line 39
    .line 40
    iget-object v3, p1, Lm70/g0;->d:Ljava/util/List;

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
    iget v1, p0, Lm70/g0;->e:I

    .line 50
    .line 51
    iget v3, p1, Lm70/g0;->e:I

    .line 52
    .line 53
    if-eq v1, v3, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 57
    .line 58
    iget-object v3, p1, Lm70/g0;->f:Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-nez v1, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-boolean v1, p0, Lm70/g0;->g:Z

    .line 68
    .line 69
    iget-boolean v3, p1, Lm70/g0;->g:Z

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Lm70/g0;->h:Lm70/f0;

    .line 75
    .line 76
    iget-object v3, p1, Lm70/g0;->h:Lm70/f0;

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
    iget-boolean v1, p0, Lm70/g0;->i:Z

    .line 86
    .line 87
    iget-boolean v3, p1, Lm70/g0;->i:Z

    .line 88
    .line 89
    if-eq v1, v3, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-object v1, p0, Lm70/g0;->j:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v3, p1, Lm70/g0;->j:Ljava/lang/String;

    .line 95
    .line 96
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-nez v1, :cond_b

    .line 101
    .line 102
    return v2

    .line 103
    :cond_b
    iget-object v1, p0, Lm70/g0;->k:Ljava/util/List;

    .line 104
    .line 105
    iget-object v3, p1, Lm70/g0;->k:Ljava/util/List;

    .line 106
    .line 107
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-nez v1, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    iget-boolean v1, p0, Lm70/g0;->l:Z

    .line 115
    .line 116
    iget-boolean v3, p1, Lm70/g0;->l:Z

    .line 117
    .line 118
    if-eq v1, v3, :cond_d

    .line 119
    .line 120
    return v2

    .line 121
    :cond_d
    iget-object p0, p0, Lm70/g0;->m:Llf0/i;

    .line 122
    .line 123
    iget-object p1, p1, Lm70/g0;->m:Llf0/i;

    .line 124
    .line 125
    if-eq p0, p1, :cond_e

    .line 126
    .line 127
    return v2

    .line 128
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lm70/g0;->a:Ler0/g;

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
    iget-object v2, p0, Lm70/g0;->b:Ljava/util/Map;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lp3/m;->a(IILjava/util/Map;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lm70/g0;->c:Lqr0/s;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lm70/g0;->d:Ljava/util/List;

    .line 25
    .line 26
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget v2, p0, Lm70/g0;->e:I

    .line 31
    .line 32
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 37
    .line 38
    if-nez v2, :cond_0

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    :goto_0
    add-int/2addr v0, v2

    .line 47
    mul-int/2addr v0, v1

    .line 48
    iget-boolean v2, p0, Lm70/g0;->g:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object v2, p0, Lm70/g0;->h:Lm70/f0;

    .line 55
    .line 56
    iget-object v2, v2, Lm70/f0;->a:Ljava/util/List;

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-boolean v2, p0, Lm70/g0;->i:Z

    .line 63
    .line 64
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-object v2, p0, Lm70/g0;->j:Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-object v2, p0, Lm70/g0;->k:Ljava/util/List;

    .line 75
    .line 76
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget-boolean v2, p0, Lm70/g0;->l:Z

    .line 81
    .line 82
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    iget-object p0, p0, Lm70/g0;->m:Llf0/i;

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    add-int/2addr p0, v0

    .line 93
    return p0
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
    iget-object v1, p0, Lm70/g0;->a:Ler0/g;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", tripStatistics="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lm70/g0;->b:Ljava/util/Map;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", unitsType="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lm70/g0;->c:Lqr0/s;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", intervals="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lm70/g0;->d:Ljava/util/List;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", selectedOffset="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget v1, p0, Lm70/g0;->e:I

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", selectedColumnIndex="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", doResetScrollPosition="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-boolean v1, p0, Lm70/g0;->g:Z

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", filters="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lm70/g0;->h:Lm70/f0;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", isRefreshing="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string v1, ", overviewTitle="

    .line 89
    .line 90
    const-string v2, ", overview="

    .line 91
    .line 92
    iget-object v3, p0, Lm70/g0;->j:Ljava/lang/String;

    .line 93
    .line 94
    iget-boolean v4, p0, Lm70/g0;->i:Z

    .line 95
    .line 96
    invoke-static {v1, v3, v2, v0, v4}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 97
    .line 98
    .line 99
    const-string v1, ", isLoading="

    .line 100
    .line 101
    const-string v2, ", viewMode="

    .line 102
    .line 103
    iget-object v3, p0, Lm70/g0;->k:Ljava/util/List;

    .line 104
    .line 105
    iget-boolean v4, p0, Lm70/g0;->l:Z

    .line 106
    .line 107
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->w(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget-object p0, p0, Lm70/g0;->m:Llf0/i;

    .line 111
    .line 112
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string p0, ")"

    .line 116
    .line 117
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0
.end method
