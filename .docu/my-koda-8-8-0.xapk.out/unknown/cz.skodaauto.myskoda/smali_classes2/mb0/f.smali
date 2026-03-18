.class public final Lmb0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lmb0/e;

.field public final b:Lmb0/n;

.field public final c:Ljava/lang/Boolean;

.field public final d:Ljava/time/OffsetDateTime;

.field public final e:Lqr0/q;

.field public final f:Ljava/lang/Boolean;

.field public final g:Ljava/lang/Boolean;

.field public final h:Lmb0/m;

.field public final i:Lmb0/l;

.field public final j:Lmb0/i;

.field public final k:Lmb0/g;

.field public final l:Ljava/util/List;

.field public final m:Ljava/util/List;

.field public final n:Ljava/util/List;

.field public final o:Ljava/time/OffsetDateTime;

.field public final p:Lmb0/c;


# direct methods
.method public constructor <init>(Lmb0/e;Lmb0/n;Ljava/lang/Boolean;Ljava/time/OffsetDateTime;Lqr0/q;Ljava/lang/Boolean;Ljava/lang/Boolean;Lmb0/m;Lmb0/l;Lmb0/i;Lmb0/g;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/time/OffsetDateTime;Lmb0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmb0/f;->a:Lmb0/e;

    .line 5
    .line 6
    iput-object p2, p0, Lmb0/f;->b:Lmb0/n;

    .line 7
    .line 8
    iput-object p3, p0, Lmb0/f;->c:Ljava/lang/Boolean;

    .line 9
    .line 10
    iput-object p4, p0, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 11
    .line 12
    iput-object p5, p0, Lmb0/f;->e:Lqr0/q;

    .line 13
    .line 14
    iput-object p6, p0, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 15
    .line 16
    iput-object p7, p0, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 17
    .line 18
    iput-object p8, p0, Lmb0/f;->h:Lmb0/m;

    .line 19
    .line 20
    iput-object p9, p0, Lmb0/f;->i:Lmb0/l;

    .line 21
    .line 22
    iput-object p10, p0, Lmb0/f;->j:Lmb0/i;

    .line 23
    .line 24
    iput-object p11, p0, Lmb0/f;->k:Lmb0/g;

    .line 25
    .line 26
    iput-object p12, p0, Lmb0/f;->l:Ljava/util/List;

    .line 27
    .line 28
    iput-object p13, p0, Lmb0/f;->m:Ljava/util/List;

    .line 29
    .line 30
    iput-object p14, p0, Lmb0/f;->n:Ljava/util/List;

    .line 31
    .line 32
    iput-object p15, p0, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lmb0/f;->p:Lmb0/c;

    .line 37
    .line 38
    return-void
.end method

.method public static a(Lmb0/f;Lmb0/e;Lqr0/q;I)Lmb0/f;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    and-int/lit8 v1, p3, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v0, Lmb0/f;->a:Lmb0/e;

    .line 8
    .line 9
    move-object v3, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object/from16 v3, p1

    .line 12
    .line 13
    :goto_0
    iget-object v4, v0, Lmb0/f;->b:Lmb0/n;

    .line 14
    .line 15
    iget-object v5, v0, Lmb0/f;->c:Ljava/lang/Boolean;

    .line 16
    .line 17
    iget-object v6, v0, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 18
    .line 19
    and-int/lit8 v1, p3, 0x10

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iget-object v1, v0, Lmb0/f;->e:Lqr0/q;

    .line 24
    .line 25
    move-object v7, v1

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move-object/from16 v7, p2

    .line 28
    .line 29
    :goto_1
    iget-object v8, v0, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 30
    .line 31
    iget-object v9, v0, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 32
    .line 33
    iget-object v10, v0, Lmb0/f;->h:Lmb0/m;

    .line 34
    .line 35
    iget-object v11, v0, Lmb0/f;->i:Lmb0/l;

    .line 36
    .line 37
    iget-object v12, v0, Lmb0/f;->j:Lmb0/i;

    .line 38
    .line 39
    iget-object v13, v0, Lmb0/f;->k:Lmb0/g;

    .line 40
    .line 41
    iget-object v14, v0, Lmb0/f;->l:Ljava/util/List;

    .line 42
    .line 43
    iget-object v15, v0, Lmb0/f;->m:Ljava/util/List;

    .line 44
    .line 45
    iget-object v1, v0, Lmb0/f;->n:Ljava/util/List;

    .line 46
    .line 47
    iget-object v2, v0, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 48
    .line 49
    move-object/from16 v16, v1

    .line 50
    .line 51
    iget-object v1, v0, Lmb0/f;->p:Lmb0/c;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    const-string v0, "state"

    .line 57
    .line 58
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    move-object/from16 v17, v2

    .line 62
    .line 63
    new-instance v2, Lmb0/f;

    .line 64
    .line 65
    move-object/from16 v18, v1

    .line 66
    .line 67
    invoke-direct/range {v2 .. v18}, Lmb0/f;-><init>(Lmb0/e;Lmb0/n;Ljava/lang/Boolean;Ljava/time/OffsetDateTime;Lqr0/q;Ljava/lang/Boolean;Ljava/lang/Boolean;Lmb0/m;Lmb0/l;Lmb0/i;Lmb0/g;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/time/OffsetDateTime;Lmb0/c;)V

    .line 68
    .line 69
    .line 70
    return-object v2
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
    instance-of v1, p1, Lmb0/f;

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
    check-cast p1, Lmb0/f;

    .line 12
    .line 13
    iget-object v1, p0, Lmb0/f;->a:Lmb0/e;

    .line 14
    .line 15
    iget-object v3, p1, Lmb0/f;->a:Lmb0/e;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lmb0/f;->b:Lmb0/n;

    .line 21
    .line 22
    iget-object v3, p1, Lmb0/f;->b:Lmb0/n;

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
    iget-object v1, p0, Lmb0/f;->c:Ljava/lang/Boolean;

    .line 32
    .line 33
    iget-object v3, p1, Lmb0/f;->c:Ljava/lang/Boolean;

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
    iget-object v1, p0, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 43
    .line 44
    iget-object v3, p1, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lmb0/f;->e:Lqr0/q;

    .line 54
    .line 55
    iget-object v3, p1, Lmb0/f;->e:Lqr0/q;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 65
    .line 66
    iget-object v3, p1, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 76
    .line 77
    iget-object v3, p1, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lmb0/f;->h:Lmb0/m;

    .line 87
    .line 88
    iget-object v3, p1, Lmb0/f;->h:Lmb0/m;

    .line 89
    .line 90
    if-eq v1, v3, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-object v1, p0, Lmb0/f;->i:Lmb0/l;

    .line 94
    .line 95
    iget-object v3, p1, Lmb0/f;->i:Lmb0/l;

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
    iget-object v1, p0, Lmb0/f;->j:Lmb0/i;

    .line 105
    .line 106
    iget-object v3, p1, Lmb0/f;->j:Lmb0/i;

    .line 107
    .line 108
    if-eq v1, v3, :cond_b

    .line 109
    .line 110
    return v2

    .line 111
    :cond_b
    iget-object v1, p0, Lmb0/f;->k:Lmb0/g;

    .line 112
    .line 113
    iget-object v3, p1, Lmb0/f;->k:Lmb0/g;

    .line 114
    .line 115
    if-eq v1, v3, :cond_c

    .line 116
    .line 117
    return v2

    .line 118
    :cond_c
    iget-object v1, p0, Lmb0/f;->l:Ljava/util/List;

    .line 119
    .line 120
    iget-object v3, p1, Lmb0/f;->l:Ljava/util/List;

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
    iget-object v1, p0, Lmb0/f;->m:Ljava/util/List;

    .line 130
    .line 131
    iget-object v3, p1, Lmb0/f;->m:Ljava/util/List;

    .line 132
    .line 133
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-nez v1, :cond_e

    .line 138
    .line 139
    return v2

    .line 140
    :cond_e
    iget-object v1, p0, Lmb0/f;->n:Ljava/util/List;

    .line 141
    .line 142
    iget-object v3, p1, Lmb0/f;->n:Ljava/util/List;

    .line 143
    .line 144
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-nez v1, :cond_f

    .line 149
    .line 150
    return v2

    .line 151
    :cond_f
    iget-object v1, p0, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 152
    .line 153
    iget-object v3, p1, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 154
    .line 155
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    if-nez v1, :cond_10

    .line 160
    .line 161
    return v2

    .line 162
    :cond_10
    iget-object p0, p0, Lmb0/f;->p:Lmb0/c;

    .line 163
    .line 164
    iget-object p1, p1, Lmb0/f;->p:Lmb0/c;

    .line 165
    .line 166
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result p0

    .line 170
    if-nez p0, :cond_11

    .line 171
    .line 172
    return v2

    .line 173
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lmb0/f;->a:Lmb0/e;

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
    iget-object v2, p0, Lmb0/f;->b:Lmb0/n;

    .line 11
    .line 12
    invoke-virtual {v2}, Lmb0/n;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    const/4 v0, 0x0

    .line 19
    iget-object v3, p0, Lmb0/f;->c:Ljava/lang/Boolean;

    .line 20
    .line 21
    if-nez v3, :cond_0

    .line 22
    .line 23
    move v3, v0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    :goto_0
    add-int/2addr v2, v3

    .line 30
    mul-int/2addr v2, v1

    .line 31
    iget-object v3, p0, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 32
    .line 33
    if-nez v3, :cond_1

    .line 34
    .line 35
    move v3, v0

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    :goto_1
    add-int/2addr v2, v3

    .line 42
    mul-int/2addr v2, v1

    .line 43
    iget-object v3, p0, Lmb0/f;->e:Lqr0/q;

    .line 44
    .line 45
    if-nez v3, :cond_2

    .line 46
    .line 47
    move v3, v0

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    invoke-virtual {v3}, Lqr0/q;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    :goto_2
    add-int/2addr v2, v3

    .line 54
    mul-int/2addr v2, v1

    .line 55
    iget-object v3, p0, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 56
    .line 57
    if-nez v3, :cond_3

    .line 58
    .line 59
    move v3, v0

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    :goto_3
    add-int/2addr v2, v3

    .line 66
    mul-int/2addr v2, v1

    .line 67
    iget-object v3, p0, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 68
    .line 69
    if-nez v3, :cond_4

    .line 70
    .line 71
    move v3, v0

    .line 72
    goto :goto_4

    .line 73
    :cond_4
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    :goto_4
    add-int/2addr v2, v3

    .line 78
    mul-int/2addr v2, v1

    .line 79
    iget-object v3, p0, Lmb0/f;->h:Lmb0/m;

    .line 80
    .line 81
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    add-int/2addr v3, v2

    .line 86
    mul-int/2addr v3, v1

    .line 87
    iget-object v2, p0, Lmb0/f;->i:Lmb0/l;

    .line 88
    .line 89
    invoke-virtual {v2}, Lmb0/l;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    add-int/2addr v2, v3

    .line 94
    mul-int/2addr v2, v1

    .line 95
    iget-object v3, p0, Lmb0/f;->j:Lmb0/i;

    .line 96
    .line 97
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    add-int/2addr v3, v2

    .line 102
    mul-int/2addr v3, v1

    .line 103
    iget-object v2, p0, Lmb0/f;->k:Lmb0/g;

    .line 104
    .line 105
    if-nez v2, :cond_5

    .line 106
    .line 107
    move v2, v0

    .line 108
    goto :goto_5

    .line 109
    :cond_5
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    :goto_5
    add-int/2addr v3, v2

    .line 114
    mul-int/2addr v3, v1

    .line 115
    iget-object v2, p0, Lmb0/f;->l:Ljava/util/List;

    .line 116
    .line 117
    invoke-static {v3, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 118
    .line 119
    .line 120
    move-result v2

    .line 121
    iget-object v3, p0, Lmb0/f;->m:Ljava/util/List;

    .line 122
    .line 123
    invoke-static {v2, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    iget-object v3, p0, Lmb0/f;->n:Ljava/util/List;

    .line 128
    .line 129
    invoke-static {v2, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    iget-object v3, p0, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 134
    .line 135
    if-nez v3, :cond_6

    .line 136
    .line 137
    move v3, v0

    .line 138
    goto :goto_6

    .line 139
    :cond_6
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 140
    .line 141
    .line 142
    move-result v3

    .line 143
    :goto_6
    add-int/2addr v2, v3

    .line 144
    mul-int/2addr v2, v1

    .line 145
    iget-object p0, p0, Lmb0/f;->p:Lmb0/c;

    .line 146
    .line 147
    if-nez p0, :cond_7

    .line 148
    .line 149
    goto :goto_7

    .line 150
    :cond_7
    invoke-virtual {p0}, Lmb0/c;->hashCode()I

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    :goto_7
    add-int/2addr v2, v0

    .line 155
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "AirConditioningStatus(state="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lmb0/f;->a:Lmb0/e;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", windowHeating="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lmb0/f;->b:Lmb0/n;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", windowHeatingEnabled="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lmb0/f;->c:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", targetTemperatureAt="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", targetTemperature="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lmb0/f;->e:Lqr0/q;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", airConditioningWithoutExternalPower="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", airConditioningAtUnlock="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", steeringWheelPosition="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lmb0/f;->h:Lmb0/m;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", seatHeating="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lmb0/f;->i:Lmb0/l;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", heaterSource="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lmb0/f;->j:Lmb0/i;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", chargerConnectionState="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Lmb0/f;->k:Lmb0/g;

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", errors="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Lmb0/f;->l:Ljava/util/List;

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", timers="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", runningRequests="

    .line 129
    .line 130
    const-string v2, ", carCapturedTimestamp="

    .line 131
    .line 132
    iget-object v3, p0, Lmb0/f;->m:Ljava/util/List;

    .line 133
    .line 134
    iget-object v4, p0, Lmb0/f;->n:Ljava/util/List;

    .line 135
    .line 136
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    iget-object v1, p0, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 140
    .line 141
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    const-string v1, ", outsideTemperature="

    .line 145
    .line 146
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    iget-object p0, p0, Lmb0/f;->p:Lmb0/c;

    .line 150
    .line 151
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    const-string p0, ")"

    .line 155
    .line 156
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0
.end method
