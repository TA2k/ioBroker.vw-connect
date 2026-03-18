.class public final Lqp0/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Lqp0/t0;

.field public final d:Lxj0/f;

.field public final e:Lbl0/a;

.field public final f:Lqr0/d;

.field public final g:Lmy0/c;

.field public final h:Ljava/lang/Integer;

.field public final i:Ljava/lang/Integer;

.field public final j:Lmy0/c;

.field public final k:Lqp0/a0;

.field public final l:Ljava/lang/String;

.field public final m:Lqp0/z;

.field public final n:Ljava/lang/Boolean;

.field public final o:Ljava/lang/Boolean;

.field public final p:Lqp0/n;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lqp0/t0;Lxj0/f;Lbl0/a;Lqr0/d;Lmy0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lmy0/c;Lqp0/a0;Ljava/lang/String;Lqp0/z;Ljava/lang/Boolean;Ljava/lang/Boolean;Lqp0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqp0/b0;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lqp0/b0;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 9
    .line 10
    iput-object p4, p0, Lqp0/b0;->d:Lxj0/f;

    .line 11
    .line 12
    iput-object p5, p0, Lqp0/b0;->e:Lbl0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lqp0/b0;->f:Lqr0/d;

    .line 15
    .line 16
    iput-object p7, p0, Lqp0/b0;->g:Lmy0/c;

    .line 17
    .line 18
    iput-object p8, p0, Lqp0/b0;->h:Ljava/lang/Integer;

    .line 19
    .line 20
    iput-object p9, p0, Lqp0/b0;->i:Ljava/lang/Integer;

    .line 21
    .line 22
    iput-object p10, p0, Lqp0/b0;->j:Lmy0/c;

    .line 23
    .line 24
    iput-object p11, p0, Lqp0/b0;->k:Lqp0/a0;

    .line 25
    .line 26
    iput-object p12, p0, Lqp0/b0;->l:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p13, p0, Lqp0/b0;->m:Lqp0/z;

    .line 29
    .line 30
    iput-object p14, p0, Lqp0/b0;->n:Ljava/lang/Boolean;

    .line 31
    .line 32
    iput-object p15, p0, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lqp0/b0;->p:Lqp0/n;

    .line 37
    .line 38
    return-void
.end method

.method public static a(Lqp0/b0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lqp0/n;I)Lqp0/b0;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p6

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lqp0/b0;->a:Ljava/lang/String;

    .line 10
    .line 11
    move-object v4, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object/from16 v4, p1

    .line 14
    .line 15
    :goto_0
    and-int/lit8 v2, v1, 0x2

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget-object v2, v0, Lqp0/b0;->b:Ljava/lang/String;

    .line 20
    .line 21
    move-object v5, v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move-object/from16 v5, p2

    .line 24
    .line 25
    :goto_1
    iget-object v6, v0, Lqp0/b0;->c:Lqp0/t0;

    .line 26
    .line 27
    iget-object v7, v0, Lqp0/b0;->d:Lxj0/f;

    .line 28
    .line 29
    iget-object v8, v0, Lqp0/b0;->e:Lbl0/a;

    .line 30
    .line 31
    iget-object v9, v0, Lqp0/b0;->f:Lqr0/d;

    .line 32
    .line 33
    iget-object v10, v0, Lqp0/b0;->g:Lmy0/c;

    .line 34
    .line 35
    iget-object v11, v0, Lqp0/b0;->h:Ljava/lang/Integer;

    .line 36
    .line 37
    iget-object v12, v0, Lqp0/b0;->i:Ljava/lang/Integer;

    .line 38
    .line 39
    iget-object v13, v0, Lqp0/b0;->j:Lmy0/c;

    .line 40
    .line 41
    iget-object v14, v0, Lqp0/b0;->k:Lqp0/a0;

    .line 42
    .line 43
    and-int/lit16 v2, v1, 0x800

    .line 44
    .line 45
    if-eqz v2, :cond_2

    .line 46
    .line 47
    iget-object v2, v0, Lqp0/b0;->l:Ljava/lang/String;

    .line 48
    .line 49
    move-object v15, v2

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    move-object/from16 v15, p3

    .line 52
    .line 53
    :goto_2
    iget-object v2, v0, Lqp0/b0;->m:Lqp0/z;

    .line 54
    .line 55
    and-int/lit16 v3, v1, 0x2000

    .line 56
    .line 57
    if-eqz v3, :cond_3

    .line 58
    .line 59
    iget-object v3, v0, Lqp0/b0;->n:Ljava/lang/Boolean;

    .line 60
    .line 61
    move-object/from16 v17, v3

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    move-object/from16 v17, p4

    .line 65
    .line 66
    :goto_3
    iget-object v3, v0, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 67
    .line 68
    const v16, 0x8000

    .line 69
    .line 70
    .line 71
    and-int v1, v1, v16

    .line 72
    .line 73
    if-eqz v1, :cond_4

    .line 74
    .line 75
    iget-object v1, v0, Lqp0/b0;->p:Lqp0/n;

    .line 76
    .line 77
    move-object/from16 v19, v1

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move-object/from16 v19, p5

    .line 81
    .line 82
    :goto_4
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    const-string v0, "type"

    .line 86
    .line 87
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    move-object/from16 v18, v3

    .line 91
    .line 92
    new-instance v3, Lqp0/b0;

    .line 93
    .line 94
    move-object/from16 v16, v2

    .line 95
    .line 96
    invoke-direct/range {v3 .. v19}, Lqp0/b0;-><init>(Ljava/lang/String;Ljava/lang/String;Lqp0/t0;Lxj0/f;Lbl0/a;Lqr0/d;Lmy0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lmy0/c;Lqp0/a0;Ljava/lang/String;Lqp0/z;Ljava/lang/Boolean;Ljava/lang/Boolean;Lqp0/n;)V

    .line 97
    .line 98
    .line 99
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
    instance-of v1, p1, Lqp0/b0;

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
    check-cast p1, Lqp0/b0;

    .line 12
    .line 13
    iget-object v1, p0, Lqp0/b0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lqp0/b0;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lqp0/b0;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lqp0/b0;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 36
    .line 37
    iget-object v3, p1, Lqp0/b0;->c:Lqp0/t0;

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
    iget-object v1, p0, Lqp0/b0;->d:Lxj0/f;

    .line 47
    .line 48
    iget-object v3, p1, Lqp0/b0;->d:Lxj0/f;

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
    iget-object v1, p0, Lqp0/b0;->e:Lbl0/a;

    .line 58
    .line 59
    iget-object v3, p1, Lqp0/b0;->e:Lbl0/a;

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
    iget-object v1, p0, Lqp0/b0;->f:Lqr0/d;

    .line 69
    .line 70
    iget-object v3, p1, Lqp0/b0;->f:Lqr0/d;

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
    iget-object v1, p0, Lqp0/b0;->g:Lmy0/c;

    .line 80
    .line 81
    iget-object v3, p1, Lqp0/b0;->g:Lmy0/c;

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
    iget-object v1, p0, Lqp0/b0;->h:Ljava/lang/Integer;

    .line 91
    .line 92
    iget-object v3, p1, Lqp0/b0;->h:Ljava/lang/Integer;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lqp0/b0;->i:Ljava/lang/Integer;

    .line 102
    .line 103
    iget-object v3, p1, Lqp0/b0;->i:Ljava/lang/Integer;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object v1, p0, Lqp0/b0;->j:Lmy0/c;

    .line 113
    .line 114
    iget-object v3, p1, Lqp0/b0;->j:Lmy0/c;

    .line 115
    .line 116
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    iget-object v1, p0, Lqp0/b0;->k:Lqp0/a0;

    .line 124
    .line 125
    iget-object v3, p1, Lqp0/b0;->k:Lqp0/a0;

    .line 126
    .line 127
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-nez v1, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    iget-object v1, p0, Lqp0/b0;->l:Ljava/lang/String;

    .line 135
    .line 136
    iget-object v3, p1, Lqp0/b0;->l:Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_d

    .line 143
    .line 144
    return v2

    .line 145
    :cond_d
    iget-object v1, p0, Lqp0/b0;->m:Lqp0/z;

    .line 146
    .line 147
    iget-object v3, p1, Lqp0/b0;->m:Lqp0/z;

    .line 148
    .line 149
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_e

    .line 154
    .line 155
    return v2

    .line 156
    :cond_e
    iget-object v1, p0, Lqp0/b0;->n:Ljava/lang/Boolean;

    .line 157
    .line 158
    iget-object v3, p1, Lqp0/b0;->n:Ljava/lang/Boolean;

    .line 159
    .line 160
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-nez v1, :cond_f

    .line 165
    .line 166
    return v2

    .line 167
    :cond_f
    iget-object v1, p0, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 168
    .line 169
    iget-object v3, p1, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 170
    .line 171
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    if-nez v1, :cond_10

    .line 176
    .line 177
    return v2

    .line 178
    :cond_10
    iget-object p0, p0, Lqp0/b0;->p:Lqp0/n;

    .line 179
    .line 180
    iget-object p1, p1, Lqp0/b0;->p:Lqp0/n;

    .line 181
    .line 182
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    if-nez p0, :cond_11

    .line 187
    .line 188
    return v2

    .line 189
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lqp0/b0;->a:Ljava/lang/String;

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
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    mul-int/lit8 v1, v1, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lqp0/b0;->b:Ljava/lang/String;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move v2, v0

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    :goto_1
    add-int/2addr v1, v2

    .line 25
    mul-int/lit8 v1, v1, 0x1f

    .line 26
    .line 27
    iget-object v2, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 28
    .line 29
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    add-int/2addr v2, v1

    .line 34
    mul-int/lit8 v2, v2, 0x1f

    .line 35
    .line 36
    iget-object v1, p0, Lqp0/b0;->d:Lxj0/f;

    .line 37
    .line 38
    if-nez v1, :cond_2

    .line 39
    .line 40
    move v1, v0

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    invoke-virtual {v1}, Lxj0/f;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    :goto_2
    add-int/2addr v2, v1

    .line 47
    mul-int/lit8 v2, v2, 0x1f

    .line 48
    .line 49
    iget-object v1, p0, Lqp0/b0;->e:Lbl0/a;

    .line 50
    .line 51
    if-nez v1, :cond_3

    .line 52
    .line 53
    move v1, v0

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    invoke-virtual {v1}, Lbl0/a;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    :goto_3
    add-int/2addr v2, v1

    .line 60
    mul-int/lit8 v2, v2, 0x1f

    .line 61
    .line 62
    iget-object v1, p0, Lqp0/b0;->f:Lqr0/d;

    .line 63
    .line 64
    if-nez v1, :cond_4

    .line 65
    .line 66
    move v1, v0

    .line 67
    goto :goto_4

    .line 68
    :cond_4
    iget-wide v3, v1, Lqr0/d;->a:D

    .line 69
    .line 70
    invoke-static {v3, v4}, Ljava/lang/Double;->hashCode(D)I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    :goto_4
    add-int/2addr v2, v1

    .line 75
    mul-int/lit8 v2, v2, 0x1f

    .line 76
    .line 77
    iget-object v1, p0, Lqp0/b0;->g:Lmy0/c;

    .line 78
    .line 79
    if-nez v1, :cond_5

    .line 80
    .line 81
    move v1, v0

    .line 82
    goto :goto_5

    .line 83
    :cond_5
    iget-wide v3, v1, Lmy0/c;->d:J

    .line 84
    .line 85
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    :goto_5
    add-int/2addr v2, v1

    .line 90
    mul-int/lit8 v2, v2, 0x1f

    .line 91
    .line 92
    iget-object v1, p0, Lqp0/b0;->h:Ljava/lang/Integer;

    .line 93
    .line 94
    if-nez v1, :cond_6

    .line 95
    .line 96
    move v1, v0

    .line 97
    goto :goto_6

    .line 98
    :cond_6
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    :goto_6
    add-int/2addr v2, v1

    .line 103
    mul-int/lit8 v2, v2, 0x1f

    .line 104
    .line 105
    iget-object v1, p0, Lqp0/b0;->i:Ljava/lang/Integer;

    .line 106
    .line 107
    if-nez v1, :cond_7

    .line 108
    .line 109
    move v1, v0

    .line 110
    goto :goto_7

    .line 111
    :cond_7
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    :goto_7
    add-int/2addr v2, v1

    .line 116
    mul-int/lit8 v2, v2, 0x1f

    .line 117
    .line 118
    iget-object v1, p0, Lqp0/b0;->j:Lmy0/c;

    .line 119
    .line 120
    if-nez v1, :cond_8

    .line 121
    .line 122
    move v1, v0

    .line 123
    goto :goto_8

    .line 124
    :cond_8
    iget-wide v3, v1, Lmy0/c;->d:J

    .line 125
    .line 126
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    :goto_8
    add-int/2addr v2, v1

    .line 131
    mul-int/lit8 v2, v2, 0x1f

    .line 132
    .line 133
    iget-object v1, p0, Lqp0/b0;->k:Lqp0/a0;

    .line 134
    .line 135
    if-nez v1, :cond_9

    .line 136
    .line 137
    move v1, v0

    .line 138
    goto :goto_9

    .line 139
    :cond_9
    invoke-virtual {v1}, Lqp0/a0;->hashCode()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    :goto_9
    add-int/2addr v2, v1

    .line 144
    mul-int/lit8 v2, v2, 0x1f

    .line 145
    .line 146
    iget-object v1, p0, Lqp0/b0;->l:Ljava/lang/String;

    .line 147
    .line 148
    if-nez v1, :cond_a

    .line 149
    .line 150
    move v1, v0

    .line 151
    goto :goto_a

    .line 152
    :cond_a
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    :goto_a
    add-int/2addr v2, v1

    .line 157
    mul-int/lit8 v2, v2, 0x1f

    .line 158
    .line 159
    iget-object v1, p0, Lqp0/b0;->m:Lqp0/z;

    .line 160
    .line 161
    if-nez v1, :cond_b

    .line 162
    .line 163
    move v1, v0

    .line 164
    goto :goto_b

    .line 165
    :cond_b
    invoke-virtual {v1}, Lqp0/z;->hashCode()I

    .line 166
    .line 167
    .line 168
    move-result v1

    .line 169
    :goto_b
    add-int/2addr v2, v1

    .line 170
    mul-int/lit8 v2, v2, 0x1f

    .line 171
    .line 172
    iget-object v1, p0, Lqp0/b0;->n:Ljava/lang/Boolean;

    .line 173
    .line 174
    if-nez v1, :cond_c

    .line 175
    .line 176
    move v1, v0

    .line 177
    goto :goto_c

    .line 178
    :cond_c
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    :goto_c
    add-int/2addr v2, v1

    .line 183
    mul-int/lit8 v2, v2, 0x1f

    .line 184
    .line 185
    iget-object v1, p0, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 186
    .line 187
    if-nez v1, :cond_d

    .line 188
    .line 189
    move v1, v0

    .line 190
    goto :goto_d

    .line 191
    :cond_d
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 192
    .line 193
    .line 194
    move-result v1

    .line 195
    :goto_d
    add-int/2addr v2, v1

    .line 196
    mul-int/lit8 v2, v2, 0x1f

    .line 197
    .line 198
    iget-object p0, p0, Lqp0/b0;->p:Lqp0/n;

    .line 199
    .line 200
    if-nez p0, :cond_e

    .line 201
    .line 202
    goto :goto_e

    .line 203
    :cond_e
    invoke-virtual {p0}, Lqp0/n;->hashCode()I

    .line 204
    .line 205
    .line 206
    move-result v0

    .line 207
    :goto_e
    add-int/2addr v2, v0

    .line 208
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", name="

    .line 2
    .line 3
    const-string v1, ", type="

    .line 4
    .line 5
    const-string v2, "Waypoint(id="

    .line 6
    .line 7
    iget-object v3, p0, Lqp0/b0;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lqp0/b0;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", location="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lqp0/b0;->d:Lxj0/f;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", address="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lqp0/b0;->e:Lbl0/a;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", distanceToNextWaypoint="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lqp0/b0;->f:Lqr0/d;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, ", durationToNextWaypoint="

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-object v1, p0, Lqp0/b0;->g:Lmy0/c;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v1, ", batteryChargeAtStartPct="

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lqp0/b0;->h:Ljava/lang/Integer;

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, ", batteryChargeAtEndPct="

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    iget-object v1, p0, Lqp0/b0;->i:Ljava/lang/Integer;

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string v1, ", chargingDuration="

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Lqp0/b0;->j:Lmy0/c;

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, ", chargingStation="

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    iget-object v1, p0, Lqp0/b0;->k:Lqp0/a0;

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v1, ", offerId="

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    iget-object v1, p0, Lqp0/b0;->l:Ljava/lang/String;

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    const-string v1, ", aiStopover="

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    iget-object v1, p0, Lqp0/b0;->m:Lqp0/z;

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string v1, ", isAIGenerated="

    .line 121
    .line 122
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    iget-object v1, p0, Lqp0/b0;->n:Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    const-string v1, ", isNextWaypointInWalkingDistance="

    .line 131
    .line 132
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    iget-object v1, p0, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v1, ", placeReview="

    .line 141
    .line 142
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    iget-object p0, p0, Lqp0/b0;->p:Lqp0/n;

    .line 146
    .line 147
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    const-string p0, ")"

    .line 151
    .line 152
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    return-object p0
.end method
