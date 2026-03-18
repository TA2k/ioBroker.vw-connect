.class public final Lm70/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Z

.field public final d:Lqr0/s;

.field public final e:Ljava/time/LocalDate;

.field public final f:Ljava/lang/String;

.field public final g:Ll70/h;

.field public final h:Ljava/util/List;

.field public final i:Ll70/d;

.field public final j:Z

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Z

.field public final p:Z

.field public final q:Z

.field public final r:Z


# direct methods
.method public constructor <init>(Lql0/g;ZZLqr0/s;Ljava/time/LocalDate;Ljava/lang/String;Ll70/h;Ljava/util/List;Ll70/d;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 2

    .line 1
    move/from16 v0, p15

    .line 2
    .line 3
    const-string v1, "unitsType"

    .line 4
    .line 5
    invoke-static {p4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "restrictedDates"

    .line 9
    .line 10
    invoke-static {p8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lm70/b;->a:Lql0/g;

    .line 17
    .line 18
    iput-boolean p2, p0, Lm70/b;->b:Z

    .line 19
    .line 20
    iput-boolean p3, p0, Lm70/b;->c:Z

    .line 21
    .line 22
    iput-object p4, p0, Lm70/b;->d:Lqr0/s;

    .line 23
    .line 24
    iput-object p5, p0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 25
    .line 26
    iput-object p6, p0, Lm70/b;->f:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p7, p0, Lm70/b;->g:Ll70/h;

    .line 29
    .line 30
    iput-object p8, p0, Lm70/b;->h:Ljava/util/List;

    .line 31
    .line 32
    iput-object p9, p0, Lm70/b;->i:Ll70/d;

    .line 33
    .line 34
    iput-boolean p10, p0, Lm70/b;->j:Z

    .line 35
    .line 36
    iput-object p11, p0, Lm70/b;->k:Ljava/lang/String;

    .line 37
    .line 38
    iput-object p12, p0, Lm70/b;->l:Ljava/lang/String;

    .line 39
    .line 40
    move-object p1, p13

    .line 41
    iput-object p1, p0, Lm70/b;->m:Ljava/lang/String;

    .line 42
    .line 43
    move-object/from16 p1, p14

    .line 44
    .line 45
    iput-object p1, p0, Lm70/b;->n:Ljava/lang/String;

    .line 46
    .line 47
    iput-boolean v0, p0, Lm70/b;->o:Z

    .line 48
    .line 49
    invoke-static {p6}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    const/4 p2, 0x0

    .line 54
    const/4 p4, 0x1

    .line 55
    if-nez p1, :cond_0

    .line 56
    .line 57
    const-string p1, "^\\d{1,4}(?:[.,]\\d{0,3})?$"

    .line 58
    .line 59
    invoke-static {p1}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    const-string p5, "compile(...)"

    .line 64
    .line 65
    invoke-static {p1, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, p6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    invoke-virtual {p1}, Ljava/util/regex/Matcher;->matches()Z

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_1

    .line 77
    .line 78
    :cond_0
    if-eqz v0, :cond_2

    .line 79
    .line 80
    :cond_1
    move p1, p4

    .line 81
    goto :goto_0

    .line 82
    :cond_2
    move p1, p2

    .line 83
    :goto_0
    iput-boolean p1, p0, Lm70/b;->p:Z

    .line 84
    .line 85
    if-nez p3, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0}, Lm70/b;->b()Ll70/d;

    .line 88
    .line 89
    .line 90
    move-result-object p3

    .line 91
    if-eqz p3, :cond_3

    .line 92
    .line 93
    if-nez p1, :cond_3

    .line 94
    .line 95
    move p1, p4

    .line 96
    goto :goto_1

    .line 97
    :cond_3
    move p1, p2

    .line 98
    :goto_1
    iput-boolean p1, p0, Lm70/b;->q:Z

    .line 99
    .line 100
    if-eqz p9, :cond_4

    .line 101
    .line 102
    move p2, p4

    .line 103
    :cond_4
    iput-boolean p2, p0, Lm70/b;->r:Z

    .line 104
    .line 105
    return-void
.end method

.method public static a(Lm70/b;Lql0/g;ZLqr0/s;Ljava/time/LocalDate;Ljava/lang/String;Ll70/h;Ljava/util/ArrayList;Ll70/d;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZI)Lm70/b;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p15

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lm70/b;->a:Lql0/g;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object/from16 v2, p1

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    iget-boolean v3, v0, Lm70/b;->b:Z

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    const/4 v3, 0x1

    .line 22
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 23
    .line 24
    if-eqz v4, :cond_2

    .line 25
    .line 26
    iget-boolean v4, v0, Lm70/b;->c:Z

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move/from16 v4, p2

    .line 30
    .line 31
    :goto_2
    and-int/lit8 v5, v1, 0x8

    .line 32
    .line 33
    if-eqz v5, :cond_3

    .line 34
    .line 35
    iget-object v5, v0, Lm70/b;->d:Lqr0/s;

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_3
    move-object/from16 v5, p3

    .line 39
    .line 40
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 41
    .line 42
    if-eqz v6, :cond_4

    .line 43
    .line 44
    iget-object v6, v0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_4
    move-object/from16 v6, p4

    .line 48
    .line 49
    :goto_4
    and-int/lit8 v7, v1, 0x20

    .line 50
    .line 51
    if-eqz v7, :cond_5

    .line 52
    .line 53
    iget-object v7, v0, Lm70/b;->f:Ljava/lang/String;

    .line 54
    .line 55
    goto :goto_5

    .line 56
    :cond_5
    move-object/from16 v7, p5

    .line 57
    .line 58
    :goto_5
    and-int/lit8 v8, v1, 0x40

    .line 59
    .line 60
    if-eqz v8, :cond_6

    .line 61
    .line 62
    iget-object v8, v0, Lm70/b;->g:Ll70/h;

    .line 63
    .line 64
    goto :goto_6

    .line 65
    :cond_6
    move-object/from16 v8, p6

    .line 66
    .line 67
    :goto_6
    and-int/lit16 v9, v1, 0x80

    .line 68
    .line 69
    if-eqz v9, :cond_7

    .line 70
    .line 71
    iget-object v9, v0, Lm70/b;->h:Ljava/util/List;

    .line 72
    .line 73
    goto :goto_7

    .line 74
    :cond_7
    move-object/from16 v9, p7

    .line 75
    .line 76
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 77
    .line 78
    if-eqz v10, :cond_8

    .line 79
    .line 80
    iget-object v10, v0, Lm70/b;->i:Ll70/d;

    .line 81
    .line 82
    goto :goto_8

    .line 83
    :cond_8
    move-object/from16 v10, p8

    .line 84
    .line 85
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 86
    .line 87
    if-eqz v11, :cond_9

    .line 88
    .line 89
    iget-boolean v11, v0, Lm70/b;->j:Z

    .line 90
    .line 91
    goto :goto_9

    .line 92
    :cond_9
    move/from16 v11, p9

    .line 93
    .line 94
    :goto_9
    and-int/lit16 v12, v1, 0x400

    .line 95
    .line 96
    if-eqz v12, :cond_a

    .line 97
    .line 98
    iget-object v12, v0, Lm70/b;->k:Ljava/lang/String;

    .line 99
    .line 100
    goto :goto_a

    .line 101
    :cond_a
    move-object/from16 v12, p10

    .line 102
    .line 103
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 104
    .line 105
    if-eqz v13, :cond_b

    .line 106
    .line 107
    iget-object v13, v0, Lm70/b;->l:Ljava/lang/String;

    .line 108
    .line 109
    goto :goto_b

    .line 110
    :cond_b
    move-object/from16 v13, p11

    .line 111
    .line 112
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 113
    .line 114
    if-eqz v14, :cond_c

    .line 115
    .line 116
    iget-object v14, v0, Lm70/b;->m:Ljava/lang/String;

    .line 117
    .line 118
    goto :goto_c

    .line 119
    :cond_c
    move-object/from16 v14, p12

    .line 120
    .line 121
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 122
    .line 123
    if-eqz v15, :cond_d

    .line 124
    .line 125
    iget-object v15, v0, Lm70/b;->n:Ljava/lang/String;

    .line 126
    .line 127
    goto :goto_d

    .line 128
    :cond_d
    move-object/from16 v15, p13

    .line 129
    .line 130
    :goto_d
    and-int/lit16 v1, v1, 0x4000

    .line 131
    .line 132
    if-eqz v1, :cond_e

    .line 133
    .line 134
    iget-boolean v1, v0, Lm70/b;->o:Z

    .line 135
    .line 136
    goto :goto_e

    .line 137
    :cond_e
    move/from16 v1, p14

    .line 138
    .line 139
    :goto_e
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    const-string v0, "unitsType"

    .line 143
    .line 144
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    const-string v0, "costValue"

    .line 148
    .line 149
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    const-string v0, "restrictedDates"

    .line 153
    .line 154
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    new-instance v0, Lm70/b;

    .line 158
    .line 159
    move-object/from16 p0, v0

    .line 160
    .line 161
    move/from16 p15, v1

    .line 162
    .line 163
    move-object/from16 p1, v2

    .line 164
    .line 165
    move/from16 p2, v3

    .line 166
    .line 167
    move/from16 p3, v4

    .line 168
    .line 169
    move-object/from16 p4, v5

    .line 170
    .line 171
    move-object/from16 p5, v6

    .line 172
    .line 173
    move-object/from16 p6, v7

    .line 174
    .line 175
    move-object/from16 p7, v8

    .line 176
    .line 177
    move-object/from16 p8, v9

    .line 178
    .line 179
    move-object/from16 p9, v10

    .line 180
    .line 181
    move/from16 p10, v11

    .line 182
    .line 183
    move-object/from16 p11, v12

    .line 184
    .line 185
    move-object/from16 p12, v13

    .line 186
    .line 187
    move-object/from16 p13, v14

    .line 188
    .line 189
    move-object/from16 p14, v15

    .line 190
    .line 191
    invoke-direct/range {p0 .. p15}, Lm70/b;-><init>(Lql0/g;ZZLqr0/s;Ljava/time/LocalDate;Ljava/lang/String;Ll70/h;Ljava/util/List;Ll70/d;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 192
    .line 193
    .line 194
    return-object v0
.end method


# virtual methods
.method public final b()Ll70/d;
    .locals 10

    .line 1
    iget-object v0, p0, Lm70/b;->f:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :try_start_0
    invoke-static {v0}, Lly0/v;->i(Ljava/lang/String;)Z

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    invoke-static {v0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 15
    .line 16
    .line 17
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    goto :goto_0

    .line 19
    :catch_0
    :cond_0
    move-object v0, v1

    .line 20
    :goto_0
    if-eqz v0, :cond_1

    .line 21
    .line 22
    new-instance v2, Ljava/math/BigDecimal;

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    invoke-static {v0}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-direct {v2, v0}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move-object v2, v1

    .line 37
    :goto_1
    iget-object v0, p0, Lm70/b;->g:Ll70/h;

    .line 38
    .line 39
    if-eqz v0, :cond_4

    .line 40
    .line 41
    iget-object v3, p0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 42
    .line 43
    if-eqz v3, :cond_4

    .line 44
    .line 45
    if-eqz v2, :cond_4

    .line 46
    .line 47
    iget-object v3, p0, Lm70/b;->k:Ljava/lang/String;

    .line 48
    .line 49
    if-eqz v3, :cond_4

    .line 50
    .line 51
    new-instance v4, Ll70/d;

    .line 52
    .line 53
    iget-object v3, p0, Lm70/b;->i:Ll70/d;

    .line 54
    .line 55
    if-eqz v3, :cond_2

    .line 56
    .line 57
    iget-object v1, v3, Ll70/d;->a:Ljava/lang/String;

    .line 58
    .line 59
    :cond_2
    move-object v5, v1

    .line 60
    const-string v1, "unitsType"

    .line 61
    .line 62
    iget-object v3, p0, Lm70/b;->d:Lqr0/s;

    .line 63
    .line 64
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    sget-object v1, Ll70/h;->d:Ll70/h;

    .line 68
    .line 69
    if-ne v0, v1, :cond_3

    .line 70
    .line 71
    sget-object v0, Lqr0/s;->f:Lqr0/s;

    .line 72
    .line 73
    if-ne v3, v0, :cond_3

    .line 74
    .line 75
    new-instance v0, Ljava/math/BigDecimal;

    .line 76
    .line 77
    invoke-virtual {v2}, Ljava/math/BigDecimal;->doubleValue()D

    .line 78
    .line 79
    .line 80
    move-result-wide v1

    .line 81
    const-wide v6, 0x400e488509bf9c63L    # 3.78541

    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    div-double/2addr v1, v6

    .line 87
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-direct {v0, v1}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    move-object v6, v0

    .line 95
    goto :goto_2

    .line 96
    :cond_3
    move-object v6, v2

    .line 97
    :goto_2
    iget-object v8, p0, Lm70/b;->g:Ll70/h;

    .line 98
    .line 99
    iget-object v9, p0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 100
    .line 101
    iget-object v7, p0, Lm70/b;->k:Ljava/lang/String;

    .line 102
    .line 103
    invoke-direct/range {v4 .. v9}, Ll70/d;-><init>(Ljava/lang/String;Ljava/math/BigDecimal;Ljava/lang/String;Ll70/h;Ljava/time/LocalDate;)V

    .line 104
    .line 105
    .line 106
    return-object v4

    .line 107
    :cond_4
    return-object v1
.end method

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
    instance-of v1, p1, Lm70/b;

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
    check-cast p1, Lm70/b;

    .line 12
    .line 13
    iget-object v1, p0, Lm70/b;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lm70/b;->a:Lql0/g;

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
    iget-boolean v1, p0, Lm70/b;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lm70/b;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lm70/b;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lm70/b;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object v1, p0, Lm70/b;->d:Lqr0/s;

    .line 39
    .line 40
    iget-object v3, p1, Lm70/b;->d:Lqr0/s;

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 46
    .line 47
    iget-object v3, p1, Lm70/b;->e:Ljava/time/LocalDate;

    .line 48
    .line 49
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Lm70/b;->f:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v3, p1, Lm70/b;->f:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/b;->g:Ll70/h;

    .line 68
    .line 69
    iget-object v3, p1, Lm70/b;->g:Ll70/h;

    .line 70
    .line 71
    if-eq v1, v3, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Lm70/b;->h:Ljava/util/List;

    .line 75
    .line 76
    iget-object v3, p1, Lm70/b;->h:Ljava/util/List;

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
    iget-object v1, p0, Lm70/b;->i:Ll70/d;

    .line 86
    .line 87
    iget-object v3, p1, Lm70/b;->i:Ll70/d;

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
    iget-boolean v1, p0, Lm70/b;->j:Z

    .line 97
    .line 98
    iget-boolean v3, p1, Lm70/b;->j:Z

    .line 99
    .line 100
    if-eq v1, v3, :cond_b

    .line 101
    .line 102
    return v2

    .line 103
    :cond_b
    iget-object v1, p0, Lm70/b;->k:Ljava/lang/String;

    .line 104
    .line 105
    iget-object v3, p1, Lm70/b;->k:Ljava/lang/String;

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
    iget-object v1, p0, Lm70/b;->l:Ljava/lang/String;

    .line 115
    .line 116
    iget-object v3, p1, Lm70/b;->l:Ljava/lang/String;

    .line 117
    .line 118
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-nez v1, :cond_d

    .line 123
    .line 124
    return v2

    .line 125
    :cond_d
    iget-object v1, p0, Lm70/b;->m:Ljava/lang/String;

    .line 126
    .line 127
    iget-object v3, p1, Lm70/b;->m:Ljava/lang/String;

    .line 128
    .line 129
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    if-nez v1, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget-object v1, p0, Lm70/b;->n:Ljava/lang/String;

    .line 137
    .line 138
    iget-object v3, p1, Lm70/b;->n:Ljava/lang/String;

    .line 139
    .line 140
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    if-nez v1, :cond_f

    .line 145
    .line 146
    return v2

    .line 147
    :cond_f
    iget-boolean p0, p0, Lm70/b;->o:Z

    .line 148
    .line 149
    iget-boolean p1, p1, Lm70/b;->o:Z

    .line 150
    .line 151
    if-eq p0, p1, :cond_10

    .line 152
    .line 153
    return v2

    .line 154
    :cond_10
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lm70/b;->a:Lql0/g;

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
    iget-boolean v3, p0, Lm70/b;->b:Z

    .line 16
    .line 17
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iget-boolean v3, p0, Lm70/b;->c:Z

    .line 22
    .line 23
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    iget-object v3, p0, Lm70/b;->d:Lqr0/s;

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    add-int/2addr v3, v1

    .line 34
    mul-int/2addr v3, v2

    .line 35
    iget-object v1, p0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 36
    .line 37
    if-nez v1, :cond_1

    .line 38
    .line 39
    move v1, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v1}, Ljava/time/LocalDate;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    :goto_1
    add-int/2addr v3, v1

    .line 46
    mul-int/2addr v3, v2

    .line 47
    iget-object v1, p0, Lm70/b;->f:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v3, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    iget-object v3, p0, Lm70/b;->g:Ll70/h;

    .line 54
    .line 55
    if-nez v3, :cond_2

    .line 56
    .line 57
    move v3, v0

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_2
    add-int/2addr v1, v3

    .line 64
    mul-int/2addr v1, v2

    .line 65
    iget-object v3, p0, Lm70/b;->h:Ljava/util/List;

    .line 66
    .line 67
    invoke-static {v1, v2, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget-object v3, p0, Lm70/b;->i:Ll70/d;

    .line 72
    .line 73
    if-nez v3, :cond_3

    .line 74
    .line 75
    move v3, v0

    .line 76
    goto :goto_3

    .line 77
    :cond_3
    invoke-virtual {v3}, Ll70/d;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    :goto_3
    add-int/2addr v1, v3

    .line 82
    mul-int/2addr v1, v2

    .line 83
    iget-boolean v3, p0, Lm70/b;->j:Z

    .line 84
    .line 85
    invoke-static {v1, v2, v3}, La7/g0;->e(IIZ)I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    iget-object v3, p0, Lm70/b;->k:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v3, :cond_4

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    :goto_4
    add-int/2addr v1, v0

    .line 99
    mul-int/2addr v1, v2

    .line 100
    iget-object v0, p0, Lm70/b;->l:Ljava/lang/String;

    .line 101
    .line 102
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    iget-object v1, p0, Lm70/b;->m:Ljava/lang/String;

    .line 107
    .line 108
    invoke-static {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget-object v1, p0, Lm70/b;->n:Ljava/lang/String;

    .line 113
    .line 114
    invoke-static {v0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    iget-boolean p0, p0, Lm70/b;->o:Z

    .line 119
    .line 120
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    const-string v0, ", isFatalError="

    .line 2
    .line 3
    const-string v1, ", isLoading="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Lm70/b;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Lm70/b;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-boolean v1, p0, Lm70/b;->c:Z

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", unitsType="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lm70/b;->d:Lqr0/s;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", selectedDate="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lm70/b;->e:Ljava/time/LocalDate;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", costValue="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lm70/b;->f:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, ", fuelType="

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-object v1, p0, Lm70/b;->g:Ll70/h;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v1, ", restrictedDates="

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lm70/b;->h:Ljava/util/List;

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, ", fuelPrice="

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    iget-object v1, p0, Lm70/b;->i:Ll70/d;

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string v1, ", showDatePicker="

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    iget-boolean v1, p0, Lm70/b;->j:Z

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, ", currencyCode="

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v1, ", dateTitle="

    .line 96
    .line 97
    const-string v2, ", dateDescription="

    .line 98
    .line 99
    iget-object v3, p0, Lm70/b;->k:Ljava/lang/String;

    .line 100
    .line 101
    iget-object v4, p0, Lm70/b;->l:Ljava/lang/String;

    .line 102
    .line 103
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    const-string v1, ", priceDescription="

    .line 107
    .line 108
    const-string v2, ", isResponseErrorCostFormat="

    .line 109
    .line 110
    iget-object v3, p0, Lm70/b;->m:Ljava/lang/String;

    .line 111
    .line 112
    iget-object v4, p0, Lm70/b;->n:Ljava/lang/String;

    .line 113
    .line 114
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string v1, ")"

    .line 118
    .line 119
    iget-boolean p0, p0, Lm70/b;->o:Z

    .line 120
    .line 121
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    return-object p0
.end method
