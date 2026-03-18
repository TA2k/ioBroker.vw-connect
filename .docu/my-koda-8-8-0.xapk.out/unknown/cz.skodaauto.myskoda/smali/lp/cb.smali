.class public abstract Llp/cb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lhu/w0;


# direct methods
.method public static a(Lw71/c;Lw71/c;Lw71/c;D)Ljava/util/ArrayList;
    .locals 14

    .line 1
    move-object/from16 v1, p2

    .line 2
    .line 3
    invoke-static/range {p0 .. p1}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {p0, v1}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 8
    .line 9
    .line 10
    move-result-wide v4

    .line 11
    sub-double/2addr v2, v4

    .line 12
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(D)D

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    const-wide v4, 0x3f947ae147ae147bL    # 0.02

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    cmpg-double v2, v2, v4

    .line 22
    .line 23
    sget-object v3, Lw71/a;->c:Lmb/e;

    .line 24
    .line 25
    if-gtz v2, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-static {v1, p1}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-static {v2}, Lw71/d;->g(Lw71/c;)Lw71/c;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    if-nez v2, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    invoke-static {p0, v2}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    if-nez v2, :cond_2

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    invoke-virtual {v3, p1, v1}, Lmb/e;->m(Lw71/c;Lw71/c;)Lw71/a;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    if-nez v4, :cond_3

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    invoke-virtual {v2, v4}, Lw71/a;->b(Lw71/a;)Lw71/c;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    if-nez v2, :cond_4

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_4
    move-object p0, v2

    .line 61
    :goto_0
    new-instance v2, Ljava/util/ArrayList;

    .line 62
    .line 63
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-static {p0, p1}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 67
    .line 68
    .line 69
    move-result-wide v4

    .line 70
    invoke-static {p0, v1}, Lw71/d;->a(Lw71/c;Lw71/c;)D

    .line 71
    .line 72
    .line 73
    move-result-wide v6

    .line 74
    add-double/2addr v6, v4

    .line 75
    const/4 v4, 0x2

    .line 76
    int-to-double v4, v4

    .line 77
    div-double/2addr v6, v4

    .line 78
    invoke-static {v3, p0, p1}, Lmb/e;->p(Lmb/e;Lw71/c;Lw71/c;)Lw71/a;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    if-eqz v0, :cond_8

    .line 83
    .line 84
    invoke-virtual {v0}, Lw71/a;->a()D

    .line 85
    .line 86
    .line 87
    move-result-wide v4

    .line 88
    invoke-static {v3, p0, v1}, Lmb/e;->p(Lmb/e;Lw71/c;Lw71/c;)Lw71/a;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    if-eqz v0, :cond_8

    .line 93
    .line 94
    invoke-virtual {v0}, Lw71/a;->a()D

    .line 95
    .line 96
    .line 97
    move-result-wide v8

    .line 98
    sub-double/2addr v8, v4

    .line 99
    const-wide v10, 0x400921fb54442d18L    # Math.PI

    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    cmpl-double v0, v8, v10

    .line 105
    .line 106
    const-wide v10, 0x401921fb54442d18L    # 6.283185307179586

    .line 107
    .line 108
    .line 109
    .line 110
    .line 111
    if-lez v0, :cond_5

    .line 112
    .line 113
    sub-double/2addr v8, v10

    .line 114
    goto :goto_1

    .line 115
    :cond_5
    const-wide v12, -0x3ff6de04abbbd2e8L    # -3.141592653589793

    .line 116
    .line 117
    .line 118
    .line 119
    .line 120
    cmpg-double v0, v8, v12

    .line 121
    .line 122
    if-gez v0, :cond_6

    .line 123
    .line 124
    add-double/2addr v8, v10

    .line 125
    :cond_6
    :goto_1
    mul-double v10, v6, v8

    .line 126
    .line 127
    invoke-static {v10, v11}, Ljava/lang/Math;->abs(D)D

    .line 128
    .line 129
    .line 130
    move-result-wide v10

    .line 131
    div-double v10, v10, p3

    .line 132
    .line 133
    invoke-static {v10, v11}, Ljava/lang/Math;->rint(D)D

    .line 134
    .line 135
    .line 136
    move-result-wide v10

    .line 137
    double-to-int v0, v10

    .line 138
    if-lez v0, :cond_8

    .line 139
    .line 140
    int-to-double v10, v0

    .line 141
    div-double/2addr v8, v10

    .line 142
    add-int/lit8 v0, v0, -0x1

    .line 143
    .line 144
    const/4 v3, 0x0

    .line 145
    :goto_2
    if-ge v3, v0, :cond_7

    .line 146
    .line 147
    add-double/2addr v4, v8

    .line 148
    invoke-static {v4, v5, v6, v7}, Lw71/d;->c(DD)Lw71/c;

    .line 149
    .line 150
    .line 151
    move-result-object v10

    .line 152
    invoke-static {p0, v10}, Lw71/d;->h(Lw71/c;Lw71/c;)Lw71/c;

    .line 153
    .line 154
    .line 155
    move-result-object v10

    .line 156
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    add-int/lit8 v3, v3, 0x1

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_7
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    :cond_8
    return-object v2
.end method

.method public static final b()V
    .locals 4

    .line 1
    :try_start_0
    sget-object v0, Llp/cb;->a:Lhu/w0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-class v1, Lhu/p;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lhu/p;

    .line 16
    .line 17
    check-cast v0, Lhu/i;

    .line 18
    .line 19
    iget-object v0, v0, Lhu/i;->o:Lju/c;

    .line 20
    .line 21
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lhu/w0;

    .line 26
    .line 27
    const-string v1, "<set-?>"

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Llp/cb;->a:Lhu/w0;

    .line 33
    .line 34
    :cond_0
    sget-object v0, Llp/cb;->a:Lhu/w0;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    const-string v2, "sharedSessionRepository"

    .line 38
    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    :try_start_1
    iget-boolean v3, v0, Lhu/w0;->i:Z

    .line 42
    .line 43
    if-eqz v3, :cond_3

    .line 44
    .line 45
    if-eqz v0, :cond_1

    .line 46
    .line 47
    invoke-virtual {v0}, Lhu/w0;->b()V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw v1

    .line 55
    :cond_2
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 59
    :catch_0
    :cond_3
    return-void
.end method
