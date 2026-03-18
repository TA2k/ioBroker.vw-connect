.class public abstract Lt1/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;

.field public static b:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lqf0/d;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqf0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lt1/o;->a:Ll2/u2;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lg4/g;Lg4/p0;Lk4/m;Ljava/util/List;Ll2/o;I)V
    .locals 12

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    check-cast v0, Ll2/t;

    .line 4
    .line 5
    sget-object v1, Lt1/o;->a:Ll2/u2;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Ljava/util/concurrent/Executor;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    if-eqz v1, :cond_8

    .line 15
    .line 16
    iget-object v3, p0, Lg4/g;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    invoke-static {v3}, Lt1/o;->b(I)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_8

    .line 27
    .line 28
    const v3, -0x1eeadbd2

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    sget-object v3, Lw3/h1;->n:Ll2/u2;

    .line 35
    .line 36
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    move-object v6, v3

    .line 41
    check-cast v6, Lt4/m;

    .line 42
    .line 43
    sget-object v3, Lw3/h1;->h:Ll2/u2;

    .line 44
    .line 45
    invoke-virtual {v0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    move-object v9, v3

    .line 50
    check-cast v9, Lt4/c;

    .line 51
    .line 52
    and-int/lit8 v3, p5, 0x70

    .line 53
    .line 54
    xor-int/lit8 v3, v3, 0x30

    .line 55
    .line 56
    const/4 v4, 0x1

    .line 57
    const/16 v5, 0x20

    .line 58
    .line 59
    if-le v3, v5, :cond_0

    .line 60
    .line 61
    :try_start_0
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-nez v3, :cond_1

    .line 66
    .line 67
    :cond_0
    and-int/lit8 v3, p5, 0x30

    .line 68
    .line 69
    if-ne v3, v5, :cond_2

    .line 70
    .line 71
    :cond_1
    move v3, v4

    .line 72
    goto :goto_0

    .line 73
    :cond_2
    move v3, v2

    .line 74
    :goto_0
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    invoke-virtual {v0, v5}, Ll2/t;->e(I)Z

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    or-int/2addr v3, v5

    .line 83
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v5

    .line 87
    or-int/2addr v3, v5

    .line 88
    and-int/lit8 v5, p5, 0xe

    .line 89
    .line 90
    xor-int/lit8 v5, v5, 0x6

    .line 91
    .line 92
    const/4 v7, 0x4

    .line 93
    if-le v5, v7, :cond_3

    .line 94
    .line 95
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-nez v5, :cond_5

    .line 100
    .line 101
    :cond_3
    and-int/lit8 v5, p5, 0x6

    .line 102
    .line 103
    if-ne v5, v7, :cond_4

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_4
    move v4, v2

    .line 107
    :cond_5
    :goto_1
    or-int/2addr v3, v4

    .line 108
    invoke-virtual {v0, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    or-int/2addr v3, v4

    .line 113
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    or-int/2addr v3, v4

    .line 118
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    if-nez v3, :cond_6

    .line 123
    .line 124
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 125
    .line 126
    if-ne v4, v3, :cond_7

    .line 127
    .line 128
    :cond_6
    new-instance v4, Lq0/f;

    .line 129
    .line 130
    const/4 v11, 0x2

    .line 131
    move-object v8, p0

    .line 132
    move-object v5, p1

    .line 133
    move-object v10, p2

    .line 134
    move-object v7, p3

    .line 135
    invoke-direct/range {v4 .. v11}, Lq0/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_7
    check-cast v4, Ljava/lang/Runnable;

    .line 142
    .line 143
    invoke-interface {v1, v4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 144
    .line 145
    .line 146
    :catch_0
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 147
    .line 148
    .line 149
    return-void

    .line 150
    :cond_8
    const p0, -0x1edd1e69

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0, p0}, Ll2/t;->Y(I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 157
    .line 158
    .line 159
    return-void
.end method

.method public static final b(I)Z
    .locals 3

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-lt p0, v0, :cond_2

    .line 5
    .line 6
    const/16 v0, 0x3e8

    .line 7
    .line 8
    if-ge p0, v0, :cond_2

    .line 9
    .line 10
    sget-object p0, Lt1/o;->b:Ljava/lang/Boolean;

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-nez p0, :cond_1

    .line 14
    .line 15
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Runtime;->availableProcessors()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    const/4 v2, 0x4

    .line 24
    if-lt p0, v2, :cond_0

    .line 25
    .line 26
    move p0, v0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move p0, v1

    .line 29
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    sput-object p0, Lt1/o;->b:Ljava/lang/Boolean;

    .line 34
    .line 35
    :cond_1
    sget-object p0, Lt1/o;->b:Ljava/lang/Boolean;

    .line 36
    .line 37
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_2

    .line 45
    .line 46
    return v0

    .line 47
    :cond_2
    return v1
.end method
