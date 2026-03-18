.class public final Ln1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/o;


# instance fields
.field public final a:Ln1/v;


# direct methods
.method public constructor <init>(Ln1/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln1/d;->a:Ln1/v;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/d;->a:Ln1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p0, p0, Ln1/n;->p:I

    .line 8
    .line 9
    return p0
.end method

.method public final b()I
    .locals 15

    .line 1
    iget-object p0, p0, Ln1/d;->a:Ln1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v0, v0, Ln1/n;->m:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    return v1

    .line 17
    :cond_0
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object v2, v0, Ln1/n;->q:Lg1/w1;

    .line 22
    .line 23
    sget-object v3, Lg1/w1;->d:Lg1/w1;

    .line 24
    .line 25
    const/16 v4, 0x20

    .line 26
    .line 27
    const-wide v5, 0xffffffffL

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    if-ne v2, v3, :cond_1

    .line 33
    .line 34
    invoke-virtual {v0}, Ln1/n;->e()J

    .line 35
    .line 36
    .line 37
    move-result-wide v7

    .line 38
    and-long/2addr v7, v5

    .line 39
    :goto_0
    long-to-int v0, v7

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v0}, Ln1/n;->e()J

    .line 42
    .line 43
    .line 44
    move-result-wide v7

    .line 45
    shr-long/2addr v7, v4

    .line 46
    goto :goto_0

    .line 47
    :goto_1
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    iget-object v2, p0, Ln1/n;->q:Lg1/w1;

    .line 52
    .line 53
    const/4 v7, 0x1

    .line 54
    if-ne v2, v3, :cond_2

    .line 55
    .line 56
    move v2, v7

    .line 57
    goto :goto_2

    .line 58
    :cond_2
    move v2, v1

    .line 59
    :goto_2
    iget-object v3, p0, Ln1/n;->m:Ljava/lang/Object;

    .line 60
    .line 61
    move v8, v1

    .line 62
    move v9, v8

    .line 63
    move v10, v9

    .line 64
    :goto_3
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 65
    .line 66
    .line 67
    move-result v11

    .line 68
    if-ge v8, v11, :cond_6

    .line 69
    .line 70
    invoke-static {v2, p0, v8}, Ljp/s1;->a(ZLn1/n;I)I

    .line 71
    .line 72
    .line 73
    move-result v11

    .line 74
    const/4 v12, -0x1

    .line 75
    if-ne v11, v12, :cond_3

    .line 76
    .line 77
    add-int/lit8 v8, v8, 0x1

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    move v12, v1

    .line 81
    :goto_4
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 82
    .line 83
    .line 84
    move-result v13

    .line 85
    if-ge v8, v13, :cond_5

    .line 86
    .line 87
    invoke-static {v2, p0, v8}, Ljp/s1;->a(ZLn1/n;I)I

    .line 88
    .line 89
    .line 90
    move-result v13

    .line 91
    if-ne v13, v11, :cond_5

    .line 92
    .line 93
    if-eqz v2, :cond_4

    .line 94
    .line 95
    invoke-interface {v3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v13

    .line 99
    check-cast v13, Ln1/o;

    .line 100
    .line 101
    iget-wide v13, v13, Ln1/o;->s:J

    .line 102
    .line 103
    and-long/2addr v13, v5

    .line 104
    :goto_5
    long-to-int v13, v13

    .line 105
    goto :goto_6

    .line 106
    :cond_4
    invoke-interface {v3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v13

    .line 110
    check-cast v13, Ln1/o;

    .line 111
    .line 112
    iget-wide v13, v13, Ln1/o;->s:J

    .line 113
    .line 114
    shr-long/2addr v13, v4

    .line 115
    goto :goto_5

    .line 116
    :goto_6
    invoke-static {v12, v13}, Ljava/lang/Math;->max(II)I

    .line 117
    .line 118
    .line 119
    move-result v12

    .line 120
    add-int/lit8 v8, v8, 0x1

    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_5
    add-int/2addr v9, v12

    .line 124
    add-int/lit8 v10, v10, 0x1

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_6
    div-int/2addr v9, v10

    .line 128
    iget p0, p0, Ln1/n;->s:I

    .line 129
    .line 130
    add-int/2addr v9, p0

    .line 131
    if-nez v9, :cond_7

    .line 132
    .line 133
    goto :goto_7

    .line 134
    :cond_7
    div-int/2addr v0, v9

    .line 135
    if-ge v0, v7, :cond_8

    .line 136
    .line 137
    :goto_7
    return v7

    .line 138
    :cond_8
    return v0
.end method

.method public final c()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/d;->a:Ln1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Ln1/n;->m:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    xor-int/lit8 p0, p0, 0x1

    .line 16
    .line 17
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/d;->a:Ln1/v;

    .line 2
    .line 3
    iget-object p0, p0, Ln1/v;->d:Lm1/o;

    .line 4
    .line 5
    iget-object p0, p0, Lm1/o;->b:Ll2/g1;

    .line 6
    .line 7
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final e()I
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/d;->a:Ln1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Ln1/n;->m:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-static {p0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ln1/o;

    .line 14
    .line 15
    iget p0, p0, Ln1/o;->a:I

    .line 16
    .line 17
    return p0
.end method
