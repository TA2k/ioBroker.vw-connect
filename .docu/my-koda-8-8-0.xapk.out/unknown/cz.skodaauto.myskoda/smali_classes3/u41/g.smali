.class public final synthetic Lu41/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lu41/g;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lu41/g;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lu41/g;->a:Lu41/g;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.capabilities.Operation"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "id"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "scopes"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "requiredUserRole"

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "securePIN"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "status"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Lu41/g;->descriptor:Lsz0/g;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lu41/l;->f:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    sget-object v2, Lu41/i;->a:Lu41/i;

    .line 8
    .line 9
    aput-object v2, v0, v1

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    aget-object v2, p0, v1

    .line 13
    .line 14
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    aput-object v2, v0, v1

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    aget-object v2, p0, v1

    .line 22
    .line 23
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lqz0/a;

    .line 28
    .line 29
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    aput-object v2, v0, v1

    .line 34
    .line 35
    const/4 v1, 0x3

    .line 36
    sget-object v2, Luz0/g;->a:Luz0/g;

    .line 37
    .line 38
    aput-object v2, v0, v1

    .line 39
    .line 40
    const/4 v1, 0x4

    .line 41
    aget-object p0, p0, v1

    .line 42
    .line 43
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    aput-object p0, v0, v1

    .line 48
    .line 49
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lu41/g;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lu41/l;->f:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v4, v1

    .line 13
    move v6, v2

    .line 14
    move v10, v6

    .line 15
    move-object v7, v3

    .line 16
    move-object v8, v7

    .line 17
    move-object v9, v8

    .line 18
    move-object v11, v9

    .line 19
    :goto_0
    if-eqz v4, :cond_8

    .line 20
    .line 21
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    const/4 v12, -0x1

    .line 26
    if-eq v5, v12, :cond_7

    .line 27
    .line 28
    if-eqz v5, :cond_4

    .line 29
    .line 30
    if-eq v5, v1, :cond_3

    .line 31
    .line 32
    const/4 v12, 0x2

    .line 33
    if-eq v5, v12, :cond_2

    .line 34
    .line 35
    const/4 v12, 0x3

    .line 36
    if-eq v5, v12, :cond_1

    .line 37
    .line 38
    const/4 v12, 0x4

    .line 39
    if-ne v5, v12, :cond_0

    .line 40
    .line 41
    aget-object v5, v0, v12

    .line 42
    .line 43
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v5

    .line 47
    check-cast v5, Lqz0/a;

    .line 48
    .line 49
    invoke-interface {p1, p0, v12, v5, v11}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    move-object v11, v5

    .line 54
    check-cast v11, Ljava/util/List;

    .line 55
    .line 56
    or-int/lit8 v6, v6, 0x10

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    new-instance p0, Lqz0/k;

    .line 60
    .line 61
    invoke-direct {p0, v5}, Lqz0/k;-><init>(I)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_1
    invoke-interface {p1, p0, v12}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    or-int/lit8 v6, v6, 0x8

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_2
    aget-object v5, v0, v12

    .line 73
    .line 74
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    check-cast v5, Lqz0/a;

    .line 79
    .line 80
    invoke-interface {p1, p0, v12, v5, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    move-object v9, v5

    .line 85
    check-cast v9, Lu41/t;

    .line 86
    .line 87
    or-int/lit8 v6, v6, 0x4

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_3
    aget-object v5, v0, v1

    .line 91
    .line 92
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    check-cast v5, Lqz0/a;

    .line 97
    .line 98
    invoke-interface {p1, p0, v1, v5, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v5

    .line 102
    move-object v8, v5

    .line 103
    check-cast v8, Ljava/util/Set;

    .line 104
    .line 105
    or-int/lit8 v6, v6, 0x2

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_4
    sget-object v5, Lu41/i;->a:Lu41/i;

    .line 109
    .line 110
    if-eqz v7, :cond_5

    .line 111
    .line 112
    new-instance v12, Lu41/k;

    .line 113
    .line 114
    invoke-direct {v12, v7}, Lu41/k;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_5
    move-object v12, v3

    .line 119
    :goto_1
    invoke-interface {p1, p0, v2, v5, v12}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    check-cast v5, Lu41/k;

    .line 124
    .line 125
    if-eqz v5, :cond_6

    .line 126
    .line 127
    iget-object v5, v5, Lu41/k;->a:Ljava/lang/String;

    .line 128
    .line 129
    move-object v7, v5

    .line 130
    goto :goto_2

    .line 131
    :cond_6
    move-object v7, v3

    .line 132
    :goto_2
    or-int/lit8 v6, v6, 0x1

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_7
    move v4, v2

    .line 136
    goto :goto_0

    .line 137
    :cond_8
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 138
    .line 139
    .line 140
    new-instance v5, Lu41/l;

    .line 141
    .line 142
    invoke-direct/range {v5 .. v11}, Lu41/l;-><init>(ILjava/lang/String;Ljava/util/Set;Lu41/t;ZLjava/util/List;)V

    .line 143
    .line 144
    .line 145
    return-object v5
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lu41/g;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Lu41/l;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lu41/g;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lu41/l;->f:[Llx0/i;

    .line 15
    .line 16
    sget-object v1, Lu41/i;->a:Lu41/i;

    .line 17
    .line 18
    iget-object v2, p2, Lu41/l;->a:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p2, Lu41/l;->e:Ljava/util/List;

    .line 21
    .line 22
    iget-boolean v4, p2, Lu41/l;->d:Z

    .line 23
    .line 24
    iget-object v5, p2, Lu41/l;->c:Lu41/t;

    .line 25
    .line 26
    new-instance v6, Lu41/k;

    .line 27
    .line 28
    invoke-direct {v6, v2}, Lu41/k;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    invoke-interface {p1, p0, v2, v1, v6}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    aget-object v2, v0, v1

    .line 37
    .line 38
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Lqz0/a;

    .line 43
    .line 44
    iget-object p2, p2, Lu41/l;->b:Ljava/util/Set;

    .line 45
    .line 46
    invoke-interface {p1, p0, v1, v2, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    if-eqz p2, :cond_0

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    if-eqz v5, :cond_1

    .line 57
    .line 58
    :goto_0
    const/4 p2, 0x2

    .line 59
    aget-object v1, v0, p2

    .line 60
    .line 61
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    check-cast v1, Lqz0/a;

    .line 66
    .line 67
    invoke-interface {p1, p0, p2, v1, v5}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    if-eqz p2, :cond_2

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_2
    if-eqz v4, :cond_3

    .line 78
    .line 79
    :goto_1
    const/4 p2, 0x3

    .line 80
    invoke-interface {p1, p0, p2, v4}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 81
    .line 82
    .line 83
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    if-eqz p2, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 91
    .line 92
    invoke-static {v3, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    if-nez p2, :cond_5

    .line 97
    .line 98
    :goto_2
    const/4 p2, 0x4

    .line 99
    aget-object v0, v0, p2

    .line 100
    .line 101
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    check-cast v0, Lqz0/a;

    .line 106
    .line 107
    invoke-interface {p1, p0, p2, v0, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_5
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 111
    .line 112
    .line 113
    return-void
.end method
