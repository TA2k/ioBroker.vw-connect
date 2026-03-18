.class public final synthetic Lje/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lje/f;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lje/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lje/f;->a:Lje/f;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "static"

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "currency"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "startsAt"

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "endsAt"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "seasons"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    new-instance v0, Lje/e;

    .line 39
    .line 40
    invoke-direct {v0, v2}, Lje/e;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v0}, Luz0/d1;->k(Ljava/lang/annotation/Annotation;)V

    .line 44
    .line 45
    .line 46
    sput-object v1, Lje/f;->descriptor:Lsz0/g;

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lje/h;->f:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    sget-object v2, Lje/p;->a:Lje/p;

    .line 8
    .line 9
    aput-object v2, v0, v1

    .line 10
    .line 11
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 12
    .line 13
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const/4 v3, 0x1

    .line 18
    aput-object v2, v0, v3

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    aput-object v1, v0, v2

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    aget-object p0, p0, v1

    .line 29
    .line 30
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    aput-object p0, v0, v1

    .line 35
    .line 36
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object p0, Lje/f;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lje/h;->f:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v5, v2

    .line 13
    move-object v6, v3

    .line 14
    move-object v7, v6

    .line 15
    move-object v8, v7

    .line 16
    move-object v9, v8

    .line 17
    move v3, v1

    .line 18
    :goto_0
    if-eqz v3, :cond_5

    .line 19
    .line 20
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    const/4 v10, -0x1

    .line 25
    if-eq v4, v10, :cond_4

    .line 26
    .line 27
    if-eqz v4, :cond_3

    .line 28
    .line 29
    if-eq v4, v1, :cond_2

    .line 30
    .line 31
    const/4 v10, 0x2

    .line 32
    if-eq v4, v10, :cond_1

    .line 33
    .line 34
    const/4 v10, 0x3

    .line 35
    if-ne v4, v10, :cond_0

    .line 36
    .line 37
    aget-object v4, v0, v10

    .line 38
    .line 39
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Lqz0/a;

    .line 44
    .line 45
    invoke-interface {p1, p0, v10, v4, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    move-object v9, v4

    .line 50
    check-cast v9, Ljava/util/List;

    .line 51
    .line 52
    or-int/lit8 v5, v5, 0x8

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    new-instance p0, Lqz0/k;

    .line 56
    .line 57
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_1
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 62
    .line 63
    invoke-interface {p1, p0, v10, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    move-object v8, v4

    .line 68
    check-cast v8, Ljava/lang/String;

    .line 69
    .line 70
    or-int/lit8 v5, v5, 0x4

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 74
    .line 75
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    move-object v7, v4

    .line 80
    check-cast v7, Ljava/lang/String;

    .line 81
    .line 82
    or-int/lit8 v5, v5, 0x2

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_3
    sget-object v4, Lje/p;->a:Lje/p;

    .line 86
    .line 87
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    move-object v6, v4

    .line 92
    check-cast v6, Lje/r;

    .line 93
    .line 94
    or-int/lit8 v5, v5, 0x1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_4
    move v3, v2

    .line 98
    goto :goto_0

    .line 99
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 100
    .line 101
    .line 102
    new-instance v4, Lje/h;

    .line 103
    .line 104
    invoke-direct/range {v4 .. v9}, Lje/h;-><init>(ILje/r;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 105
    .line 106
    .line 107
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lje/f;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Lje/h;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lje/f;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lje/h;->f:[Llx0/i;

    .line 15
    .line 16
    sget-object v1, Lje/p;->a:Lje/p;

    .line 17
    .line 18
    iget-object v2, p2, Lje/h;->b:Lje/r;

    .line 19
    .line 20
    iget-object v3, p2, Lje/h;->d:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v4, p2, Lje/h;->c:Ljava/lang/String;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    invoke-interface {p1, p0, v5, v1, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    if-eqz v4, :cond_1

    .line 36
    .line 37
    :goto_0
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 38
    .line 39
    const/4 v2, 0x1

    .line 40
    invoke-interface {p1, p0, v2, v1, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    if-eqz v3, :cond_3

    .line 51
    .line 52
    :goto_1
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 53
    .line 54
    const/4 v2, 0x2

    .line 55
    invoke-interface {p1, p0, v2, v1, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_3
    const/4 v1, 0x3

    .line 59
    aget-object v0, v0, v1

    .line 60
    .line 61
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    check-cast v0, Lqz0/a;

    .line 66
    .line 67
    iget-object p2, p2, Lje/h;->e:Ljava/util/List;

    .line 68
    .line 69
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method
