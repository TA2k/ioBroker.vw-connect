.class public final synthetic Lkg/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lkg/p;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/p;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/p;->a:Lkg/p;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.RemainingTime"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "text"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "localizedLabel"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "expiresSoon"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "isHighlighted"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "description"

    .line 38
    .line 39
    const/4 v2, 0x1

    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Lkg/p;->descriptor:Lsz0/g;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x5

    .line 8
    new-array v1, v1, [Lqz0/a;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    aput-object p0, v1, v2

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    aput-object p0, v1, v2

    .line 15
    .line 16
    sget-object p0, Luz0/g;->a:Luz0/g;

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    aput-object p0, v1, v2

    .line 20
    .line 21
    const/4 v2, 0x3

    .line 22
    aput-object p0, v1, v2

    .line 23
    .line 24
    const/4 p0, 0x4

    .line 25
    aput-object v0, v1, p0

    .line 26
    .line 27
    return-object v1
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object p0, Lkg/p;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v4, v1

    .line 11
    move v7, v4

    .line 12
    move v8, v7

    .line 13
    move-object v5, v2

    .line 14
    move-object v6, v5

    .line 15
    move-object v9, v6

    .line 16
    move v2, v0

    .line 17
    :goto_0
    if-eqz v2, :cond_6

    .line 18
    .line 19
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v10, -0x1

    .line 24
    if-eq v3, v10, :cond_5

    .line 25
    .line 26
    if-eqz v3, :cond_4

    .line 27
    .line 28
    if-eq v3, v0, :cond_3

    .line 29
    .line 30
    const/4 v10, 0x2

    .line 31
    if-eq v3, v10, :cond_2

    .line 32
    .line 33
    const/4 v10, 0x3

    .line 34
    if-eq v3, v10, :cond_1

    .line 35
    .line 36
    const/4 v10, 0x4

    .line 37
    if-ne v3, v10, :cond_0

    .line 38
    .line 39
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 40
    .line 41
    invoke-interface {p1, p0, v10, v3, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    move-object v9, v3

    .line 46
    check-cast v9, Ljava/lang/String;

    .line 47
    .line 48
    or-int/lit8 v4, v4, 0x10

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    new-instance p0, Lqz0/k;

    .line 52
    .line 53
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_1
    invoke-interface {p1, p0, v10}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    or-int/lit8 v4, v4, 0x8

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    invoke-interface {p1, p0, v10}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 65
    .line 66
    .line 67
    move-result v7

    .line 68
    or-int/lit8 v4, v4, 0x4

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_3
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    or-int/lit8 v4, v4, 0x2

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_4
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    or-int/lit8 v4, v4, 0x1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_5
    move v2, v1

    .line 86
    goto :goto_0

    .line 87
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 88
    .line 89
    .line 90
    new-instance v3, Lkg/r;

    .line 91
    .line 92
    invoke-direct/range {v3 .. v9}, Lkg/r;-><init>(ILjava/lang/String;Ljava/lang/String;ZZLjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-object v3
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lkg/p;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lkg/r;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lkg/p;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v0, p2, Lkg/r;->d:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v1, p2, Lkg/r;->h:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-interface {p1, p0, v2, v0}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    iget-object v2, p2, Lkg/r;->e:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    iget-boolean v2, p2, Lkg/r;->f:Z

    .line 30
    .line 31
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 32
    .line 33
    .line 34
    const/4 v0, 0x3

    .line 35
    iget-boolean p2, p2, Lkg/r;->g:Z

    .line 36
    .line 37
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 38
    .line 39
    .line 40
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-eqz p2, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    if-eqz v1, :cond_1

    .line 48
    .line 49
    :goto_0
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 50
    .line 51
    const/4 v0, 0x4

    .line 52
    invoke-interface {p1, p0, v0, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 56
    .line 57
    .line 58
    return-void
.end method
