.class public final synthetic Lkg/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lkg/d;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/d;->a:Lkg/d;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.Condition"

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "caption"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "value"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "subcaption"

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "description"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    sput-object v1, Lkg/d;->descriptor:Lsz0/g;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

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
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x4

    .line 12
    new-array v2, v2, [Lqz0/a;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    aput-object p0, v2, v3

    .line 16
    .line 17
    const/4 v3, 0x1

    .line 18
    aput-object p0, v2, v3

    .line 19
    .line 20
    const/4 p0, 0x2

    .line 21
    aput-object v0, v2, p0

    .line 22
    .line 23
    const/4 p0, 0x3

    .line 24
    aput-object v1, v2, p0

    .line 25
    .line 26
    return-object v2
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object p0, Lkg/d;->descriptor:Lsz0/g;

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
    move v5, v1

    .line 11
    move-object v4, v2

    .line 12
    move-object v6, v4

    .line 13
    move-object v7, v6

    .line 14
    move-object v8, v7

    .line 15
    move v2, v0

    .line 16
    :goto_0
    if-eqz v2, :cond_5

    .line 17
    .line 18
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/4 v9, -0x1

    .line 23
    if-eq v3, v9, :cond_4

    .line 24
    .line 25
    if-eqz v3, :cond_3

    .line 26
    .line 27
    if-eq v3, v0, :cond_2

    .line 28
    .line 29
    const/4 v9, 0x2

    .line 30
    if-eq v3, v9, :cond_1

    .line 31
    .line 32
    const/4 v9, 0x3

    .line 33
    if-ne v3, v9, :cond_0

    .line 34
    .line 35
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 36
    .line 37
    invoke-interface {p1, p0, v9, v3, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    move-object v8, v3

    .line 42
    check-cast v8, Ljava/lang/String;

    .line 43
    .line 44
    or-int/lit8 v5, v5, 0x8

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    new-instance p0, Lqz0/k;

    .line 48
    .line 49
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_1
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 54
    .line 55
    invoke-interface {p1, p0, v9, v3, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    move-object v7, v3

    .line 60
    check-cast v7, Ljava/lang/String;

    .line 61
    .line 62
    or-int/lit8 v5, v5, 0x4

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    or-int/lit8 v5, v5, 0x2

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    or-int/lit8 v5, v5, 0x1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_4
    move v2, v1

    .line 80
    goto :goto_0

    .line 81
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 82
    .line 83
    .line 84
    new-instance v3, Lkg/f;

    .line 85
    .line 86
    invoke-direct/range {v3 .. v8}, Lkg/f;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    return-object v3
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lkg/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lkg/f;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lkg/d;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v0, p2, Lkg/f;->d:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v1, p2, Lkg/f;->g:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lkg/f;->f:Ljava/lang/String;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-interface {p1, p0, v3, v0}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    iget-object p2, p2, Lkg/f;->e:Ljava/lang/String;

    .line 26
    .line 27
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    if-eqz p2, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    if-eqz v2, :cond_1

    .line 38
    .line 39
    :goto_0
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 40
    .line 41
    const/4 v0, 0x2

    .line 42
    invoke-interface {p1, p0, v0, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    if-eqz v1, :cond_3

    .line 53
    .line 54
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 55
    .line 56
    const/4 v0, 0x3

    .line 57
    invoke-interface {p1, p0, v0, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 61
    .line 62
    .line 63
    return-void
.end method
