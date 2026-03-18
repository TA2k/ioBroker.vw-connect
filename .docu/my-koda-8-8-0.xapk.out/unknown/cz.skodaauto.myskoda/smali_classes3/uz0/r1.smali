.class public final Luz0/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# instance fields
.field public final a:Lqz0/a;

.field public final b:Lqz0/a;

.field public final c:Lqz0/a;

.field public final d:Lsz0/h;


# direct methods
.method public constructor <init>(Lqz0/a;Lqz0/a;Lqz0/a;)V
    .locals 1

    .line 1
    const-string v0, "aSerializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bSerializer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "cSerializer"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Luz0/r1;->a:Lqz0/a;

    .line 20
    .line 21
    iput-object p2, p0, Luz0/r1;->b:Lqz0/a;

    .line 22
    .line 23
    iput-object p3, p0, Luz0/r1;->c:Lqz0/a;

    .line 24
    .line 25
    const/4 p1, 0x0

    .line 26
    new-array p1, p1, [Lsz0/g;

    .line 27
    .line 28
    new-instance p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 29
    .line 30
    const/16 p3, 0xc

    .line 31
    .line 32
    invoke-direct {p2, p0, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    const-string p3, "kotlin.Triple"

    .line 36
    .line 37
    invoke-static {p3, p1, p2}, Lkp/x8;->c(Ljava/lang/String;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Luz0/r1;->d:Lsz0/h;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Luz0/r1;->d:Lsz0/h;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v1, Luz0/b1;->c:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    move-object v3, v2

    .line 11
    move-object v4, v3

    .line 12
    :goto_0
    invoke-interface {p1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 13
    .line 14
    .line 15
    move-result v5

    .line 16
    const/4 v6, -0x1

    .line 17
    if-eq v5, v6, :cond_3

    .line 18
    .line 19
    const/4 v6, 0x0

    .line 20
    if-eqz v5, :cond_2

    .line 21
    .line 22
    const/4 v7, 0x1

    .line 23
    if-eq v5, v7, :cond_1

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    if-ne v5, v4, :cond_0

    .line 27
    .line 28
    iget-object v5, p0, Luz0/r1;->c:Lqz0/a;

    .line 29
    .line 30
    check-cast v5, Lqz0/a;

    .line 31
    .line 32
    invoke-interface {p1, v0, v4, v5, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    new-instance p0, Lqz0/h;

    .line 38
    .line 39
    const-string p1, "Unexpected index "

    .line 40
    .line 41
    invoke-static {v5, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    iget-object v3, p0, Luz0/r1;->b:Lqz0/a;

    .line 50
    .line 51
    check-cast v3, Lqz0/a;

    .line 52
    .line 53
    invoke-interface {p1, v0, v7, v3, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    goto :goto_0

    .line 58
    :cond_2
    const/4 v2, 0x0

    .line 59
    iget-object v5, p0, Luz0/r1;->a:Lqz0/a;

    .line 60
    .line 61
    check-cast v5, Lqz0/a;

    .line 62
    .line 63
    invoke-interface {p1, v0, v2, v5, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    goto :goto_0

    .line 68
    :cond_3
    invoke-interface {p1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 69
    .line 70
    .line 71
    if-eq v2, v1, :cond_6

    .line 72
    .line 73
    if-eq v3, v1, :cond_5

    .line 74
    .line 75
    if-eq v4, v1, :cond_4

    .line 76
    .line 77
    new-instance p0, Llx0/r;

    .line 78
    .line 79
    invoke-direct {p0, v2, v3, v4}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_4
    new-instance p0, Lqz0/h;

    .line 84
    .line 85
    const-string p1, "Element \'third\' is missing"

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_5
    new-instance p0, Lqz0/h;

    .line 92
    .line 93
    const-string p1, "Element \'second\' is missing"

    .line 94
    .line 95
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_6
    new-instance p0, Lqz0/h;

    .line 100
    .line 101
    const-string p1, "Element \'first\' is missing"

    .line 102
    .line 103
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/r1;->d:Lsz0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Llx0/r;

    .line 2
    .line 3
    const-string v0, "value"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Luz0/r1;->d:Lsz0/h;

    .line 9
    .line 10
    invoke-interface {p1, v0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v1, p0, Luz0/r1;->a:Lqz0/a;

    .line 15
    .line 16
    check-cast v1, Lqz0/a;

    .line 17
    .line 18
    iget-object v2, p2, Llx0/r;->d:Ljava/lang/Object;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-interface {p1, v0, v3, v1, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Luz0/r1;->b:Lqz0/a;

    .line 25
    .line 26
    check-cast v1, Lqz0/a;

    .line 27
    .line 28
    iget-object v2, p2, Llx0/r;->e:Ljava/lang/Object;

    .line 29
    .line 30
    const/4 v3, 0x1

    .line 31
    invoke-interface {p1, v0, v3, v1, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Luz0/r1;->c:Lqz0/a;

    .line 35
    .line 36
    check-cast p0, Lqz0/a;

    .line 37
    .line 38
    iget-object p2, p2, Llx0/r;->f:Ljava/lang/Object;

    .line 39
    .line 40
    const/4 v1, 0x2

    .line 41
    invoke-interface {p1, v0, v1, p0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {p1, v0}, Ltz0/b;->b(Lsz0/g;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method
