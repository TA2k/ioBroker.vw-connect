.class public final Lak0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lck0/b;
.implements Lme0/a;


# instance fields
.field public final a:Lez0/c;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lak0/b;->a:Lez0/c;

    .line 9
    .line 10
    new-instance v0, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lak0/b;->b:Ljava/util/ArrayList;

    .line 16
    .line 17
    new-instance v0, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lak0/b;->c:Ljava/util/ArrayList;

    .line 23
    .line 24
    iput-object v0, p0, Lak0/b;->d:Ljava/util/ArrayList;

    .line 25
    .line 26
    return-void
.end method

.method public static c(Ljava/util/ArrayList;Ldk0/a;)Z
    .locals 3

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_2

    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Ldk0/a;

    .line 25
    .line 26
    iget-object v1, v0, Ldk0/a;->a:Ljava/lang/String;

    .line 27
    .line 28
    iget-object v2, p1, Ldk0/a;->a:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    iget-object v0, v0, Ldk0/a;->b:Ldk0/b;

    .line 37
    .line 38
    iget-object v1, p1, Ldk0/a;->b:Ldk0/b;

    .line 39
    .line 40
    if-ne v0, v1, :cond_1

    .line 41
    .line 42
    const/4 p0, 0x0

    .line 43
    return p0

    .line 44
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 45
    return p0
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p1, p0, Lak0/b;->c:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lak0/b;->b:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method public final b(Ldk0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lak0/b;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    instance-of v1, p2, Lak0/a;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lak0/a;

    .line 9
    .line 10
    iget v2, v1, Lak0/a;->h:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lak0/a;->h:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lak0/a;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lak0/a;-><init>(Lak0/b;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lak0/a;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lak0/a;->h:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    iget-object p1, v1, Lak0/a;->e:Lez0/c;

    .line 39
    .line 40
    iget-object v1, v1, Lak0/a;->d:Ldk0/a;

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    move-object p2, p1

    .line 46
    move-object p1, v1

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iput-object p1, v1, Lak0/a;->d:Ldk0/a;

    .line 60
    .line 61
    iget-object p2, p0, Lak0/b;->a:Lez0/c;

    .line 62
    .line 63
    iput-object p2, v1, Lak0/a;->e:Lez0/c;

    .line 64
    .line 65
    iput v4, v1, Lak0/a;->h:I

    .line 66
    .line 67
    invoke-virtual {p2, v1}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    if-ne v1, v2, :cond_3

    .line 72
    .line 73
    return-object v2

    .line 74
    :cond_3
    :goto_1
    const/4 v1, 0x0

    .line 75
    :try_start_0
    invoke-static {v0, p1}, Lak0/b;->c(Ljava/util/ArrayList;Ldk0/a;)Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-eqz v2, :cond_4

    .line 80
    .line 81
    iget-object v2, p0, Lak0/b;->d:Ljava/util/ArrayList;

    .line 82
    .line 83
    invoke-static {v2, p1}, Lak0/b;->c(Ljava/util/ArrayList;Ldk0/a;)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_4

    .line 88
    .line 89
    iget-object p0, p0, Lak0/b;->c:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :catchall_0
    move-exception p0

    .line 99
    goto :goto_3

    .line 100
    :cond_4
    :goto_2
    invoke-interface {p2, v1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    :goto_3
    invoke-interface {p2, v1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    throw p0
.end method
