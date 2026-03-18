.class public abstract Lzy0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Lkotlin/coroutines/Continuation;

.field public static final b:Lj51/i;

.field public static final c:Lj51/i;

.field public static final d:Lj51/i;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Lkotlin/coroutines/Continuation;

    .line 3
    .line 4
    sput-object v0, Lzy0/c;->a:[Lkotlin/coroutines/Continuation;

    .line 5
    .line 6
    new-instance v0, Lj51/i;

    .line 7
    .line 8
    const-string v1, "NULL"

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lzy0/c;->b:Lj51/i;

    .line 15
    .line 16
    new-instance v0, Lj51/i;

    .line 17
    .line 18
    const-string v1, "UNINITIALIZED"

    .line 19
    .line 20
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lzy0/c;->c:Lj51/i;

    .line 24
    .line 25
    new-instance v0, Lj51/i;

    .line 26
    .line 27
    const-string v1, "DONE"

    .line 28
    .line 29
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lzy0/c;->d:Lj51/i;

    .line 33
    .line 34
    return-void
.end method

.method public static final a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lci0/c;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    move-object v1, p0

    .line 5
    move-object v2, p1

    .line 6
    move-object v4, p3

    .line 7
    move-object v5, p4

    .line 8
    invoke-direct/range {v0 .. v5}, Lci0/c;-><init>(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lvy0/y1;

    .line 12
    .line 13
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const/4 p3, 0x1

    .line 18
    invoke-direct {p0, p1, p2, p3}, Lvy0/y1;-><init>(Lpx0/g;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    invoke-static {p0, p1, p0, v0}, Ljp/rb;->a(Laz0/p;ZLaz0/p;Lay0/n;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 27
    .line 28
    if-ne p0, p1, :cond_0

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method

.method public static synthetic b(Lzy0/o;Lpx0/g;ILxy0/a;I)Lyy0/i;
    .locals 1

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p1, Lpx0/h;->d:Lpx0/h;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p4, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    const/4 p2, -0x3

    .line 12
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 13
    .line 14
    if-eqz p4, :cond_2

    .line 15
    .line 16
    sget-object p3, Lxy0/a;->d:Lxy0/a;

    .line 17
    .line 18
    :cond_2
    invoke-interface {p0, p1, p2, p3}, Lzy0/o;->b(Lpx0/g;ILxy0/a;)Lyy0/i;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public static final c(Lpx0/g;Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-static {p0, p2}, Laz0/b;->n(Lpx0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    :try_start_0
    new-instance v0, Lzy0/v;

    .line 6
    .line 7
    invoke-direct {v0, p4, p0}, Lzy0/v;-><init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V

    .line 8
    .line 9
    .line 10
    if-nez p3, :cond_0

    .line 11
    .line 12
    invoke-static {p3, p1, v0}, Ljp/hg;->e(Lay0/n;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p1

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    const/4 v1, 0x2

    .line 20
    invoke-static {v1, p3}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {p3, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    :goto_0
    invoke-static {p0, p2}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    if-ne p1, p0, :cond_1

    .line 33
    .line 34
    const-string p0, "frame"

    .line 35
    .line 36
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    return-object p1

    .line 40
    :goto_1
    invoke-static {p0, p2}, Laz0/b;->g(Lpx0/g;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    throw p1
.end method
