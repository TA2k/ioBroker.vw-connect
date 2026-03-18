.class public final Lzb/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# instance fields
.field public final d:Lpx0/g;

.field public final e:Lvy0/z1;

.field public final f:Ljava/util/LinkedHashMap;


# direct methods
.method public constructor <init>(Lr7/a;)V
    .locals 2

    .line 1
    iget-object p1, p1, Lr7/a;->d:Lpx0/g;

    .line 2
    .line 3
    const-string v0, "context"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lvy0/h1;->d:Lvy0/h1;

    .line 12
    .line 13
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-interface {p1, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    :goto_0
    iput-object p1, p0, Lzb/k0;->d:Lpx0/g;

    .line 29
    .line 30
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p1, Lvy0/i1;

    .line 35
    .line 36
    new-instance v0, Lvy0/z1;

    .line 37
    .line 38
    invoke-direct {v0, p1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 39
    .line 40
    .line 41
    iput-object v0, p0, Lzb/k0;->e:Lvy0/z1;

    .line 42
    .line 43
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 44
    .line 45
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lzb/k0;->f:Ljava/util/LinkedHashMap;

    .line 49
    .line 50
    return-void
.end method

.method public static a(Lzb/k0;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lzb/k0;->f:Ljava/util/LinkedHashMap;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lvy0/i1;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static b(Lzb/k0;Lay0/n;)V
    .locals 5

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const-wide/16 v0, 0xfa

    .line 4
    .line 5
    sget-object v2, Lmy0/e;->g:Lmy0/e;

    .line 6
    .line 7
    invoke-static {v0, v1, v2}, Lmy0/h;->t(JLmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iget-object v2, p0, Lzb/k0;->d:Lpx0/g;

    .line 12
    .line 13
    sget-object v3, Lvy0/x;->d:Lvy0/w;

    .line 14
    .line 15
    invoke-interface {v2, v3}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Lvy0/x;

    .line 20
    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    sget-object v2, Lvy0/p0;->a:Lcz0/e;

    .line 24
    .line 25
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const-string v3, "dispatcher"

    .line 29
    .line 30
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v3, Lb1/c1;

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    invoke-direct {v3, v0, v1, p1, v4}, Lb1/c1;-><init>(JLay0/n;Lkotlin/coroutines/Continuation;)V

    .line 37
    .line 38
    .line 39
    const/4 p1, 0x4

    .line 40
    const-string v0, "UI_EVENT_TAG"

    .line 41
    .line 42
    invoke-static {p0, v0, v2, v3, p1}, Lzb/k0;->c(Lzb/k0;Ljava/lang/String;Lvy0/x;Lay0/n;I)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public static c(Lzb/k0;Ljava/lang/String;Lvy0/x;Lay0/n;I)V
    .locals 5

    .line 1
    and-int/lit8 p4, p4, 0x2

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p2, p0, Lzb/k0;->d:Lpx0/g;

    .line 6
    .line 7
    sget-object p4, Lvy0/x;->d:Lvy0/w;

    .line 8
    .line 9
    invoke-interface {p2, p4}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    check-cast p2, Lvy0/x;

    .line 14
    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 18
    .line 19
    :cond_0
    sget-object p4, Lvy0/c0;->d:Lvy0/c0;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const-string v0, "dispatcher"

    .line 25
    .line 26
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lzb/k0;->f:Ljava/util/LinkedHashMap;

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lvy0/i1;

    .line 36
    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    invoke-interface {v1}, Lvy0/i1;->isCancelled()Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    const/4 v3, 0x1

    .line 44
    if-ne v2, v3, :cond_1

    .line 45
    .line 46
    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    iget-object v2, p0, Lzb/k0;->e:Lvy0/z1;

    .line 51
    .line 52
    invoke-virtual {p2, v2}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    new-instance v2, Lg1/d3;

    .line 57
    .line 58
    const/4 v3, 0x0

    .line 59
    const/4 v4, 0x1

    .line 60
    invoke-direct {v2, v1, p3, v3, v4}, Lg1/d3;-><init>(Lvy0/i1;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {p0, p2, p4, v2}, Lvy0/e0;->D(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;)Lvy0/x1;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-interface {v0, p1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lzb/k0;->d:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method
