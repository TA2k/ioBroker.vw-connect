.class public final Landroidx/glance/session/SessionWorker;
.super Landroidx/work/CoroutineWorker;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B5\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\u0008\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000c\u0010\rB\u0019\u0008\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u000c\u0010\u000e\u00a8\u0006\u000f"
    }
    d2 = {
        "Landroidx/glance/session/SessionWorker;",
        "Landroidx/work/CoroutineWorker;",
        "Landroid/content/Context;",
        "appContext",
        "Landroidx/work/WorkerParameters;",
        "params",
        "Lh7/h;",
        "sessionManager",
        "Lh7/x;",
        "timeouts",
        "Lvy0/x;",
        "coroutineContext",
        "<init>",
        "(Landroid/content/Context;Landroidx/work/WorkerParameters;Lh7/h;Lh7/x;Lvy0/x;)V",
        "(Landroid/content/Context;Landroidx/work/WorkerParameters;)V",
        "glance_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final j:Landroidx/work/WorkerParameters;

.field public final k:Lh7/h;

.field public final l:Lh7/x;

.field public final m:Lvy0/x;

.field public final n:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V
    .locals 8

    .line 13
    sget-object v3, Lh7/n;->a:Lh7/m;

    const/16 v6, 0x18

    const/4 v7, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    .line 14
    invoke-direct/range {v0 .. v7}, Landroidx/glance/session/SessionWorker;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;Lh7/h;Lh7/x;Lvy0/x;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;Lh7/h;Lh7/x;Lvy0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Landroidx/work/CoroutineWorker;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V

    .line 2
    iput-object p2, p0, Landroidx/glance/session/SessionWorker;->j:Landroidx/work/WorkerParameters;

    .line 3
    iput-object p3, p0, Landroidx/glance/session/SessionWorker;->k:Lh7/h;

    .line 4
    iput-object p4, p0, Landroidx/glance/session/SessionWorker;->l:Lh7/x;

    .line 5
    iput-object p5, p0, Landroidx/glance/session/SessionWorker;->m:Lvy0/x;

    .line 6
    iget-object p1, p0, Leb/v;->e:Landroidx/work/WorkerParameters;

    .line 7
    iget-object p1, p1, Landroidx/work/WorkerParameters;->b:Leb/h;

    .line 8
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p2, "KEY"

    .line 9
    iget-object p1, p1, Leb/h;->a:Ljava/util/HashMap;

    .line 10
    invoke-virtual {p1, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    instance-of p2, p1, Ljava/lang/String;

    if-eqz p2, :cond_0

    check-cast p1, Ljava/lang/String;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    .line 11
    iput-object p1, p0, Landroidx/glance/session/SessionWorker;->n:Ljava/lang/String;

    return-void

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 12
    const-string p1, "SessionWorker must be started with a key"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;Lh7/h;Lh7/x;Lvy0/x;ILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p7, p6, 0x4

    if-eqz p7, :cond_0

    .line 15
    sget-object p3, Lh7/n;->a:Lh7/m;

    :cond_0
    move-object v3, p3

    and-int/lit8 p3, p6, 0x8

    if-eqz p3, :cond_1

    .line 16
    new-instance p4, Lh7/x;

    invoke-direct {p4}, Lh7/x;-><init>()V

    :cond_1
    move-object v4, p4

    and-int/lit8 p3, p6, 0x10

    if-eqz p3, :cond_2

    .line 17
    sget-object p3, Lvy0/p0;->a:Lcz0/e;

    .line 18
    sget-object p5, Laz0/m;->a:Lwy0/c;

    :cond_2
    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v5, p5

    .line 19
    invoke-direct/range {v0 .. v5}, Landroidx/glance/session/SessionWorker;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;Lh7/h;Lh7/x;Lvy0/x;)V

    return-void
.end method


# virtual methods
.method public final d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lh7/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lh7/o;

    .line 7
    .line 8
    iget v1, v0, Lh7/o;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lh7/o;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh7/o;

    .line 21
    .line 22
    check-cast p1, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p1}, Lh7/o;-><init>(Landroidx/glance/session/SessionWorker;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v0, Lh7/o;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lh7/o;->f:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Landroidx/glance/session/SessionWorker;->l:Lh7/x;

    .line 54
    .line 55
    iget-object p1, p1, Lh7/x;->d:Lf3/d;

    .line 56
    .line 57
    new-instance v2, Lh40/w3;

    .line 58
    .line 59
    const/4 v4, 0x0

    .line 60
    const/16 v5, 0xd

    .line 61
    .line 62
    invoke-direct {v2, p0, v4, v5}, Lh40/w3;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 63
    .line 64
    .line 65
    iput v3, v0, Lh7/o;->f:I

    .line 66
    .line 67
    invoke-static {p1, v2, v0}, Llp/p0;->a(Lf3/d;Lh40/w3;Lrx0/c;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    if-ne p1, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    :goto_1
    check-cast p1, Leb/u;

    .line 75
    .line 76
    if-nez p1, :cond_4

    .line 77
    .line 78
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 79
    .line 80
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 81
    .line 82
    .line 83
    const-string p1, "TIMEOUT_EXIT_REASON"

    .line 84
    .line 85
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 86
    .line 87
    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    new-instance p1, Leb/h;

    .line 91
    .line 92
    invoke-direct {p1, p0}, Leb/h;-><init>(Ljava/util/LinkedHashMap;)V

    .line 93
    .line 94
    .line 95
    invoke-static {p1}, Lkp/b6;->d(Leb/h;)[B

    .line 96
    .line 97
    .line 98
    new-instance p0, Leb/t;

    .line 99
    .line 100
    invoke-direct {p0, p1}, Leb/t;-><init>(Leb/h;)V

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :cond_4
    return-object p1
.end method

.method public final e()Lvy0/x;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/glance/session/SessionWorker;->m:Lvy0/x;

    .line 2
    .line 3
    return-object p0
.end method
