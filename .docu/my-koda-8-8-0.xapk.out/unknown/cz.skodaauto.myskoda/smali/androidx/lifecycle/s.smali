.class public final Landroidx/lifecycle/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;
.implements Lvy0/b0;


# instance fields
.field public final d:Landroidx/lifecycle/r;

.field public final e:Lpx0/g;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/r;Lpx0/g;)V
    .locals 1

    .line 1
    const-string v0, "lifecycle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "coroutineContext"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Landroidx/lifecycle/s;->d:Landroidx/lifecycle/r;

    .line 15
    .line 16
    iput-object p2, p0, Landroidx/lifecycle/s;->e:Lpx0/g;

    .line 17
    .line 18
    invoke-virtual {p1}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 23
    .line 24
    if-ne p0, p1, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    invoke-static {p2, p0}, Lvy0/e0;->i(Lpx0/g;Ljava/util/concurrent/CancellationException;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 1

    .line 1
    iget-object p1, p0, Landroidx/lifecycle/s;->d:Landroidx/lifecycle/r;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    sget-object v0, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 8
    .line 9
    invoke-virtual {p2, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    if-gtz p2, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Landroidx/lifecycle/s;->e:Lpx0/g;

    .line 19
    .line 20
    const/4 p1, 0x0

    .line 21
    invoke-static {p0, p1}, Lvy0/e0;->i(Lpx0/g;Ljava/util/concurrent/CancellationException;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/s;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method
