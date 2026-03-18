.class public final Landroidx/lifecycle/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Landroidx/lifecycle/s0;

.field public f:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Landroidx/lifecycle/s0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/lifecycle/t0;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/lifecycle/t0;->e:Landroidx/lifecycle/s0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroidx/lifecycle/r;Lra/d;)V
    .locals 1

    .line 1
    const-string v0, "registry"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "lifecycle"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-boolean v0, p0, Landroidx/lifecycle/t0;->f:Z

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    iput-boolean v0, p0, Landroidx/lifecycle/t0;->f:Z

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Landroidx/lifecycle/t0;->e:Landroidx/lifecycle/s0;

    .line 22
    .line 23
    iget-object p1, p1, Landroidx/lifecycle/s0;->b:Landroidx/lifecycle/c1;

    .line 24
    .line 25
    iget-object p1, p1, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Lb/i;

    .line 28
    .line 29
    iget-object p0, p0, Landroidx/lifecycle/t0;->d:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {p2, p0, p1}, Lra/d;->c(Ljava/lang/String;Lra/c;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string p1, "Already attached to lifecycleOwner"

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public final close()V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 1

    .line 1
    sget-object v0, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 2
    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    iput-boolean p2, p0, Landroidx/lifecycle/t0;->f:Z

    .line 7
    .line 8
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-virtual {p1, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
