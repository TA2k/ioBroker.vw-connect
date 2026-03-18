.class public final Lb/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;
.implements Lb/d;


# instance fields
.field public final d:Landroidx/lifecycle/r;

.field public final e:Lb/a0;

.field public f:Lb/g0;

.field public final synthetic g:Lb/h0;


# direct methods
.method public constructor <init>(Lb/h0;Landroidx/lifecycle/r;Lb/a0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "onBackPressedCallback"

    .line 5
    .line 6
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lb/f0;->g:Lb/h0;

    .line 10
    .line 11
    iput-object p2, p0, Lb/f0;->d:Landroidx/lifecycle/r;

    .line 12
    .line 13
    iput-object p3, p0, Lb/f0;->e:Lb/a0;

    .line 14
    .line 15
    invoke-virtual {p2, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final cancel()V
    .locals 1

    .line 1
    iget-object v0, p0, Lb/f0;->d:Landroidx/lifecycle/r;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb/f0;->e:Lb/a0;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lb/a0;->removeCancellable(Lb/d;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lb/f0;->f:Lb/g0;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0}, Lb/g0;->cancel()V

    .line 16
    .line 17
    .line 18
    :cond_0
    const/4 v0, 0x0

    .line 19
    iput-object v0, p0, Lb/f0;->f:Lb/g0;

    .line 20
    .line 21
    return-void
.end method

.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 8

    .line 1
    sget-object p1, Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;

    .line 2
    .line 3
    if-ne p2, p1, :cond_0

    .line 4
    .line 5
    iget-object v2, p0, Lb/f0;->g:Lb/h0;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string p1, "onBackPressedCallback"

    .line 11
    .line 12
    iget-object p2, p0, Lb/f0;->e:Lb/a0;

    .line 13
    .line 14
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object p1, v2, Lb/h0;->b:Lmx0/l;

    .line 18
    .line 19
    invoke-virtual {p1, p2}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lb/g0;

    .line 23
    .line 24
    invoke-direct {p1, v2, p2}, Lb/g0;-><init>(Lb/h0;Lb/a0;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2, p1}, Lb/a0;->addCancellable(Lb/d;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Lb/h0;->e()V

    .line 31
    .line 32
    .line 33
    new-instance v0, La71/z;

    .line 34
    .line 35
    const/4 v6, 0x0

    .line 36
    const/16 v7, 0xb

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    const-class v3, Lb/h0;

    .line 40
    .line 41
    const-string v4, "updateEnabledCallbacks"

    .line 42
    .line 43
    const-string v5, "updateEnabledCallbacks()V"

    .line 44
    .line 45
    invoke-direct/range {v0 .. v7}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2, v0}, Lb/a0;->setEnabledChangedCallback$activity_release(Lay0/a;)V

    .line 49
    .line 50
    .line 51
    iput-object p1, p0, Lb/f0;->f:Lb/g0;

    .line 52
    .line 53
    return-void

    .line 54
    :cond_0
    sget-object p1, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 55
    .line 56
    if-ne p2, p1, :cond_1

    .line 57
    .line 58
    iget-object p0, p0, Lb/f0;->f:Lb/g0;

    .line 59
    .line 60
    if-eqz p0, :cond_2

    .line 61
    .line 62
    invoke-virtual {p0}, Lb/g0;->cancel()V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    sget-object p1, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 67
    .line 68
    if-ne p2, p1, :cond_2

    .line 69
    .line 70
    invoke-virtual {p0}, Lb/f0;->cancel()V

    .line 71
    .line 72
    .line 73
    :cond_2
    return-void
.end method
