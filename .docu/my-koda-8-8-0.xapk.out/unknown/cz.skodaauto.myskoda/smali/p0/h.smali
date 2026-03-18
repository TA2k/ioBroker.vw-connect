.class public final synthetic Lp0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk0/a;


# instance fields
.field public final synthetic d:Lp0/k;

.field public final synthetic e:Lp0/j;

.field public final synthetic f:I

.field public final synthetic g:Lb0/g;

.field public final synthetic h:Lb0/g;


# direct methods
.method public synthetic constructor <init>(Lp0/k;Lp0/j;ILb0/g;Lb0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp0/h;->d:Lp0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lp0/h;->e:Lp0/j;

    .line 7
    .line 8
    iput p3, p0, Lp0/h;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Lp0/h;->g:Lb0/g;

    .line 11
    .line 12
    iput-object p5, p0, Lp0/h;->h:Lb0/g;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 7

    .line 1
    iget-object v0, p0, Lp0/h;->e:Lp0/j;

    .line 2
    .line 3
    move-object v2, p1

    .line 4
    check-cast v2, Landroid/view/Surface;

    .line 5
    .line 6
    iget-object p1, p0, Lp0/h;->d:Lp0/k;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    :try_start_0
    invoke-virtual {v0}, Lh0/t0;->d()V
    :try_end_0
    .catch Lh0/s0; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    new-instance v1, Lp0/l;

    .line 18
    .line 19
    iget-object p1, p1, Lp0/k;->g:Lh0/k;

    .line 20
    .line 21
    iget-object v4, p1, Lh0/k;->a:Landroid/util/Size;

    .line 22
    .line 23
    iget v3, p0, Lp0/h;->f:I

    .line 24
    .line 25
    iget-object v5, p0, Lp0/h;->g:Lb0/g;

    .line 26
    .line 27
    iget-object v6, p0, Lp0/h;->h:Lb0/g;

    .line 28
    .line 29
    invoke-direct/range {v1 .. v6}, Lp0/l;-><init>(Landroid/view/Surface;ILandroid/util/Size;Lb0/g;Lb0/g;)V

    .line 30
    .line 31
    .line 32
    new-instance p0, Lp0/f;

    .line 33
    .line 34
    const/4 p1, 0x1

    .line 35
    invoke-direct {p0, v0, p1}, Lp0/f;-><init>(Lp0/j;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iget-object v2, v1, Lp0/l;->n:Ly4/k;

    .line 43
    .line 44
    iget-object v2, v2, Ly4/k;->e:Ly4/j;

    .line 45
    .line 46
    invoke-virtual {v2, p1, p0}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 47
    .line 48
    .line 49
    iget-object p0, v0, Lp0/j;->r:Lp0/l;

    .line 50
    .line 51
    if-nez p0, :cond_0

    .line 52
    .line 53
    const/4 p0, 0x1

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    const/4 p0, 0x0

    .line 56
    :goto_0
    const-string p1, "Consumer can only be linked once."

    .line 57
    .line 58
    invoke-static {p1, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 59
    .line 60
    .line 61
    iput-object v1, v0, Lp0/j;->r:Lp0/l;

    .line 62
    .line 63
    invoke-static {v1}, Lk0/h;->c(Ljava/lang/Object;)Lk0/j;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :catch_0
    move-exception v0

    .line 69
    move-object p0, v0

    .line 70
    new-instance p1, Lk0/j;

    .line 71
    .line 72
    const/4 v0, 0x1

    .line 73
    invoke-direct {p1, p0, v0}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    return-object p1
.end method
