.class public final Lmm/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmm/o;
.implements Landroidx/lifecycle/f;


# instance fields
.field public final synthetic d:I

.field public final e:Landroidx/lifecycle/r;

.field public final f:Lvy0/i1;


# direct methods
.method public synthetic constructor <init>(Landroidx/lifecycle/r;Lvy0/i1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmm/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmm/k;->e:Landroidx/lifecycle/r;

    .line 4
    .line 5
    iput-object p2, p0, Lmm/k;->f:Lvy0/i1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lmm/k;->e:Landroidx/lifecycle/r;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public b(Lyl/q;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lmm/k;->e:Landroidx/lifecycle/r;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lkp/i8;->b(Landroidx/lifecycle/r;Lrx0/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final onDestroy(Landroidx/lifecycle/x;)V
    .locals 0

    .line 1
    iget p1, p0, Lmm/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lmm/k;->f:Lvy0/i1;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    invoke-interface {p0, p1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :pswitch_0
    iget-object p0, p0, Lmm/k;->f:Lvy0/i1;

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    invoke-interface {p0, p1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public start()V
    .locals 1

    .line 1
    iget-object v0, p0, Lmm/k;->e:Landroidx/lifecycle/r;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
