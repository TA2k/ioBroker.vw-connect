.class public final Lb0/o0;
.super Lb0/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lb0/a1;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lb0/o0;->g:I

    .line 1
    invoke-direct {p0, p1}, Lb0/b0;-><init>(Lb0/a1;)V

    .line 2
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Lb0/o0;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lb0/a1;Lb0/p0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb0/o0;->g:I

    .line 3
    invoke-direct {p0, p1}, Lb0/b0;-><init>(Lb0/a1;)V

    .line 4
    new-instance p1, Ljava/lang/ref/WeakReference;

    invoke-direct {p1, p2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lb0/o0;->h:Ljava/lang/Object;

    .line 5
    new-instance p1, Lb0/n0;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Lb0/n0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p0, p1}, Lb0/b0;->a(Lb0/a0;)V

    return-void
.end method


# virtual methods
.method public close()V
    .locals 2

    .line 1
    iget v0, p0, Lb0/o0;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lb0/b0;->close()V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object v0, p0, Lb0/o0;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    invoke-super {p0}, Lb0/b0;->close()V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void

    .line 25
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
