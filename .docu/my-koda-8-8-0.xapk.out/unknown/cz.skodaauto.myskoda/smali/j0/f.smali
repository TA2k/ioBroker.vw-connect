.class public final Lj0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static volatile f:Lj0/f;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lj0/f;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Lb0/n;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Lb0/n;-><init>(I)V

    const/4 v1, 0x2

    .line 4
    invoke-static {v1, v0}, Ljava/util/concurrent/Executors;->newFixedThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    iput-object v0, p0, Lj0/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lj0/f;->d:I

    iput-object p1, p0, Lj0/f;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 2

    .line 1
    iget v0, p0, Lj0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lj0/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lvp/j2;

    .line 9
    .line 10
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lvp/g1;

    .line 13
    .line 14
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 15
    .line 16
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    iget-object p0, p0, Lj0/f;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 26
    .line 27
    new-instance v0, Lhs/j;

    .line 28
    .line 29
    const/4 v1, 0x2

    .line 30
    invoke-direct {v0, p1, v1}, Lhs/j;-><init>(Ljava/lang/Runnable;I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_1
    iget-object p0, p0, Lj0/f;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Ljava/util/concurrent/ExecutorService;

    .line 40
    .line 41
    invoke-interface {p0, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
