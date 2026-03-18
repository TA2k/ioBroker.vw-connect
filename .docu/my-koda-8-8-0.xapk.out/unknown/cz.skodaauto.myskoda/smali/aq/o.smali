.class public final Laq/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/r;
.implements Laq/g;
.implements Laq/f;
.implements Laq/d;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/util/concurrent/Executor;

.field public final f:Laq/b;

.field public final g:Laq/t;


# direct methods
.method public synthetic constructor <init>(Ljava/util/concurrent/Executor;Laq/b;Laq/t;I)V
    .locals 0

    .line 1
    iput p4, p0, Laq/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laq/o;->e:Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    iput-object p2, p0, Laq/o;->f:Laq/b;

    .line 6
    .line 7
    iput-object p3, p0, Laq/o;->g:Laq/t;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Laq/j;)V
    .locals 3

    .line 1
    iget v0, p0, Laq/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llr/b;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-direct {v0, p0, p1, v2, v1}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Laq/o;->e:Ljava/util/concurrent/Executor;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    new-instance v0, Lk0/g;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-direct {v0, p0, p1, v2, v1}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Laq/o;->e:Ljava/util/concurrent/Executor;

    .line 27
    .line 28
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/o;->g:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/t;->o(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/o;->g:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public s()V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/o;->g:Laq/t;

    .line 2
    .line 3
    invoke-virtual {p0}, Laq/t;->p()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
