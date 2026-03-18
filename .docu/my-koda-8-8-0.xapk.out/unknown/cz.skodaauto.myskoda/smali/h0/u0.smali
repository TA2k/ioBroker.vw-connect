.class public final Lh0/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk0/c;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly4/h;


# direct methods
.method public synthetic constructor <init>(Ly4/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh0/u0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh0/u0;->e:Ly4/h;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lh0/u0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh0/u0;->e:Ly4/h;

    .line 7
    .line 8
    :try_start_0
    invoke-virtual {p0, p1}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :catchall_0
    move-exception p1

    .line 13
    invoke-virtual {p0, p1}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 14
    .line 15
    .line 16
    :goto_0
    return-void

    .line 17
    :pswitch_0
    check-cast p1, Ljava/util/List;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    new-instance v0, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lh0/u0;->e:Ly4/h;

    .line 28
    .line 29
    invoke-virtual {p0, v0}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final y(Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    iget v0, p0, Lh0/u0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh0/u0;->e:Ly4/h;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    instance-of v0, p1, Ljava/util/concurrent/TimeoutException;

    .line 13
    .line 14
    iget-object p0, p0, Lh0/u0;->e:Ly4/h;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    :goto_0
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
