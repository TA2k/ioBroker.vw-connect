.class public final synthetic Lp0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lp0/k;


# direct methods
.method public synthetic constructor <init>(Lp0/k;I)V
    .locals 0

    .line 1
    iput p2, p0, Lp0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lp0/e;->e:Lp0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lp0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp0/e;->e:Lp0/k;

    .line 7
    .line 8
    iget-boolean v0, p0, Lp0/k;->n:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lp0/k;->d()V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void

    .line 16
    :pswitch_0
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v1, Lp0/e;

    .line 21
    .line 22
    const/4 v2, 0x1

    .line 23
    iget-object p0, p0, Lp0/e;->e:Lp0/k;

    .line 24
    .line 25
    invoke-direct {v1, p0, v2}, Lp0/e;-><init>(Lp0/k;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lj0/c;->execute(Ljava/lang/Runnable;)V

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
