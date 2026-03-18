.class public final synthetic Lp0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lp0/j;


# direct methods
.method public synthetic constructor <init>(Lp0/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lp0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lp0/f;->e:Lp0/j;

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
    .locals 1

    .line 1
    iget v0, p0, Lp0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp0/f;->e:Lp0/j;

    .line 7
    .line 8
    iget-object v0, p0, Lp0/j;->r:Lp0/l;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Lp0/l;->d()V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lp0/j;->q:Lh0/t0;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Lp0/j;->p:Ly4/h;

    .line 20
    .line 21
    invoke-virtual {v0}, Ly4/h;->c()V

    .line 22
    .line 23
    .line 24
    :cond_1
    const/4 v0, 0x0

    .line 25
    iput-object v0, p0, Lp0/j;->q:Lh0/t0;

    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    iget-object p0, p0, Lp0/f;->e:Lp0/j;

    .line 29
    .line 30
    invoke-virtual {p0}, Lh0/t0;->b()V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_1
    iget-object p0, p0, Lp0/f;->e:Lp0/j;

    .line 35
    .line 36
    invoke-virtual {p0}, Lp0/j;->a()V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
