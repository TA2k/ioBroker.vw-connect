.class public final synthetic Lh0/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lgw0/c;


# direct methods
.method public synthetic constructor <init>(Lgw0/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh0/f1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh0/f1;->e:Lgw0/c;

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
    .locals 2

    .line 1
    iget v0, p0, Lh0/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh0/f1;->e:Lgw0/c;

    .line 7
    .line 8
    iget-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lh0/g1;

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    new-instance v0, Lh0/g1;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-direct {v0, p0, v1}, Lh0/g1;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 21
    .line 22
    :cond_0
    iget-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Landroidx/lifecycle/i0;

    .line 25
    .line 26
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lh0/g1;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Landroidx/lifecycle/g0;->f(Landroidx/lifecycle/j0;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_0
    iget-object p0, p0, Lh0/f1;->e:Lgw0/c;

    .line 35
    .line 36
    iget-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lh0/g1;

    .line 39
    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Landroidx/lifecycle/i0;

    .line 45
    .line 46
    invoke-virtual {p0, v0}, Landroidx/lifecycle/g0;->i(Landroidx/lifecycle/j0;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    return-void

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
