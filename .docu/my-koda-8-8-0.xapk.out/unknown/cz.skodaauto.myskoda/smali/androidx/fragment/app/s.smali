.class public final Landroidx/fragment/app/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/fragment/app/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/fragment/app/s;->e:Ljava/lang/Object;

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
    iget v0, p0, Landroidx/fragment/app/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/fragment/app/s;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    iget-object p0, p0, Landroidx/fragment/app/s;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Landroidx/fragment/app/r;

    .line 18
    .line 19
    iget-object v0, p0, Landroidx/fragment/app/r;->b:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Landroidx/fragment/app/r;->e()V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void

    .line 31
    :pswitch_1
    iget-object p0, p0, Landroidx/fragment/app/s;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Landroidx/fragment/app/x;

    .line 34
    .line 35
    iget-object v0, p0, Landroidx/fragment/app/x;->g:Landroidx/fragment/app/u;

    .line 36
    .line 37
    iget-object p0, p0, Landroidx/fragment/app/x;->o:Landroid/app/Dialog;

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Landroidx/fragment/app/u;->onDismiss(Landroid/content/DialogInterface;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
