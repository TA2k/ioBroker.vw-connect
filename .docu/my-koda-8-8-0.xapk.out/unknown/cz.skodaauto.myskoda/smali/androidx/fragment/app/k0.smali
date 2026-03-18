.class public final synthetic Landroidx/fragment/app/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lra/c;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/fragment/app/k0;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/fragment/app/k0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Landroid/os/Bundle;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/fragment/app/k0;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/fragment/app/k0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->Y()Landroid/os/Bundle;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p0, Landroidx/fragment/app/o0;

    .line 16
    .line 17
    invoke-virtual {p0}, Landroidx/fragment/app/o0;->markFragmentsCreated()V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Landroidx/fragment/app/o0;->mFragmentLifecycleRegistry:Landroidx/lifecycle/z;

    .line 21
    .line 22
    sget-object v0, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 25
    .line 26
    .line 27
    new-instance p0, Landroid/os/Bundle;

    .line 28
    .line 29
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
