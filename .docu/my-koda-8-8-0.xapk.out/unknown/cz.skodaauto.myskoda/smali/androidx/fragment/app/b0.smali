.class public final Landroidx/fragment/app/b0;
.super Landroidx/fragment/app/h0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Landroidx/fragment/app/j0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/b0;->a:Landroidx/fragment/app/j0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/b0;->a:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j0;->mSavedStateRegistryController:Lra/e;

    .line 4
    .line 5
    invoke-virtual {v0}, Lra/e;->a()V

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Landroidx/lifecycle/v0;->c(Lra/f;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const-string v1, "registryState"

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    iget-object p0, p0, Landroidx/fragment/app/j0;->mSavedStateRegistryController:Lra/e;

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lra/e;->b(Landroid/os/Bundle;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
