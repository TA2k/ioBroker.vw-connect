.class public final Landroidx/fragment/app/n0;
.super Landroidx/fragment/app/t0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ln5/c;
.implements Ln5/d;
.implements Landroidx/core/app/i0;
.implements Landroidx/core/app/j0;
.implements Landroidx/lifecycle/i1;
.implements Lb/j0;
.implements Le/i;
.implements Lra/f;
.implements Landroidx/fragment/app/o1;
.implements Ld6/k;


# instance fields
.field public final synthetic h:Landroidx/fragment/app/o0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/o0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Landroidx/fragment/app/t0;-><init>(Landroidx/fragment/app/o0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Landroidx/fragment/app/j0;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/fragment/app/o0;->onAttachFragment(Landroidx/fragment/app/j0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addMenuProvider(Ld6/o;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->addMenuProvider(Ld6/o;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addOnConfigurationChangedListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->addOnConfigurationChangedListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addOnMultiWindowModeChangedListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->addOnMultiWindowModeChangedListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addOnPictureInPictureModeChangedListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->addOnPictureInPictureModeChangedListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final addOnTrimMemoryListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->addOnTrimMemoryListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/app/Activity;->findViewById(I)Landroid/view/View;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final c()Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/Window;->peekDecorView()Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final getActivityResultRegistry()Le/h;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/r;->getActivityResultRegistry()Le/h;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getLifecycle()Landroidx/lifecycle/r;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/fragment/app/o0;->mFragmentLifecycleRegistry:Landroidx/lifecycle/z;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getOnBackPressedDispatcher()Lb/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/r;->getOnBackPressedDispatcher()Lb/h0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getSavedStateRegistry()Lra/d;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/r;->getSavedStateRegistry()Lra/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getViewModelStore()Landroidx/lifecycle/h1;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/r;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final removeMenuProvider(Ld6/o;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->removeMenuProvider(Ld6/o;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeOnConfigurationChangedListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->removeOnConfigurationChangedListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeOnMultiWindowModeChangedListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->removeOnMultiWindowModeChangedListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeOnPictureInPictureModeChangedListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->removeOnPictureInPictureModeChangedListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final removeOnTrimMemoryListener(Lc6/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lb/r;->removeOnTrimMemoryListener(Lc6/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
