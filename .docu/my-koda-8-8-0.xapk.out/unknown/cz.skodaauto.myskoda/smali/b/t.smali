.class public Lb/t;
.super Landroid/app/Dialog;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/x;
.implements Lb/j0;
.implements Lra/f;


# instance fields
.field public d:Landroidx/lifecycle/z;

.field public final e:Lra/e;

.field public final f:Lb/h0;


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1, p2}, Landroid/app/Dialog;-><init>(Landroid/content/Context;I)V

    .line 7
    .line 8
    .line 9
    new-instance p1, Lg11/c;

    .line 10
    .line 11
    new-instance p2, Lr1/b;

    .line 12
    .line 13
    const/4 v0, 0x6

    .line 14
    invoke-direct {p2, p0, v0}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p1, p0, p2}, Lg11/c;-><init>(Lra/f;Lr1/b;)V

    .line 18
    .line 19
    .line 20
    new-instance p2, Lra/e;

    .line 21
    .line 22
    invoke-direct {p2, p1}, Lra/e;-><init>(Lg11/c;)V

    .line 23
    .line 24
    .line 25
    iput-object p2, p0, Lb/t;->e:Lra/e;

    .line 26
    .line 27
    new-instance p1, Lb/h0;

    .line 28
    .line 29
    new-instance p2, La0/d;

    .line 30
    .line 31
    const/4 v0, 0x7

    .line 32
    invoke-direct {p2, p0, v0}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    invoke-direct {p1, p2}, Lb/h0;-><init>(Ljava/lang/Runnable;)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lb/t;->f:Lb/h0;

    .line 39
    .line 40
    return-void
.end method

.method public static a(Lb/t;)V
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/app/Dialog;->onBackPressed()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    .line 1
    const-string v0, "view"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lb/t;->b()V

    .line 7
    .line 8
    .line 9
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final b()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "getDecorView(...)"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, p0}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const v2, 0x7f0a0303

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v2, p0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-static {v0, p0}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public final getLifecycle()Landroidx/lifecycle/r;
    .locals 2

    .line 1
    iget-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/z;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method

.method public final getOnBackPressedDispatcher()Lb/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb/t;->f:Lb/h0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSavedStateRegistry()Lra/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lb/t;->e:Lra/e;

    .line 2
    .line 3
    iget-object p0, p0, Lra/e;->b:Lra/d;

    .line 4
    .line 5
    return-object p0
.end method

.method public final onBackPressed()V
    .locals 0

    .line 1
    iget-object p0, p0, Lb/t;->f:Lb/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lb/h0;->c()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/app/Dialog;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 5
    .line 6
    const/16 v1, 0x21

    .line 7
    .line 8
    if-lt v0, v1, :cond_0

    .line 9
    .line 10
    invoke-static {p0}, Lb/s;->q(Lb/t;)Landroid/window/OnBackInvokedDispatcher;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "getOnBackInvokedDispatcher(...)"

    .line 15
    .line 16
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Lb/t;->f:Lb/h0;

    .line 20
    .line 21
    iput-object v0, v1, Lb/h0;->e:Landroid/window/OnBackInvokedDispatcher;

    .line 22
    .line 23
    iget-boolean v0, v1, Lb/h0;->g:Z

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Lb/h0;->d(Z)V

    .line 26
    .line 27
    .line 28
    :cond_0
    iget-object v0, p0, Lb/t;->e:Lra/e;

    .line 29
    .line 30
    invoke-virtual {v0, p1}, Lra/e;->b(Landroid/os/Bundle;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 34
    .line 35
    if-nez p1, :cond_1

    .line 36
    .line 37
    new-instance p1, Landroidx/lifecycle/z;

    .line 38
    .line 39
    const/4 v0, 0x1

    .line 40
    invoke-direct {p1, p0, v0}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 41
    .line 42
    .line 43
    iput-object p1, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 44
    .line 45
    :cond_1
    sget-object p0, Landroidx/lifecycle/p;->ON_CREATE:Landroidx/lifecycle/p;

    .line 46
    .line 47
    invoke-virtual {p1, p0}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public final onSaveInstanceState()Landroid/os/Bundle;
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/app/Dialog;->onSaveInstanceState()Landroid/os/Bundle;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "onSaveInstanceState(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lb/t;->e:Lra/e;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lra/e;->c(Landroid/os/Bundle;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public final onStart()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/app/Dialog;->onStart()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Landroidx/lifecycle/z;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, v1}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 15
    .line 16
    :cond_0
    sget-object p0, Landroidx/lifecycle/p;->ON_RESUME:Landroidx/lifecycle/p;

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public onStop()V
    .locals 2

    .line 1
    iget-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/z;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 12
    .line 13
    :cond_0
    sget-object v1, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 16
    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput-object v0, p0, Lb/t;->d:Landroidx/lifecycle/z;

    .line 20
    .line 21
    invoke-super {p0}, Landroid/app/Dialog;->onStop()V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public setContentView(I)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb/t;->b()V

    .line 2
    invoke-super {p0, p1}, Landroid/app/Dialog;->setContentView(I)V

    return-void
.end method

.method public setContentView(Landroid/view/View;)V
    .locals 1

    const-string v0, "view"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-virtual {p0}, Lb/t;->b()V

    .line 4
    invoke-super {p0, p1}, Landroid/app/Dialog;->setContentView(Landroid/view/View;)V

    return-void
.end method

.method public setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    const-string v0, "view"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-virtual {p0}, Lb/t;->b()V

    .line 6
    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method
