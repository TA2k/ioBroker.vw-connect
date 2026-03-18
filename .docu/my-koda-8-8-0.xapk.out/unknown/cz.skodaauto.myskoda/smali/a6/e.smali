.class public final La6/e;
.super Lb81/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:La6/b;

.field public final h:La6/d;


# direct methods
.method public constructor <init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lb81/b;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, La6/d;

    .line 5
    .line 6
    invoke-direct {v0, p0, p1}, La6/d;-><init>(La6/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, La6/e;->h:La6/d;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final p()V
    .locals 3

    .line 1
    iget-object v0, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const-string v2, "getTheme(...)"

    .line 10
    .line 11
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Landroid/util/TypedValue;

    .line 15
    .line 16
    invoke-direct {v2}, Landroid/util/TypedValue;-><init>()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, v1, v2}, Lb81/b;->y(Landroid/content/res/Resources$Theme;Landroid/util/TypedValue;)V

    .line 20
    .line 21
    .line 22
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 23
    .line 24
    const/16 v2, 0x21

    .line 25
    .line 26
    if-ge v1, v2, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v1, "null cannot be cast to non-null type android.view.ViewGroup"

    .line 37
    .line 38
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    check-cast v0, Landroid/view/ViewGroup;

    .line 42
    .line 43
    iget-object p0, p0, La6/e;->h:La6/d;

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Landroid/view/ViewGroup;->setOnHierarchyChangeListener(Landroid/view/ViewGroup$OnHierarchyChangeListener;)V

    .line 46
    .line 47
    .line 48
    :cond_0
    return-void
.end method

.method public final w(Lgr/k;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iget-object p1, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 6
    .line 7
    const v0, 0x1020002

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lh/i;->findViewById(I)Landroid/view/View;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, p0, La6/e;->g:La6/b;

    .line 19
    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->isAlive()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    iget-object v1, p0, La6/e;->g:La6/b;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    new-instance v1, La6/b;

    .line 34
    .line 35
    const/4 v2, 0x1

    .line 36
    invoke-direct {v1, p0, p1, v2}, La6/b;-><init>(Lb81/b;Landroid/view/View;I)V

    .line 37
    .line 38
    .line 39
    iput-object v1, p0, La6/e;->g:La6/b;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->addOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method
