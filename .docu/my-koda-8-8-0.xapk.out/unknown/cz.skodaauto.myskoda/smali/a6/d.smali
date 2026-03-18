.class public final La6/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ViewGroup$OnHierarchyChangeListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/view/KeyEvent$Callback;


# direct methods
.method public constructor <init>(La6/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, La6/d;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p2, p0, La6/d;->e:Landroid/view/KeyEvent$Callback;

    return-void
.end method

.method public constructor <init>(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La6/d;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La6/d;->e:Landroid/view/KeyEvent$Callback;

    return-void
.end method

.method private final a(Landroid/view/View;Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final onChildViewAdded(Landroid/view/View;Landroid/view/View;)V
    .locals 3

    .line 1
    iget v0, p0, La6/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La6/d;->e:Landroid/view/KeyEvent$Callback;

    .line 7
    .line 8
    check-cast p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;

    .line 9
    .line 10
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t:Landroid/view/ViewGroup$OnHierarchyChangeListener;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-interface {p0, p1, p2}, Landroid/view/ViewGroup$OnHierarchyChangeListener;->onChildViewAdded(Landroid/view/View;Landroid/view/View;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void

    .line 18
    :pswitch_0
    invoke-static {p2}, La6/c;->s(Landroid/view/View;)Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    if-eqz p1, :cond_2

    .line 23
    .line 24
    invoke-static {p2}, La6/c;->n(Landroid/view/View;)Landroid/window/SplashScreenView;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string p2, "child"

    .line 29
    .line 30
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance p2, Landroid/view/WindowInsets$Builder;

    .line 34
    .line 35
    invoke-direct {p2}, Landroid/view/WindowInsets$Builder;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p2}, Landroid/view/WindowInsets$Builder;->build()Landroid/view/WindowInsets;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    const-string v0, "build(...)"

    .line 43
    .line 44
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Landroid/graphics/Rect;

    .line 48
    .line 49
    const/high16 v1, -0x80000000

    .line 50
    .line 51
    const v2, 0x7fffffff

    .line 52
    .line 53
    .line 54
    invoke-direct {v0, v1, v1, v2, v2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 55
    .line 56
    .line 57
    invoke-static {p1}, La6/c;->m(Landroid/window/SplashScreenView;)Landroid/view/View;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p1, p2, v0}, Landroid/view/View;->computeSystemWindowInsets(Landroid/view/WindowInsets;Landroid/graphics/Rect;)Landroid/view/WindowInsets;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p2, p1, :cond_1

    .line 66
    .line 67
    invoke-virtual {v0}, Landroid/graphics/Rect;->isEmpty()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    :cond_1
    iget-object p0, p0, La6/d;->e:Landroid/view/KeyEvent$Callback;

    .line 72
    .line 73
    check-cast p0, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 74
    .line 75
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {p0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    const-string p1, "null cannot be cast to non-null type android.view.ViewGroup"

    .line 84
    .line 85
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    check-cast p0, Landroid/view/ViewGroup;

    .line 89
    .line 90
    const/4 p1, 0x0

    .line 91
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->setOnHierarchyChangeListener(Landroid/view/ViewGroup$OnHierarchyChangeListener;)V

    .line 92
    .line 93
    .line 94
    :cond_2
    return-void

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onChildViewRemoved(Landroid/view/View;Landroid/view/View;)V
    .locals 1

    .line 1
    iget v0, p0, La6/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La6/d;->e:Landroid/view/KeyEvent$Callback;

    .line 7
    .line 8
    check-cast p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-virtual {p0, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p(I)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t:Landroid/view/ViewGroup$OnHierarchyChangeListener;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-interface {p0, p1, p2}, Landroid/view/ViewGroup$OnHierarchyChangeListener;->onChildViewRemoved(Landroid/view/View;Landroid/view/View;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    :pswitch_0
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
