.class public final Landroidx/fragment/app/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final synthetic d:Landroidx/fragment/app/r1;

.field public final synthetic e:Landroidx/fragment/app/v0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/v0;Landroidx/fragment/app/r1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/u0;->e:Landroidx/fragment/app/v0;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/fragment/app/u0;->d:Landroidx/fragment/app/r1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 1

    .line 1
    iget-object p1, p0, Landroidx/fragment/app/u0;->d:Landroidx/fragment/app/r1;

    .line 2
    .line 3
    iget-object v0, p1, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 4
    .line 5
    invoke-virtual {p1}, Landroidx/fragment/app/r1;->k()V

    .line 6
    .line 7
    .line 8
    iget-object p1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 9
    .line 10
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Landroid/view/ViewGroup;

    .line 15
    .line 16
    iget-object p0, p0, Landroidx/fragment/app/u0;->e:Landroidx/fragment/app/v0;

    .line 17
    .line 18
    iget-object p0, p0, Landroidx/fragment/app/v0;->d:Landroidx/fragment/app/j1;

    .line 19
    .line 20
    invoke-static {p1, p0}, Landroidx/fragment/app/r;->j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0}, Landroidx/fragment/app/r;->i()V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method
