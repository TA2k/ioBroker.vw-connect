.class public final Landroidx/fragment/app/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:Landroidx/fragment/app/j0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/d0;->d:Landroidx/fragment/app/j0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 0

    .line 1
    sget-object p1, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 2
    .line 3
    if-ne p2, p1, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/fragment/app/d0;->d:Landroidx/fragment/app/j0;

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Landroid/view/View;->cancelPendingInputEvents()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method
