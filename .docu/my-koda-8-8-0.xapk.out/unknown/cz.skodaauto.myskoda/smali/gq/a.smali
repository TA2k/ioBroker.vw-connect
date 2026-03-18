.class public final synthetic Lgq/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Landroid/view/View;

.field public final synthetic c:Ll5/a;


# direct methods
.method public synthetic constructor <init>(Ll5/a;Landroid/view/View;I)V
    .locals 0

    .line 1
    iput p3, p0, Lgq/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lgq/a;->c:Ll5/a;

    .line 4
    .line 5
    iput-object p2, p0, Lgq/a;->b:Landroid/view/View;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final onTouchExplorationStateChanged(Z)V
    .locals 2

    .line 1
    iget v0, p0, Lgq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lgq/a;->c:Ll5/a;

    .line 7
    .line 8
    check-cast v0, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    iget p1, v0, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;->j:I

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-ne p1, v1, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lgq/a;->b:Landroid/view/View;

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;->s(Landroid/view/View;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void

    .line 23
    :pswitch_0
    iget-object v0, p0, Lgq/a;->c:Ll5/a;

    .line 24
    .line 25
    check-cast v0, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;

    .line 26
    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    iget p1, v0, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;->j:I

    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    if-ne p1, v1, :cond_1

    .line 33
    .line 34
    iget-object p0, p0, Lgq/a;->b:Landroid/view/View;

    .line 35
    .line 36
    invoke-virtual {v0, p0}, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;->r(Landroid/view/View;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    return-void

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
