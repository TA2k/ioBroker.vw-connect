.class public Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;
.super Lk6/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "a"
.end annotation


# instance fields
.field private a:I

.field final synthetic b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private a(Landroid/view/View;F)Z
    .locals 3

    .line 1
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 6
    .line 7
    iget v1, v1, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->minScaledFlingVelocity:F

    .line 8
    .line 9
    cmpl-float v0, v0, v1

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-lez v0, :cond_2

    .line 13
    .line 14
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    if-ge p1, p0, :cond_0

    .line 22
    .line 23
    cmpg-float v2, p2, v0

    .line 24
    .line 25
    if-ltz v2, :cond_1

    .line 26
    .line 27
    :cond_0
    if-le p1, p0, :cond_2

    .line 28
    .line 29
    cmpl-float p0, p2, v0

    .line 30
    .line 31
    if-lez p0, :cond_2

    .line 32
    .line 33
    :cond_1
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_2
    return v1
.end method


# virtual methods
.method public clampViewPositionHorizontal(Landroid/view/View;II)I
    .locals 1

    .line 1
    iget p3, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    sub-int/2addr p3, v0

    .line 8
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 9
    .line 10
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    add-int/2addr p1, p0

    .line 15
    invoke-static {p3, p2, p1}, Llp/he;->e(III)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public clampViewPositionVertical(Landroid/view/View;II)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getViewHorizontalDragRange(Landroid/view/View;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public onViewCaptured(Landroid/view/View;I)V
    .locals 1

    .line 1
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 2
    .line 3
    invoke-virtual {p2}, Landroid/view/View;->getWidth()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    sub-int/2addr p2, v0

    .line 12
    int-to-float p2, p2

    .line 13
    const/high16 v0, 0x3f000000    # 0.5f

    .line 14
    .line 15
    mul-float/2addr p2, v0

    .line 16
    float-to-int p2, p2

    .line 17
    iput p2, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    const/4 p2, 0x1

    .line 26
    invoke-interface {p1, p2}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 30
    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->listener:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;

    .line 32
    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;->onSwipeStarted()V

    .line 36
    .line 37
    .line 38
    :cond_1
    return-void
.end method

.method public onViewDragStateChanged(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 2
    .line 3
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->draggingState:I

    .line 4
    .line 5
    return-void
.end method

.method public onViewReleased(Landroid/view/View;FF)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a(Landroid/view/View;F)Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    if-eqz p2, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 12
    .line 13
    int-to-float p2, p2

    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/view/View;->getX()F

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    sub-float/2addr p2, v0

    .line 21
    float-to-int p2, p2

    .line 22
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 27
    .line 28
    if-ge v0, v1, :cond_0

    .line 29
    .line 30
    sub-int/2addr v1, p3

    .line 31
    sub-int/2addr v1, p2

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    add-int/2addr v1, p3

    .line 34
    add-int/2addr v1, p2

    .line 35
    :goto_0
    const/4 p2, 0x1

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->a:I

    .line 38
    .line 39
    const/4 p2, 0x0

    .line 40
    :goto_1
    iget-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 41
    .line 42
    iget-object p3, p3, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->dragHelper:Lk6/f;

    .line 43
    .line 44
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    invoke-virtual {p3, v1, v0}, Lk6/f;->o(II)Z

    .line 49
    .line 50
    .line 51
    move-result p3

    .line 52
    if-eqz p3, :cond_2

    .line 53
    .line 54
    new-instance p3, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$b;

    .line 55
    .line 56
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 57
    .line 58
    invoke-direct {p3, v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$b;-><init>(Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;Landroid/view/View;Z)V

    .line 59
    .line 60
    .line 61
    sget-object p2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 62
    .line 63
    invoke-virtual {p1, p3}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 68
    .line 69
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->listener:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;

    .line 70
    .line 71
    if-eqz p1, :cond_4

    .line 72
    .line 73
    if-eqz p2, :cond_3

    .line 74
    .line 75
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;->onDismissed()V

    .line 76
    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_3
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;->onViewSettled()V

    .line 80
    .line 81
    .line 82
    :cond_4
    :goto_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 83
    .line 84
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 85
    .line 86
    .line 87
    return-void
.end method

.method public tryCaptureView(Landroid/view/View;I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;->b:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTarget:Landroid/view/View;

    .line 4
    .line 5
    if-ne p1, p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method
