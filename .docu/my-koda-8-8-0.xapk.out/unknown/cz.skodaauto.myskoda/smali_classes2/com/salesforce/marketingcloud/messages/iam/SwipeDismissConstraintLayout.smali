.class public Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;
.super Landroidx/constraintlayout/widget/ConstraintLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;,
        Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;,
        Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$b;
    }
.end annotation


# static fields
.field private static final DRAG_SENSITIVITY:F = 1.0f


# instance fields
.field dragHelper:Lk6/f;

.field draggingState:I

.field listener:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;

.field minScaledFlingVelocity:F

.field swipeTarget:Landroid/view/View;

.field private swipeTargetId:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Landroidx/constraintlayout/widget/ConstraintLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 2
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->init(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    .line 3
    invoke-direct {p0, p1, p2, p3}, Landroidx/constraintlayout/widget/ConstraintLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 4
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->init(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-void
.end method

.method private init(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sget-object v1, Lcom/salesforce/marketingcloud/R$styleable;->SwipeDismissConstraintLayout:[I

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v0, p2, v1, v2, v2}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    :try_start_0
    sget v0, Lcom/salesforce/marketingcloud/R$styleable;->SwipeDismissConstraintLayout_swipeTargetId:I

    .line 20
    .line 21
    invoke-virtual {p2, v0, v2}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    iput v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTargetId:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 28
    .line 29
    .line 30
    new-instance p2, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;

    .line 31
    .line 32
    invoke-direct {p2, p0}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Lk6/f;

    .line 36
    .line 37
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-direct {v0, v1, p0, p2}, Lk6/f;-><init>(Landroid/content/Context;Landroid/view/ViewGroup;Lk6/e;)V

    .line 42
    .line 43
    .line 44
    iget p2, v0, Lk6/f;->b:I

    .line 45
    .line 46
    int-to-float p2, p2

    .line 47
    const/high16 v1, 0x3f800000    # 1.0f

    .line 48
    .line 49
    mul-float/2addr v1, p2

    .line 50
    float-to-int p2, v1

    .line 51
    iput p2, v0, Lk6/f;->b:I

    .line 52
    .line 53
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->dragHelper:Lk6/f;

    .line 54
    .line 55
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-virtual {p1}, Landroid/view/ViewConfiguration;->getScaledMinimumFlingVelocity()I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    int-to-float p1, p1

    .line 64
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->minScaledFlingVelocity:F

    .line 65
    .line 66
    return-void

    .line 67
    :catchall_0
    move-exception p0

    .line 68
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 69
    .line 70
    .line 71
    throw p0
.end method

.method private isTarget(Landroid/view/MotionEvent;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTarget:Landroid/view/View;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    const/4 v2, 0x2

    .line 8
    new-array v2, v2, [I

    .line 9
    .line 10
    invoke-virtual {v0, v2}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawX()F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    float-to-int v0, v0

    .line 18
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawY()F

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    float-to-int p1, p1

    .line 23
    aget v3, v2, v1

    .line 24
    .line 25
    if-le v0, v3, :cond_1

    .line 26
    .line 27
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTarget:Landroid/view/View;

    .line 28
    .line 29
    invoke-virtual {v4}, Landroid/view/View;->getMeasuredWidth()I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    add-int/2addr v4, v3

    .line 34
    if-ge v0, v4, :cond_1

    .line 35
    .line 36
    const/4 v0, 0x1

    .line 37
    aget v2, v2, v0

    .line 38
    .line 39
    if-le p1, v2, :cond_1

    .line 40
    .line 41
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTarget:Landroid/view/View;

    .line 42
    .line 43
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredWidth()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    add-int/2addr p0, v2

    .line 48
    if-ge p1, p0, :cond_1

    .line 49
    .line 50
    return v0

    .line 51
    :cond_1
    return v1
.end method


# virtual methods
.method public isMoving()Z
    .locals 2

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->draggingState:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p0, v0, :cond_1

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-ne p0, v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_1
    :goto_0
    return v0
.end method

.method public onFinishInflate()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTargetId:I

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->swipeTarget:Landroid/view/View;

    .line 8
    .line 9
    invoke-super {p0}, Landroid/view/View;->onFinishInflate()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public onInterceptTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->isTarget(Landroid/view/MotionEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->dragHelper:Lk6/f;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lk6/f;->p(Landroid/view/MotionEvent;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

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

.method public onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "ClickableViewAccessibility"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->isTarget(Landroid/view/MotionEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->isMoving()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-super {p0, p1}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->dragHelper:Lk6/f;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lk6/f;->j(Landroid/view/MotionEvent;)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    return p0
.end method

.method public setListener(Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout;->listener:Lcom/salesforce/marketingcloud/messages/iam/SwipeDismissConstraintLayout$SwipeDismissListener;

    .line 2
    .line 3
    return-void
.end method
