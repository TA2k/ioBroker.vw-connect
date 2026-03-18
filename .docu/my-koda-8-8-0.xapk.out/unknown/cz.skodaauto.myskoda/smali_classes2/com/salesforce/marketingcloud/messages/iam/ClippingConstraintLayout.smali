.class public Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;
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


# instance fields
.field private borderWidth:F

.field private cornerRadius:F

.field private path:Landroid/graphics/Path;

.field private rect:Landroid/graphics/RectF;

.field private tmpRect:Landroid/graphics/Rect;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;-><init>(Landroid/content/Context;)V

    .line 2
    new-instance p1, Landroid/graphics/Path;

    invoke-direct {p1}, Landroid/graphics/Path;-><init>()V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 3
    new-instance p1, Landroid/graphics/RectF;

    const/4 v0, 0x0

    invoke-direct {p1, v0, v0, v0, v0}, Landroid/graphics/RectF;-><init>(FFFF)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->rect:Landroid/graphics/RectF;

    .line 4
    new-instance p1, Landroid/graphics/Rect;

    const/4 v0, 0x0

    invoke-direct {p1, v0, v0, v0, v0}, Landroid/graphics/Rect;-><init>(IIII)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->tmpRect:Landroid/graphics/Rect;

    .line 5
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->init()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    .line 6
    invoke-direct {p0, p1, p2}, Landroidx/constraintlayout/widget/ConstraintLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 7
    new-instance p1, Landroid/graphics/Path;

    invoke-direct {p1}, Landroid/graphics/Path;-><init>()V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 8
    new-instance p1, Landroid/graphics/RectF;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p2, p2, p2}, Landroid/graphics/RectF;-><init>(FFFF)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->rect:Landroid/graphics/RectF;

    .line 9
    new-instance p1, Landroid/graphics/Rect;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p2, p2, p2}, Landroid/graphics/Rect;-><init>(IIII)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->tmpRect:Landroid/graphics/Rect;

    .line 10
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->init()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    .line 11
    invoke-direct {p0, p1, p2, p3}, Landroidx/constraintlayout/widget/ConstraintLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 12
    new-instance p1, Landroid/graphics/Path;

    invoke-direct {p1}, Landroid/graphics/Path;-><init>()V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 13
    new-instance p1, Landroid/graphics/RectF;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p2, p2, p2}, Landroid/graphics/RectF;-><init>(FFFF)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->rect:Landroid/graphics/RectF;

    .line 14
    new-instance p1, Landroid/graphics/Rect;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p2, p2, p2}, Landroid/graphics/Rect;-><init>(IIII)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->tmpRect:Landroid/graphics/Rect;

    .line 15
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->init()V

    return-void
.end method

.method private init()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/high16 v2, 0x41f00000    # 30.0f

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    invoke-static {v3, v2, v1}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    float-to-double v1, v1

    .line 17
    invoke-static {v1, v2}, Ljava/lang/Math;->floor(D)D

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    double-to-float v1, v1

    .line 22
    iput v1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->cornerRadius:F

    .line 23
    .line 24
    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    const/high16 v1, 0x40400000    # 3.0f

    .line 29
    .line 30
    invoke-static {v3, v1, v0}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iput v0, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->borderWidth:F

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public dispatchDraw(Landroid/graphics/Canvas;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 6
    .line 7
    invoke-virtual {p1, v1}, Landroid/graphics/Canvas;->clipPath(Landroid/graphics/Path;)Z

    .line 8
    .line 9
    .line 10
    invoke-super {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->dispatchDraw(Landroid/graphics/Canvas;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public onSizeChanged(IIII)V
    .locals 2

    .line 1
    invoke-super {p0, p1, p2, p3, p4}, Landroid/view/View;->onSizeChanged(IIII)V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/graphics/Path;->reset()V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->tmpRect:Landroid/graphics/Rect;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Landroid/view/View;->getDrawingRect(Landroid/graphics/Rect;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->rect:Landroid/graphics/RectF;

    .line 15
    .line 16
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->tmpRect:Landroid/graphics/Rect;

    .line 17
    .line 18
    iget p3, p2, Landroid/graphics/Rect;->left:I

    .line 19
    .line 20
    int-to-float p3, p3

    .line 21
    iget p4, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->borderWidth:F

    .line 22
    .line 23
    add-float/2addr p3, p4

    .line 24
    iget v0, p2, Landroid/graphics/Rect;->top:I

    .line 25
    .line 26
    int-to-float v0, v0

    .line 27
    add-float/2addr v0, p4

    .line 28
    iget v1, p2, Landroid/graphics/Rect;->right:I

    .line 29
    .line 30
    int-to-float v1, v1

    .line 31
    sub-float/2addr v1, p4

    .line 32
    iget p2, p2, Landroid/graphics/Rect;->bottom:I

    .line 33
    .line 34
    int-to-float p2, p2

    .line 35
    sub-float/2addr p2, p4

    .line 36
    invoke-virtual {p1, p3, v0, v1, p2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 40
    .line 41
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->rect:Landroid/graphics/RectF;

    .line 42
    .line 43
    iget p3, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->cornerRadius:F

    .line 44
    .line 45
    sget-object p4, Landroid/graphics/Path$Direction;->CW:Landroid/graphics/Path$Direction;

    .line 46
    .line 47
    invoke-virtual {p1, p2, p3, p3, p4}, Landroid/graphics/Path;->addRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Path$Direction;)V

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->path:Landroid/graphics/Path;

    .line 51
    .line 52
    invoke-virtual {p0}, Landroid/graphics/Path;->close()V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public setClippingDetails(FF)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->borderWidth:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget v0, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->cornerRadius:F

    .line 8
    .line 9
    cmpl-float v0, v0, p2

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    return-void

    .line 15
    :cond_1
    :goto_0
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->borderWidth:F

    .line 16
    .line 17
    float-to-double p1, p2

    .line 18
    invoke-static {p1, p2}, Ljava/lang/Math;->floor(D)D

    .line 19
    .line 20
    .line 21
    move-result-wide p1

    .line 22
    double-to-float p1, p1

    .line 23
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/iam/ClippingConstraintLayout;->cornerRadius:F

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 26
    .line 27
    .line 28
    return-void
.end method
