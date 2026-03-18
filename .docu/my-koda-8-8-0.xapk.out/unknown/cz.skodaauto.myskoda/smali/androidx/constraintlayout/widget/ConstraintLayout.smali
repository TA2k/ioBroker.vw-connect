.class public Landroidx/constraintlayout/widget/ConstraintLayout;
.super Landroid/view/ViewGroup;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEBUG:Z = false

.field private static final DEBUG_DRAW_CONSTRAINTS:Z = false

.field public static final DESIGN_INFO_ID:I = 0x0

.field private static final MEASURE:Z = false

.field private static final OPTIMIZE_HEIGHT_CHANGE:Z = false

.field private static final TAG:Ljava/lang/String; = "ConstraintLayout"

.field private static final USE_CONSTRAINTS_HELPER:Z = true

.field public static final VERSION:Ljava/lang/String; = "ConstraintLayout-2.1.4"

.field private static sSharedValues:Landroidx/constraintlayout/widget/t;


# instance fields
.field mChildrenByIds:Landroid/util/SparseArray;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/util/SparseArray<",
            "Landroid/view/View;",
            ">;"
        }
    .end annotation
.end field

.field private mConstraintHelpers:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Landroidx/constraintlayout/widget/b;",
            ">;"
        }
    .end annotation
.end field

.field protected mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

.field private mConstraintSet:Landroidx/constraintlayout/widget/o;

.field private mConstraintSetId:I

.field private mConstraintsChangedListener:Landroidx/constraintlayout/widget/p;

.field private mDesignIds:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field protected mDirtyHierarchy:Z

.field private mLastMeasureHeight:I

.field mLastMeasureHeightMode:I

.field mLastMeasureHeightSize:I

.field private mLastMeasureWidth:I

.field mLastMeasureWidthMode:I

.field mLastMeasureWidthSize:I

.field protected mLayoutWidget:Lh5/e;

.field private mMaxHeight:I

.field private mMaxWidth:I

.field mMeasurer:Landroidx/constraintlayout/widget/e;

.field private mMetrics:La5/d;

.field private mMinHeight:I

.field private mMinWidth:I

.field private mOnMeasureHeightMeasureSpec:I

.field private mOnMeasureWidthMeasureSpec:I

.field private mOptimizationLevel:I

.field private mTempMapIdToWidget:Landroid/util/SparseArray;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/util/SparseArray<",
            "Lh5/d;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;)V

    .line 2
    new-instance p1, Landroid/util/SparseArray;

    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 3
    new-instance p1, Ljava/util/ArrayList;

    const/4 v0, 0x4

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 4
    new-instance p1, Lh5/e;

    invoke-direct {p1}, Lh5/e;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    const/4 p1, 0x0

    .line 5
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 6
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    const v0, 0x7fffffff

    .line 7
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 8
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    const/16 v0, 0x101

    .line 10
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 12
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    const/4 v1, -0x1

    .line 13
    iput v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSetId:I

    .line 14
    new-instance v2, Ljava/util/HashMap;

    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    iput-object v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 15
    iput v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidth:I

    .line 16
    iput v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeight:I

    .line 17
    iput v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthSize:I

    .line 18
    iput v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightSize:I

    .line 19
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthMode:I

    .line 20
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightMode:I

    .line 21
    new-instance v1, Landroid/util/SparseArray;

    invoke-direct {v1}, Landroid/util/SparseArray;-><init>()V

    iput-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 22
    new-instance v1, Landroidx/constraintlayout/widget/e;

    invoke-direct {v1, p0, p0}, Landroidx/constraintlayout/widget/e;-><init>(Landroidx/constraintlayout/widget/ConstraintLayout;Landroidx/constraintlayout/widget/ConstraintLayout;)V

    iput-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 23
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureWidthMeasureSpec:I

    .line 24
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureHeightMeasureSpec:I

    .line 25
    invoke-virtual {p0, v0, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->e(Landroid/util/AttributeSet;I)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 2

    .line 26
    invoke-direct {p0, p1, p2}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 27
    new-instance p1, Landroid/util/SparseArray;

    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 28
    new-instance p1, Ljava/util/ArrayList;

    const/4 v0, 0x4

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 29
    new-instance p1, Lh5/e;

    invoke-direct {p1}, Lh5/e;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    const/4 p1, 0x0

    .line 30
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 31
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    const v0, 0x7fffffff

    .line 32
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 33
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    const/4 v0, 0x1

    .line 34
    iput-boolean v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    const/16 v0, 0x101

    .line 35
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    const/4 v0, 0x0

    .line 36
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 37
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    const/4 v0, -0x1

    .line 38
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSetId:I

    .line 39
    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    iput-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 40
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidth:I

    .line 41
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeight:I

    .line 42
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthSize:I

    .line 43
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightSize:I

    .line 44
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthMode:I

    .line 45
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightMode:I

    .line 46
    new-instance v0, Landroid/util/SparseArray;

    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 47
    new-instance v0, Landroidx/constraintlayout/widget/e;

    invoke-direct {v0, p0, p0}, Landroidx/constraintlayout/widget/e;-><init>(Landroidx/constraintlayout/widget/ConstraintLayout;Landroidx/constraintlayout/widget/ConstraintLayout;)V

    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 48
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureWidthMeasureSpec:I

    .line 49
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureHeightMeasureSpec:I

    .line 50
    invoke-virtual {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->e(Landroid/util/AttributeSet;I)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 2

    .line 51
    invoke-direct {p0, p1, p2, p3}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 52
    new-instance p1, Landroid/util/SparseArray;

    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 53
    new-instance p1, Ljava/util/ArrayList;

    const/4 v0, 0x4

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 54
    new-instance p1, Lh5/e;

    invoke-direct {p1}, Lh5/e;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    const/4 p1, 0x0

    .line 55
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 56
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    const v0, 0x7fffffff

    .line 57
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 58
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    const/4 v0, 0x1

    .line 59
    iput-boolean v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    const/16 v0, 0x101

    .line 60
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    const/4 v0, 0x0

    .line 61
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 62
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    const/4 v0, -0x1

    .line 63
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSetId:I

    .line 64
    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    iput-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 65
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidth:I

    .line 66
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeight:I

    .line 67
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthSize:I

    .line 68
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightSize:I

    .line 69
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthMode:I

    .line 70
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightMode:I

    .line 71
    new-instance v0, Landroid/util/SparseArray;

    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 72
    new-instance v0, Landroidx/constraintlayout/widget/e;

    invoke-direct {v0, p0, p0}, Landroidx/constraintlayout/widget/e;-><init>(Landroidx/constraintlayout/widget/ConstraintLayout;Landroidx/constraintlayout/widget/ConstraintLayout;)V

    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 73
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureWidthMeasureSpec:I

    .line 74
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureHeightMeasureSpec:I

    .line 75
    invoke-virtual {p0, p2, p3}, Landroidx/constraintlayout/widget/ConstraintLayout;->e(Landroid/util/AttributeSet;I)V

    return-void
.end method

.method public static synthetic access$000(Landroidx/constraintlayout/widget/ConstraintLayout;)I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    .line 2
    .line 3
    return p0
.end method

.method public static synthetic access$100(Landroidx/constraintlayout/widget/ConstraintLayout;)Ljava/util/ArrayList;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 2
    .line 3
    return-object p0
.end method

.method private getPaddingWidth()I
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    add-int/2addr v2, v0

    .line 19
    invoke-virtual {p0}, Landroid/view/View;->getPaddingStart()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getPaddingEnd()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    add-int/2addr p0, v0

    .line 36
    if-lez p0, :cond_0

    .line 37
    .line 38
    return p0

    .line 39
    :cond_0
    return v2
.end method

.method public static getSharedValues()Landroidx/constraintlayout/widget/t;
    .locals 2

    .line 1
    sget-object v0, Landroidx/constraintlayout/widget/ConstraintLayout;->sSharedValues:Landroidx/constraintlayout/widget/t;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/constraintlayout/widget/t;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance v1, Landroid/util/SparseIntArray;

    .line 11
    .line 12
    invoke-direct {v1}, Landroid/util/SparseIntArray;-><init>()V

    .line 13
    .line 14
    .line 15
    new-instance v1, Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 18
    .line 19
    .line 20
    sput-object v0, Landroidx/constraintlayout/widget/ConstraintLayout;->sSharedValues:Landroidx/constraintlayout/widget/t;

    .line 21
    .line 22
    :cond_0
    sget-object v0, Landroidx/constraintlayout/widget/ConstraintLayout;->sSharedValues:Landroidx/constraintlayout/widget/t;

    .line 23
    .line 24
    return-object v0
.end method


# virtual methods
.method public applyConstraintsFromLayoutParams(ZLandroid/view/View;Lh5/d;Landroidx/constraintlayout/widget/d;Landroid/util/SparseArray;)V
    .locals 19
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z",
            "Landroid/view/View;",
            "Lh5/d;",
            "Landroidx/constraintlayout/widget/d;",
            "Landroid/util/SparseArray<",
            "Lh5/d;",
            ">;)V"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v6, p4

    .line 6
    .line 7
    move-object/from16 v7, p5

    .line 8
    .line 9
    invoke-virtual {v6}, Landroidx/constraintlayout/widget/d;->a()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/view/View;->getVisibility()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    iput v2, v1, Lh5/d;->h0:I

    .line 17
    .line 18
    iput-object v0, v1, Lh5/d;->g0:Ljava/lang/Object;

    .line 19
    .line 20
    instance-of v2, v0, Landroidx/constraintlayout/widget/b;

    .line 21
    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    check-cast v0, Landroidx/constraintlayout/widget/b;

    .line 25
    .line 26
    move-object/from16 v8, p0

    .line 27
    .line 28
    iget-object v2, v8, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 29
    .line 30
    iget-boolean v2, v2, Lh5/e;->w0:Z

    .line 31
    .line 32
    invoke-virtual {v0, v1, v2}, Landroidx/constraintlayout/widget/b;->i(Lh5/d;Z)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object/from16 v8, p0

    .line 37
    .line 38
    :goto_0
    iget-boolean v0, v6, Landroidx/constraintlayout/widget/d;->d0:Z

    .line 39
    .line 40
    const/4 v9, -0x1

    .line 41
    if-eqz v0, :cond_4

    .line 42
    .line 43
    move-object v0, v1

    .line 44
    check-cast v0, Lh5/h;

    .line 45
    .line 46
    iget v1, v6, Landroidx/constraintlayout/widget/d;->m0:I

    .line 47
    .line 48
    iget v2, v6, Landroidx/constraintlayout/widget/d;->n0:I

    .line 49
    .line 50
    iget v3, v6, Landroidx/constraintlayout/widget/d;->o0:F

    .line 51
    .line 52
    const/high16 v4, -0x40800000    # -1.0f

    .line 53
    .line 54
    cmpl-float v5, v3, v4

    .line 55
    .line 56
    if-eqz v5, :cond_1

    .line 57
    .line 58
    if-lez v5, :cond_3

    .line 59
    .line 60
    iput v3, v0, Lh5/h;->r0:F

    .line 61
    .line 62
    iput v9, v0, Lh5/h;->s0:I

    .line 63
    .line 64
    iput v9, v0, Lh5/h;->t0:I

    .line 65
    .line 66
    return-void

    .line 67
    :cond_1
    if-eq v1, v9, :cond_2

    .line 68
    .line 69
    if-le v1, v9, :cond_3

    .line 70
    .line 71
    iput v4, v0, Lh5/h;->r0:F

    .line 72
    .line 73
    iput v1, v0, Lh5/h;->s0:I

    .line 74
    .line 75
    iput v9, v0, Lh5/h;->t0:I

    .line 76
    .line 77
    return-void

    .line 78
    :cond_2
    if-eq v2, v9, :cond_3

    .line 79
    .line 80
    if-le v2, v9, :cond_3

    .line 81
    .line 82
    iput v4, v0, Lh5/h;->r0:F

    .line 83
    .line 84
    iput v9, v0, Lh5/h;->s0:I

    .line 85
    .line 86
    iput v2, v0, Lh5/h;->t0:I

    .line 87
    .line 88
    :cond_3
    return-void

    .line 89
    :cond_4
    iget v0, v6, Landroidx/constraintlayout/widget/d;->f0:I

    .line 90
    .line 91
    iget v2, v6, Landroidx/constraintlayout/widget/d;->g0:I

    .line 92
    .line 93
    iget v10, v6, Landroidx/constraintlayout/widget/d;->h0:I

    .line 94
    .line 95
    iget v11, v6, Landroidx/constraintlayout/widget/d;->i0:I

    .line 96
    .line 97
    iget v4, v6, Landroidx/constraintlayout/widget/d;->j0:I

    .line 98
    .line 99
    iget v12, v6, Landroidx/constraintlayout/widget/d;->k0:I

    .line 100
    .line 101
    iget v13, v6, Landroidx/constraintlayout/widget/d;->l0:F

    .line 102
    .line 103
    iget v3, v6, Landroidx/constraintlayout/widget/d;->p:I

    .line 104
    .line 105
    const/4 v14, 0x4

    .line 106
    const/4 v15, 0x2

    .line 107
    const/16 v16, 0x5

    .line 108
    .line 109
    const/16 v17, 0x3

    .line 110
    .line 111
    if-eq v3, v9, :cond_6

    .line 112
    .line 113
    invoke-virtual {v7, v3}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    move-object v5, v0

    .line 118
    check-cast v5, Lh5/d;

    .line 119
    .line 120
    if-eqz v5, :cond_5

    .line 121
    .line 122
    iget v7, v6, Landroidx/constraintlayout/widget/d;->r:F

    .line 123
    .line 124
    iget v3, v6, Landroidx/constraintlayout/widget/d;->q:I

    .line 125
    .line 126
    const/4 v1, 0x7

    .line 127
    const/4 v4, 0x0

    .line 128
    move v2, v1

    .line 129
    move-object/from16 v0, p3

    .line 130
    .line 131
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 132
    .line 133
    .line 134
    move-object v1, v0

    .line 135
    iput v7, v1, Lh5/d;->E:F

    .line 136
    .line 137
    :cond_5
    move-object v0, v1

    .line 138
    move-object v2, v6

    .line 139
    move v11, v14

    .line 140
    move v10, v15

    .line 141
    move/from16 v1, v16

    .line 142
    .line 143
    move/from16 v12, v17

    .line 144
    .line 145
    goto/16 :goto_b

    .line 146
    .line 147
    :cond_6
    if-eq v0, v9, :cond_9

    .line 148
    .line 149
    invoke-virtual {v7, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    move-object v5, v0

    .line 154
    check-cast v5, Lh5/d;

    .line 155
    .line 156
    if-eqz v5, :cond_7

    .line 157
    .line 158
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 159
    .line 160
    move v2, v15

    .line 161
    move-object v0, v1

    .line 162
    move v1, v15

    .line 163
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 164
    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_7
    move v1, v15

    .line 168
    :cond_8
    :goto_1
    move v2, v1

    .line 169
    move v1, v14

    .line 170
    goto :goto_2

    .line 171
    :cond_9
    move v1, v15

    .line 172
    if-eq v2, v9, :cond_8

    .line 173
    .line 174
    invoke-virtual {v7, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    move-object v5, v0

    .line 179
    check-cast v5, Lh5/d;

    .line 180
    .line 181
    if-eqz v5, :cond_8

    .line 182
    .line 183
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 184
    .line 185
    move-object/from16 v0, p3

    .line 186
    .line 187
    move v2, v14

    .line 188
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 189
    .line 190
    .line 191
    move/from16 v18, v2

    .line 192
    .line 193
    move v2, v1

    .line 194
    move/from16 v1, v18

    .line 195
    .line 196
    :goto_2
    if-eq v10, v9, :cond_c

    .line 197
    .line 198
    invoke-virtual {v7, v10}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    move-object v5, v0

    .line 203
    check-cast v5, Lh5/d;

    .line 204
    .line 205
    if-eqz v5, :cond_a

    .line 206
    .line 207
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 208
    .line 209
    move-object/from16 v0, p3

    .line 210
    .line 211
    move v4, v12

    .line 212
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 213
    .line 214
    .line 215
    :cond_a
    move v10, v2

    .line 216
    :cond_b
    :goto_3
    move v11, v1

    .line 217
    goto :goto_4

    .line 218
    :cond_c
    move v10, v2

    .line 219
    move v4, v12

    .line 220
    if-eq v11, v9, :cond_b

    .line 221
    .line 222
    invoke-virtual {v7, v11}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    move-object v5, v0

    .line 227
    check-cast v5, Lh5/d;

    .line 228
    .line 229
    if-eqz v5, :cond_b

    .line 230
    .line 231
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 232
    .line 233
    move v2, v1

    .line 234
    move-object/from16 v0, p3

    .line 235
    .line 236
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 237
    .line 238
    .line 239
    goto :goto_3

    .line 240
    :goto_4
    iget v0, v6, Landroidx/constraintlayout/widget/d;->i:I

    .line 241
    .line 242
    if-eq v0, v9, :cond_f

    .line 243
    .line 244
    invoke-virtual {v7, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    move-object v5, v0

    .line 249
    check-cast v5, Lh5/d;

    .line 250
    .line 251
    if-eqz v5, :cond_d

    .line 252
    .line 253
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 254
    .line 255
    iget v4, v6, Landroidx/constraintlayout/widget/d;->x:I

    .line 256
    .line 257
    move/from16 v2, v17

    .line 258
    .line 259
    move-object/from16 v0, p3

    .line 260
    .line 261
    move/from16 v1, v17

    .line 262
    .line 263
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 264
    .line 265
    .line 266
    goto :goto_5

    .line 267
    :cond_d
    move/from16 v1, v17

    .line 268
    .line 269
    :cond_e
    :goto_5
    move v2, v1

    .line 270
    move/from16 v1, v16

    .line 271
    .line 272
    goto :goto_6

    .line 273
    :cond_f
    move/from16 v1, v17

    .line 274
    .line 275
    iget v0, v6, Landroidx/constraintlayout/widget/d;->j:I

    .line 276
    .line 277
    if-eq v0, v9, :cond_e

    .line 278
    .line 279
    invoke-virtual {v7, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    move-object v5, v0

    .line 284
    check-cast v5, Lh5/d;

    .line 285
    .line 286
    if-eqz v5, :cond_e

    .line 287
    .line 288
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 289
    .line 290
    iget v4, v6, Landroidx/constraintlayout/widget/d;->x:I

    .line 291
    .line 292
    move-object/from16 v0, p3

    .line 293
    .line 294
    move/from16 v2, v16

    .line 295
    .line 296
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 297
    .line 298
    .line 299
    move/from16 v18, v2

    .line 300
    .line 301
    move v2, v1

    .line 302
    move/from16 v1, v18

    .line 303
    .line 304
    :goto_6
    iget v0, v6, Landroidx/constraintlayout/widget/d;->k:I

    .line 305
    .line 306
    if-eq v0, v9, :cond_12

    .line 307
    .line 308
    invoke-virtual {v7, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    move-object v5, v0

    .line 313
    check-cast v5, Lh5/d;

    .line 314
    .line 315
    if-eqz v5, :cond_10

    .line 316
    .line 317
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 318
    .line 319
    iget v4, v6, Landroidx/constraintlayout/widget/d;->z:I

    .line 320
    .line 321
    move-object/from16 v0, p3

    .line 322
    .line 323
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 324
    .line 325
    .line 326
    :cond_10
    move v12, v2

    .line 327
    :cond_11
    :goto_7
    move v14, v1

    .line 328
    goto :goto_8

    .line 329
    :cond_12
    move v12, v2

    .line 330
    iget v0, v6, Landroidx/constraintlayout/widget/d;->l:I

    .line 331
    .line 332
    if-eq v0, v9, :cond_11

    .line 333
    .line 334
    invoke-virtual {v7, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    move-object v5, v0

    .line 339
    check-cast v5, Lh5/d;

    .line 340
    .line 341
    if-eqz v5, :cond_11

    .line 342
    .line 343
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 344
    .line 345
    iget v4, v6, Landroidx/constraintlayout/widget/d;->z:I

    .line 346
    .line 347
    move v2, v1

    .line 348
    move-object/from16 v0, p3

    .line 349
    .line 350
    invoke-virtual/range {v0 .. v5}, Lh5/d;->w(IIIILh5/d;)V

    .line 351
    .line 352
    .line 353
    goto :goto_7

    .line 354
    :goto_8
    iget v4, v6, Landroidx/constraintlayout/widget/d;->m:I

    .line 355
    .line 356
    if-eq v4, v9, :cond_14

    .line 357
    .line 358
    const/4 v5, 0x6

    .line 359
    move-object/from16 v1, p3

    .line 360
    .line 361
    move-object v2, v6

    .line 362
    move-object v3, v7

    .line 363
    move-object v0, v8

    .line 364
    invoke-virtual/range {v0 .. v5}, Landroidx/constraintlayout/widget/ConstraintLayout;->f(Lh5/d;Landroidx/constraintlayout/widget/d;Landroid/util/SparseArray;II)V

    .line 365
    .line 366
    .line 367
    :cond_13
    :goto_9
    move-object/from16 v0, p3

    .line 368
    .line 369
    move v1, v14

    .line 370
    goto :goto_a

    .line 371
    :cond_14
    move-object v2, v6

    .line 372
    iget v4, v2, Landroidx/constraintlayout/widget/d;->n:I

    .line 373
    .line 374
    if-eq v4, v9, :cond_15

    .line 375
    .line 376
    move-object/from16 v0, p0

    .line 377
    .line 378
    move-object/from16 v1, p3

    .line 379
    .line 380
    move-object/from16 v3, p5

    .line 381
    .line 382
    move v5, v12

    .line 383
    invoke-virtual/range {v0 .. v5}, Landroidx/constraintlayout/widget/ConstraintLayout;->f(Lh5/d;Landroidx/constraintlayout/widget/d;Landroid/util/SparseArray;II)V

    .line 384
    .line 385
    .line 386
    goto :goto_9

    .line 387
    :cond_15
    iget v4, v2, Landroidx/constraintlayout/widget/d;->o:I

    .line 388
    .line 389
    if-eq v4, v9, :cond_13

    .line 390
    .line 391
    move-object/from16 v0, p0

    .line 392
    .line 393
    move-object/from16 v1, p3

    .line 394
    .line 395
    move-object/from16 v3, p5

    .line 396
    .line 397
    move v5, v14

    .line 398
    invoke-virtual/range {v0 .. v5}, Landroidx/constraintlayout/widget/ConstraintLayout;->f(Lh5/d;Landroidx/constraintlayout/widget/d;Landroid/util/SparseArray;II)V

    .line 399
    .line 400
    .line 401
    move-object v0, v1

    .line 402
    move v1, v5

    .line 403
    :goto_a
    const/4 v3, 0x0

    .line 404
    cmpl-float v4, v13, v3

    .line 405
    .line 406
    if-ltz v4, :cond_16

    .line 407
    .line 408
    iput v13, v0, Lh5/d;->e0:F

    .line 409
    .line 410
    :cond_16
    iget v4, v2, Landroidx/constraintlayout/widget/d;->F:F

    .line 411
    .line 412
    cmpl-float v3, v4, v3

    .line 413
    .line 414
    if-ltz v3, :cond_17

    .line 415
    .line 416
    iput v4, v0, Lh5/d;->f0:F

    .line 417
    .line 418
    :cond_17
    :goto_b
    if-eqz p1, :cond_19

    .line 419
    .line 420
    iget v3, v2, Landroidx/constraintlayout/widget/d;->T:I

    .line 421
    .line 422
    if-ne v3, v9, :cond_18

    .line 423
    .line 424
    iget v4, v2, Landroidx/constraintlayout/widget/d;->U:I

    .line 425
    .line 426
    if-eq v4, v9, :cond_19

    .line 427
    .line 428
    :cond_18
    iget v4, v2, Landroidx/constraintlayout/widget/d;->U:I

    .line 429
    .line 430
    iput v3, v0, Lh5/d;->Z:I

    .line 431
    .line 432
    iput v4, v0, Lh5/d;->a0:I

    .line 433
    .line 434
    :cond_19
    iget-boolean v3, v2, Landroidx/constraintlayout/widget/d;->a0:Z

    .line 435
    .line 436
    const/4 v4, 0x2

    .line 437
    const/4 v5, -0x2

    .line 438
    const/4 v6, 0x1

    .line 439
    const/4 v7, 0x0

    .line 440
    const/4 v8, 0x4

    .line 441
    const/4 v13, 0x3

    .line 442
    if-nez v3, :cond_1c

    .line 443
    .line 444
    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 445
    .line 446
    if-ne v3, v9, :cond_1b

    .line 447
    .line 448
    iget-boolean v3, v2, Landroidx/constraintlayout/widget/d;->W:Z

    .line 449
    .line 450
    if-eqz v3, :cond_1a

    .line 451
    .line 452
    invoke-virtual {v0, v13}, Lh5/d;->O(I)V

    .line 453
    .line 454
    .line 455
    goto :goto_c

    .line 456
    :cond_1a
    invoke-virtual {v0, v8}, Lh5/d;->O(I)V

    .line 457
    .line 458
    .line 459
    :goto_c
    invoke-virtual {v0, v10}, Lh5/d;->j(I)Lh5/c;

    .line 460
    .line 461
    .line 462
    move-result-object v3

    .line 463
    iget v10, v2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 464
    .line 465
    iput v10, v3, Lh5/c;->g:I

    .line 466
    .line 467
    invoke-virtual {v0, v11}, Lh5/d;->j(I)Lh5/c;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    iget v10, v2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 472
    .line 473
    iput v10, v3, Lh5/c;->g:I

    .line 474
    .line 475
    goto :goto_d

    .line 476
    :cond_1b
    invoke-virtual {v0, v13}, Lh5/d;->O(I)V

    .line 477
    .line 478
    .line 479
    invoke-virtual {v0, v7}, Lh5/d;->S(I)V

    .line 480
    .line 481
    .line 482
    goto :goto_d

    .line 483
    :cond_1c
    invoke-virtual {v0, v6}, Lh5/d;->O(I)V

    .line 484
    .line 485
    .line 486
    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 487
    .line 488
    invoke-virtual {v0, v3}, Lh5/d;->S(I)V

    .line 489
    .line 490
    .line 491
    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 492
    .line 493
    if-ne v3, v5, :cond_1d

    .line 494
    .line 495
    invoke-virtual {v0, v4}, Lh5/d;->O(I)V

    .line 496
    .line 497
    .line 498
    :cond_1d
    :goto_d
    iget-boolean v3, v2, Landroidx/constraintlayout/widget/d;->b0:Z

    .line 499
    .line 500
    if-nez v3, :cond_20

    .line 501
    .line 502
    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 503
    .line 504
    if-ne v3, v9, :cond_1f

    .line 505
    .line 506
    iget-boolean v3, v2, Landroidx/constraintlayout/widget/d;->X:Z

    .line 507
    .line 508
    if-eqz v3, :cond_1e

    .line 509
    .line 510
    invoke-virtual {v0, v13}, Lh5/d;->Q(I)V

    .line 511
    .line 512
    .line 513
    goto :goto_e

    .line 514
    :cond_1e
    invoke-virtual {v0, v8}, Lh5/d;->Q(I)V

    .line 515
    .line 516
    .line 517
    :goto_e
    invoke-virtual {v0, v12}, Lh5/d;->j(I)Lh5/c;

    .line 518
    .line 519
    .line 520
    move-result-object v3

    .line 521
    iget v4, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 522
    .line 523
    iput v4, v3, Lh5/c;->g:I

    .line 524
    .line 525
    invoke-virtual {v0, v1}, Lh5/d;->j(I)Lh5/c;

    .line 526
    .line 527
    .line 528
    move-result-object v1

    .line 529
    iget v3, v2, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 530
    .line 531
    iput v3, v1, Lh5/c;->g:I

    .line 532
    .line 533
    goto :goto_f

    .line 534
    :cond_1f
    invoke-virtual {v0, v13}, Lh5/d;->Q(I)V

    .line 535
    .line 536
    .line 537
    invoke-virtual {v0, v7}, Lh5/d;->N(I)V

    .line 538
    .line 539
    .line 540
    goto :goto_f

    .line 541
    :cond_20
    invoke-virtual {v0, v6}, Lh5/d;->Q(I)V

    .line 542
    .line 543
    .line 544
    iget v1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 545
    .line 546
    invoke-virtual {v0, v1}, Lh5/d;->N(I)V

    .line 547
    .line 548
    .line 549
    iget v1, v2, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 550
    .line 551
    if-ne v1, v5, :cond_21

    .line 552
    .line 553
    invoke-virtual {v0, v4}, Lh5/d;->Q(I)V

    .line 554
    .line 555
    .line 556
    :cond_21
    :goto_f
    iget-object v1, v2, Landroidx/constraintlayout/widget/d;->G:Ljava/lang/String;

    .line 557
    .line 558
    invoke-virtual {v0, v1}, Lh5/d;->K(Ljava/lang/String;)V

    .line 559
    .line 560
    .line 561
    iget v1, v2, Landroidx/constraintlayout/widget/d;->H:F

    .line 562
    .line 563
    iget-object v3, v0, Lh5/d;->l0:[F

    .line 564
    .line 565
    aput v1, v3, v7

    .line 566
    .line 567
    iget v1, v2, Landroidx/constraintlayout/widget/d;->I:F

    .line 568
    .line 569
    aput v1, v3, v6

    .line 570
    .line 571
    iget v1, v2, Landroidx/constraintlayout/widget/d;->J:I

    .line 572
    .line 573
    iput v1, v0, Lh5/d;->j0:I

    .line 574
    .line 575
    iget v1, v2, Landroidx/constraintlayout/widget/d;->K:I

    .line 576
    .line 577
    iput v1, v0, Lh5/d;->k0:I

    .line 578
    .line 579
    iget v1, v2, Landroidx/constraintlayout/widget/d;->Z:I

    .line 580
    .line 581
    if-ltz v1, :cond_22

    .line 582
    .line 583
    if-gt v1, v13, :cond_22

    .line 584
    .line 585
    iput v1, v0, Lh5/d;->r:I

    .line 586
    .line 587
    :cond_22
    iget v1, v2, Landroidx/constraintlayout/widget/d;->L:I

    .line 588
    .line 589
    iget v3, v2, Landroidx/constraintlayout/widget/d;->N:I

    .line 590
    .line 591
    iget v4, v2, Landroidx/constraintlayout/widget/d;->P:I

    .line 592
    .line 593
    iget v5, v2, Landroidx/constraintlayout/widget/d;->R:F

    .line 594
    .line 595
    invoke-virtual {v0, v1, v3, v4, v5}, Lh5/d;->P(IIIF)V

    .line 596
    .line 597
    .line 598
    iget v1, v2, Landroidx/constraintlayout/widget/d;->M:I

    .line 599
    .line 600
    iget v3, v2, Landroidx/constraintlayout/widget/d;->O:I

    .line 601
    .line 602
    iget v4, v2, Landroidx/constraintlayout/widget/d;->Q:I

    .line 603
    .line 604
    iget v2, v2, Landroidx/constraintlayout/widget/d;->S:F

    .line 605
    .line 606
    invoke-virtual {v0, v1, v3, v4, v2}, Lh5/d;->R(IIIF)V

    .line 607
    .line 608
    .line 609
    return-void
.end method

.method public checkLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Landroidx/constraintlayout/widget/d;

    .line 2
    .line 3
    return p0
.end method

.method public dispatchDraw(Landroid/graphics/Canvas;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-lez v1, :cond_0

    .line 13
    .line 14
    move v3, v2

    .line 15
    :goto_0
    if-ge v3, v1, :cond_0

    .line 16
    .line 17
    iget-object v4, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    check-cast v4, Landroidx/constraintlayout/widget/b;

    .line 24
    .line 25
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    add-int/lit8 v3, v3, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-super/range {p0 .. p1}, Landroid/view/ViewGroup;->dispatchDraw(Landroid/graphics/Canvas;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/view/View;->isInEditMode()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_3

    .line 39
    .line 40
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    int-to-float v1, v1

    .line 45
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    int-to-float v3, v3

    .line 50
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    move v5, v2

    .line 55
    :goto_1
    if-ge v5, v4, :cond_3

    .line 56
    .line 57
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    invoke-virtual {v6}, Landroid/view/View;->getVisibility()I

    .line 62
    .line 63
    .line 64
    move-result v7

    .line 65
    const/16 v8, 0x8

    .line 66
    .line 67
    if-ne v7, v8, :cond_1

    .line 68
    .line 69
    goto/16 :goto_2

    .line 70
    .line 71
    :cond_1
    invoke-virtual {v6}, Landroid/view/View;->getTag()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    if-eqz v6, :cond_2

    .line 76
    .line 77
    instance-of v7, v6, Ljava/lang/String;

    .line 78
    .line 79
    if-eqz v7, :cond_2

    .line 80
    .line 81
    check-cast v6, Ljava/lang/String;

    .line 82
    .line 83
    const-string v7, ","

    .line 84
    .line 85
    invoke-virtual {v6, v7}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    array-length v7, v6

    .line 90
    const/4 v8, 0x4

    .line 91
    if-ne v7, v8, :cond_2

    .line 92
    .line 93
    aget-object v7, v6, v2

    .line 94
    .line 95
    invoke-static {v7}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    const/4 v8, 0x1

    .line 100
    aget-object v8, v6, v8

    .line 101
    .line 102
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 103
    .line 104
    .line 105
    move-result v8

    .line 106
    const/4 v9, 0x2

    .line 107
    aget-object v9, v6, v9

    .line 108
    .line 109
    invoke-static {v9}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 110
    .line 111
    .line 112
    move-result v9

    .line 113
    const/4 v10, 0x3

    .line 114
    aget-object v6, v6, v10

    .line 115
    .line 116
    invoke-static {v6}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    int-to-float v7, v7

    .line 121
    const/high16 v10, 0x44870000    # 1080.0f

    .line 122
    .line 123
    div-float/2addr v7, v10

    .line 124
    mul-float/2addr v7, v1

    .line 125
    float-to-int v7, v7

    .line 126
    int-to-float v8, v8

    .line 127
    const/high16 v11, 0x44f00000    # 1920.0f

    .line 128
    .line 129
    div-float/2addr v8, v11

    .line 130
    mul-float/2addr v8, v3

    .line 131
    float-to-int v8, v8

    .line 132
    int-to-float v9, v9

    .line 133
    div-float/2addr v9, v10

    .line 134
    mul-float/2addr v9, v1

    .line 135
    float-to-int v9, v9

    .line 136
    int-to-float v6, v6

    .line 137
    div-float/2addr v6, v11

    .line 138
    mul-float/2addr v6, v3

    .line 139
    float-to-int v6, v6

    .line 140
    new-instance v15, Landroid/graphics/Paint;

    .line 141
    .line 142
    invoke-direct {v15}, Landroid/graphics/Paint;-><init>()V

    .line 143
    .line 144
    .line 145
    const/high16 v10, -0x10000

    .line 146
    .line 147
    invoke-virtual {v15, v10}, Landroid/graphics/Paint;->setColor(I)V

    .line 148
    .line 149
    .line 150
    int-to-float v11, v7

    .line 151
    int-to-float v12, v8

    .line 152
    add-int/2addr v7, v9

    .line 153
    int-to-float v13, v7

    .line 154
    move v14, v12

    .line 155
    move-object/from16 v10, p1

    .line 156
    .line 157
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 158
    .line 159
    .line 160
    move v7, v11

    .line 161
    add-int/2addr v8, v6

    .line 162
    int-to-float v14, v8

    .line 163
    move v11, v13

    .line 164
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 165
    .line 166
    .line 167
    move v6, v12

    .line 168
    move v12, v14

    .line 169
    move v13, v7

    .line 170
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 171
    .line 172
    .line 173
    move v7, v11

    .line 174
    move v11, v13

    .line 175
    move v14, v6

    .line 176
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 177
    .line 178
    .line 179
    move/from16 v16, v14

    .line 180
    .line 181
    move v14, v12

    .line 182
    move/from16 v12, v16

    .line 183
    .line 184
    const v6, -0xff0100

    .line 185
    .line 186
    .line 187
    invoke-virtual {v15, v6}, Landroid/graphics/Paint;->setColor(I)V

    .line 188
    .line 189
    .line 190
    move v13, v7

    .line 191
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 192
    .line 193
    .line 194
    move/from16 v16, v14

    .line 195
    .line 196
    move v14, v12

    .line 197
    move/from16 v12, v16

    .line 198
    .line 199
    invoke-virtual/range {v10 .. v15}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 200
    .line 201
    .line 202
    :cond_2
    :goto_2
    add-int/lit8 v5, v5, 0x1

    .line 203
    .line 204
    goto/16 :goto_1

    .line 205
    .line 206
    :cond_3
    return-void
.end method

.method public final e(Landroid/util/AttributeSet;I)V
    .locals 6

    .line 1
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 2
    .line 3
    iput-object p0, v0, Lh5/d;->g0:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 6
    .line 7
    iput-object v1, v0, Lh5/e;->v0:Li5/c;

    .line 8
    .line 9
    iget-object v0, v0, Lh5/e;->t0:Li5/f;

    .line 10
    .line 11
    iput-object v1, v0, Li5/f;->h:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/view/View;->getId()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {v0, v1, p0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 24
    .line 25
    if-eqz p1, :cond_8

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    sget-object v2, Landroidx/constraintlayout/widget/s;->b:[I

    .line 32
    .line 33
    const/4 v3, 0x0

    .line 34
    invoke-virtual {v1, p1, v2, p2, v3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->getIndexCount()I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    move v1, v3

    .line 43
    :goto_0
    if-ge v1, p2, :cond_7

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Landroid/content/res/TypedArray;->getIndex(I)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    const/16 v4, 0x10

    .line 50
    .line 51
    if-ne v2, v4, :cond_0

    .line 52
    .line 53
    iget v4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 54
    .line 55
    invoke-virtual {p1, v2, v4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    iput v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_0
    const/16 v4, 0x11

    .line 63
    .line 64
    if-ne v2, v4, :cond_1

    .line 65
    .line 66
    iget v4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 67
    .line 68
    invoke-virtual {p1, v2, v4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    iput v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_1
    const/16 v4, 0xe

    .line 76
    .line 77
    if-ne v2, v4, :cond_2

    .line 78
    .line 79
    iget v4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 80
    .line 81
    invoke-virtual {p1, v2, v4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    iput v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_2
    const/16 v4, 0xf

    .line 89
    .line 90
    if-ne v2, v4, :cond_3

    .line 91
    .line 92
    iget v4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 93
    .line 94
    invoke-virtual {p1, v2, v4}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    iput v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_3
    const/16 v4, 0x71

    .line 102
    .line 103
    if-ne v2, v4, :cond_4

    .line 104
    .line 105
    iget v4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    .line 106
    .line 107
    invoke-virtual {p1, v2, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    iput v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_4
    const/16 v4, 0x38

    .line 115
    .line 116
    if-ne v2, v4, :cond_5

    .line 117
    .line 118
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    if-eqz v2, :cond_6

    .line 123
    .line 124
    :try_start_0
    invoke-virtual {p0, v2}, Landroidx/constraintlayout/widget/ConstraintLayout;->parseLayoutDescription(I)V
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :catch_0
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_5
    const/16 v4, 0x22

    .line 132
    .line 133
    if-ne v2, v4, :cond_6

    .line 134
    .line 135
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    :try_start_1
    new-instance v4, Landroidx/constraintlayout/widget/o;

    .line 140
    .line 141
    invoke-direct {v4}, Landroidx/constraintlayout/widget/o;-><init>()V

    .line 142
    .line 143
    .line 144
    iput-object v4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 145
    .line 146
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 147
    .line 148
    .line 149
    move-result-object v5

    .line 150
    invoke-virtual {v4, v5, v2}, Landroidx/constraintlayout/widget/o;->e(Landroid/content/Context;I)V
    :try_end_1
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_1 .. :try_end_1} :catch_1

    .line 151
    .line 152
    .line 153
    goto :goto_1

    .line 154
    :catch_1
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 155
    .line 156
    :goto_1
    iput v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSetId:I

    .line 157
    .line 158
    :cond_6
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 159
    .line 160
    goto :goto_0

    .line 161
    :cond_7
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 162
    .line 163
    .line 164
    :cond_8
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 165
    .line 166
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    .line 167
    .line 168
    iput p0, p1, Lh5/e;->E0:I

    .line 169
    .line 170
    const/16 p0, 0x200

    .line 171
    .line 172
    invoke-virtual {p1, p0}, Lh5/e;->c0(I)Z

    .line 173
    .line 174
    .line 175
    move-result p0

    .line 176
    sput-boolean p0, La5/c;->q:Z

    .line 177
    .line 178
    return-void
.end method

.method public final f(Lh5/d;Landroidx/constraintlayout/widget/d;Landroid/util/SparseArray;II)V
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 2
    .line 3
    invoke-virtual {p0, p4}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/view/View;

    .line 8
    .line 9
    invoke-virtual {p3, p4}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p3

    .line 13
    check-cast p3, Lh5/d;

    .line 14
    .line 15
    if-eqz p3, :cond_1

    .line 16
    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 20
    .line 21
    .line 22
    move-result-object p4

    .line 23
    instance-of p4, p4, Landroidx/constraintlayout/widget/d;

    .line 24
    .line 25
    if-eqz p4, :cond_1

    .line 26
    .line 27
    const/4 p4, 0x1

    .line 28
    iput-boolean p4, p2, Landroidx/constraintlayout/widget/d;->c0:Z

    .line 29
    .line 30
    const/4 v0, 0x6

    .line 31
    if-ne p5, v0, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    check-cast p0, Landroidx/constraintlayout/widget/d;

    .line 38
    .line 39
    iput-boolean p4, p0, Landroidx/constraintlayout/widget/d;->c0:Z

    .line 40
    .line 41
    iget-object p0, p0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 42
    .line 43
    iput-boolean p4, p0, Lh5/d;->F:Z

    .line 44
    .line 45
    :cond_0
    invoke-virtual {p1, v0}, Lh5/d;->j(I)Lh5/c;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {p3, p5}, Lh5/d;->j(I)Lh5/c;

    .line 50
    .line 51
    .line 52
    move-result-object p3

    .line 53
    iget p5, p2, Landroidx/constraintlayout/widget/d;->D:I

    .line 54
    .line 55
    iget p2, p2, Landroidx/constraintlayout/widget/d;->C:I

    .line 56
    .line 57
    invoke-virtual {p0, p3, p5, p2, p4}, Lh5/c;->b(Lh5/c;IIZ)Z

    .line 58
    .line 59
    .line 60
    iput-boolean p4, p1, Lh5/d;->F:Z

    .line 61
    .line 62
    const/4 p0, 0x3

    .line 63
    invoke-virtual {p1, p0}, Lh5/d;->j(I)Lh5/c;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 68
    .line 69
    .line 70
    const/4 p0, 0x5

    .line 71
    invoke-virtual {p1, p0}, Lh5/d;->j(I)Lh5/c;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 76
    .line 77
    .line 78
    :cond_1
    return-void
.end method

.method public fillMetrics(La5/d;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 2
    .line 3
    iget-object p0, p0, Lh5/e;->x0:La5/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public forceLayout()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidth:I

    .line 6
    .line 7
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeight:I

    .line 8
    .line 9
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthSize:I

    .line 10
    .line 11
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightSize:I

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthMode:I

    .line 15
    .line 16
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightMode:I

    .line 17
    .line 18
    invoke-super {p0}, Landroid/view/View;->forceLayout()V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public bridge synthetic generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->generateDefaultLayoutParams()Landroidx/constraintlayout/widget/d;

    move-result-object p0

    return-object p0
.end method

.method public generateDefaultLayoutParams()Landroidx/constraintlayout/widget/d;
    .locals 7

    .line 2
    new-instance p0, Landroidx/constraintlayout/widget/d;

    const/4 v0, -0x2

    .line 3
    invoke-direct {p0, v0, v0}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(II)V

    const/4 v0, -0x1

    .line 4
    iput v0, p0, Landroidx/constraintlayout/widget/d;->a:I

    .line 5
    iput v0, p0, Landroidx/constraintlayout/widget/d;->b:I

    const/high16 v1, -0x40800000    # -1.0f

    .line 6
    iput v1, p0, Landroidx/constraintlayout/widget/d;->c:F

    const/4 v2, 0x1

    .line 7
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->d:Z

    .line 8
    iput v0, p0, Landroidx/constraintlayout/widget/d;->e:I

    .line 9
    iput v0, p0, Landroidx/constraintlayout/widget/d;->f:I

    .line 10
    iput v0, p0, Landroidx/constraintlayout/widget/d;->g:I

    .line 11
    iput v0, p0, Landroidx/constraintlayout/widget/d;->h:I

    .line 12
    iput v0, p0, Landroidx/constraintlayout/widget/d;->i:I

    .line 13
    iput v0, p0, Landroidx/constraintlayout/widget/d;->j:I

    .line 14
    iput v0, p0, Landroidx/constraintlayout/widget/d;->k:I

    .line 15
    iput v0, p0, Landroidx/constraintlayout/widget/d;->l:I

    .line 16
    iput v0, p0, Landroidx/constraintlayout/widget/d;->m:I

    .line 17
    iput v0, p0, Landroidx/constraintlayout/widget/d;->n:I

    .line 18
    iput v0, p0, Landroidx/constraintlayout/widget/d;->o:I

    .line 19
    iput v0, p0, Landroidx/constraintlayout/widget/d;->p:I

    const/4 v3, 0x0

    .line 20
    iput v3, p0, Landroidx/constraintlayout/widget/d;->q:I

    const/4 v4, 0x0

    .line 21
    iput v4, p0, Landroidx/constraintlayout/widget/d;->r:F

    .line 22
    iput v0, p0, Landroidx/constraintlayout/widget/d;->s:I

    .line 23
    iput v0, p0, Landroidx/constraintlayout/widget/d;->t:I

    .line 24
    iput v0, p0, Landroidx/constraintlayout/widget/d;->u:I

    .line 25
    iput v0, p0, Landroidx/constraintlayout/widget/d;->v:I

    const/high16 v4, -0x80000000

    .line 26
    iput v4, p0, Landroidx/constraintlayout/widget/d;->w:I

    .line 27
    iput v4, p0, Landroidx/constraintlayout/widget/d;->x:I

    .line 28
    iput v4, p0, Landroidx/constraintlayout/widget/d;->y:I

    .line 29
    iput v4, p0, Landroidx/constraintlayout/widget/d;->z:I

    .line 30
    iput v4, p0, Landroidx/constraintlayout/widget/d;->A:I

    .line 31
    iput v4, p0, Landroidx/constraintlayout/widget/d;->B:I

    .line 32
    iput v4, p0, Landroidx/constraintlayout/widget/d;->C:I

    .line 33
    iput v3, p0, Landroidx/constraintlayout/widget/d;->D:I

    const/high16 v5, 0x3f000000    # 0.5f

    .line 34
    iput v5, p0, Landroidx/constraintlayout/widget/d;->E:F

    .line 35
    iput v5, p0, Landroidx/constraintlayout/widget/d;->F:F

    const/4 v6, 0x0

    .line 36
    iput-object v6, p0, Landroidx/constraintlayout/widget/d;->G:Ljava/lang/String;

    .line 37
    iput v1, p0, Landroidx/constraintlayout/widget/d;->H:F

    .line 38
    iput v1, p0, Landroidx/constraintlayout/widget/d;->I:F

    .line 39
    iput v3, p0, Landroidx/constraintlayout/widget/d;->J:I

    .line 40
    iput v3, p0, Landroidx/constraintlayout/widget/d;->K:I

    .line 41
    iput v3, p0, Landroidx/constraintlayout/widget/d;->L:I

    .line 42
    iput v3, p0, Landroidx/constraintlayout/widget/d;->M:I

    .line 43
    iput v3, p0, Landroidx/constraintlayout/widget/d;->N:I

    .line 44
    iput v3, p0, Landroidx/constraintlayout/widget/d;->O:I

    .line 45
    iput v3, p0, Landroidx/constraintlayout/widget/d;->P:I

    .line 46
    iput v3, p0, Landroidx/constraintlayout/widget/d;->Q:I

    const/high16 v1, 0x3f800000    # 1.0f

    .line 47
    iput v1, p0, Landroidx/constraintlayout/widget/d;->R:F

    .line 48
    iput v1, p0, Landroidx/constraintlayout/widget/d;->S:F

    .line 49
    iput v0, p0, Landroidx/constraintlayout/widget/d;->T:I

    .line 50
    iput v0, p0, Landroidx/constraintlayout/widget/d;->U:I

    .line 51
    iput v0, p0, Landroidx/constraintlayout/widget/d;->V:I

    .line 52
    iput-boolean v3, p0, Landroidx/constraintlayout/widget/d;->W:Z

    .line 53
    iput-boolean v3, p0, Landroidx/constraintlayout/widget/d;->X:Z

    .line 54
    iput-object v6, p0, Landroidx/constraintlayout/widget/d;->Y:Ljava/lang/String;

    .line 55
    iput v3, p0, Landroidx/constraintlayout/widget/d;->Z:I

    .line 56
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->a0:Z

    .line 57
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->b0:Z

    .line 58
    iput-boolean v3, p0, Landroidx/constraintlayout/widget/d;->c0:Z

    .line 59
    iput-boolean v3, p0, Landroidx/constraintlayout/widget/d;->d0:Z

    .line 60
    iput-boolean v3, p0, Landroidx/constraintlayout/widget/d;->e0:Z

    .line 61
    iput v0, p0, Landroidx/constraintlayout/widget/d;->f0:I

    .line 62
    iput v0, p0, Landroidx/constraintlayout/widget/d;->g0:I

    .line 63
    iput v0, p0, Landroidx/constraintlayout/widget/d;->h0:I

    .line 64
    iput v0, p0, Landroidx/constraintlayout/widget/d;->i0:I

    .line 65
    iput v4, p0, Landroidx/constraintlayout/widget/d;->j0:I

    .line 66
    iput v4, p0, Landroidx/constraintlayout/widget/d;->k0:I

    .line 67
    iput v5, p0, Landroidx/constraintlayout/widget/d;->l0:F

    .line 68
    new-instance v0, Lh5/d;

    invoke-direct {v0}, Lh5/d;-><init>()V

    iput-object v0, p0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    return-object p0
.end method

.method public bridge synthetic generateLayoutParams(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->generateLayoutParams(Landroid/util/AttributeSet;)Landroidx/constraintlayout/widget/d;

    move-result-object p0

    return-object p0
.end method

.method public generateLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Landroid/view/ViewGroup$LayoutParams;
    .locals 6

    .line 159
    new-instance p0, Landroidx/constraintlayout/widget/d;

    .line 160
    invoke-direct {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    const/4 p1, -0x1

    .line 161
    iput p1, p0, Landroidx/constraintlayout/widget/d;->a:I

    .line 162
    iput p1, p0, Landroidx/constraintlayout/widget/d;->b:I

    const/high16 v0, -0x40800000    # -1.0f

    .line 163
    iput v0, p0, Landroidx/constraintlayout/widget/d;->c:F

    const/4 v1, 0x1

    .line 164
    iput-boolean v1, p0, Landroidx/constraintlayout/widget/d;->d:Z

    .line 165
    iput p1, p0, Landroidx/constraintlayout/widget/d;->e:I

    .line 166
    iput p1, p0, Landroidx/constraintlayout/widget/d;->f:I

    .line 167
    iput p1, p0, Landroidx/constraintlayout/widget/d;->g:I

    .line 168
    iput p1, p0, Landroidx/constraintlayout/widget/d;->h:I

    .line 169
    iput p1, p0, Landroidx/constraintlayout/widget/d;->i:I

    .line 170
    iput p1, p0, Landroidx/constraintlayout/widget/d;->j:I

    .line 171
    iput p1, p0, Landroidx/constraintlayout/widget/d;->k:I

    .line 172
    iput p1, p0, Landroidx/constraintlayout/widget/d;->l:I

    .line 173
    iput p1, p0, Landroidx/constraintlayout/widget/d;->m:I

    .line 174
    iput p1, p0, Landroidx/constraintlayout/widget/d;->n:I

    .line 175
    iput p1, p0, Landroidx/constraintlayout/widget/d;->o:I

    .line 176
    iput p1, p0, Landroidx/constraintlayout/widget/d;->p:I

    const/4 v2, 0x0

    .line 177
    iput v2, p0, Landroidx/constraintlayout/widget/d;->q:I

    const/4 v3, 0x0

    .line 178
    iput v3, p0, Landroidx/constraintlayout/widget/d;->r:F

    .line 179
    iput p1, p0, Landroidx/constraintlayout/widget/d;->s:I

    .line 180
    iput p1, p0, Landroidx/constraintlayout/widget/d;->t:I

    .line 181
    iput p1, p0, Landroidx/constraintlayout/widget/d;->u:I

    .line 182
    iput p1, p0, Landroidx/constraintlayout/widget/d;->v:I

    const/high16 v3, -0x80000000

    .line 183
    iput v3, p0, Landroidx/constraintlayout/widget/d;->w:I

    .line 184
    iput v3, p0, Landroidx/constraintlayout/widget/d;->x:I

    .line 185
    iput v3, p0, Landroidx/constraintlayout/widget/d;->y:I

    .line 186
    iput v3, p0, Landroidx/constraintlayout/widget/d;->z:I

    .line 187
    iput v3, p0, Landroidx/constraintlayout/widget/d;->A:I

    .line 188
    iput v3, p0, Landroidx/constraintlayout/widget/d;->B:I

    .line 189
    iput v3, p0, Landroidx/constraintlayout/widget/d;->C:I

    .line 190
    iput v2, p0, Landroidx/constraintlayout/widget/d;->D:I

    const/high16 v4, 0x3f000000    # 0.5f

    .line 191
    iput v4, p0, Landroidx/constraintlayout/widget/d;->E:F

    .line 192
    iput v4, p0, Landroidx/constraintlayout/widget/d;->F:F

    const/4 v5, 0x0

    .line 193
    iput-object v5, p0, Landroidx/constraintlayout/widget/d;->G:Ljava/lang/String;

    .line 194
    iput v0, p0, Landroidx/constraintlayout/widget/d;->H:F

    .line 195
    iput v0, p0, Landroidx/constraintlayout/widget/d;->I:F

    .line 196
    iput v2, p0, Landroidx/constraintlayout/widget/d;->J:I

    .line 197
    iput v2, p0, Landroidx/constraintlayout/widget/d;->K:I

    .line 198
    iput v2, p0, Landroidx/constraintlayout/widget/d;->L:I

    .line 199
    iput v2, p0, Landroidx/constraintlayout/widget/d;->M:I

    .line 200
    iput v2, p0, Landroidx/constraintlayout/widget/d;->N:I

    .line 201
    iput v2, p0, Landroidx/constraintlayout/widget/d;->O:I

    .line 202
    iput v2, p0, Landroidx/constraintlayout/widget/d;->P:I

    .line 203
    iput v2, p0, Landroidx/constraintlayout/widget/d;->Q:I

    const/high16 v0, 0x3f800000    # 1.0f

    .line 204
    iput v0, p0, Landroidx/constraintlayout/widget/d;->R:F

    .line 205
    iput v0, p0, Landroidx/constraintlayout/widget/d;->S:F

    .line 206
    iput p1, p0, Landroidx/constraintlayout/widget/d;->T:I

    .line 207
    iput p1, p0, Landroidx/constraintlayout/widget/d;->U:I

    .line 208
    iput p1, p0, Landroidx/constraintlayout/widget/d;->V:I

    .line 209
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->W:Z

    .line 210
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->X:Z

    .line 211
    iput-object v5, p0, Landroidx/constraintlayout/widget/d;->Y:Ljava/lang/String;

    .line 212
    iput v2, p0, Landroidx/constraintlayout/widget/d;->Z:I

    .line 213
    iput-boolean v1, p0, Landroidx/constraintlayout/widget/d;->a0:Z

    .line 214
    iput-boolean v1, p0, Landroidx/constraintlayout/widget/d;->b0:Z

    .line 215
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->c0:Z

    .line 216
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->d0:Z

    .line 217
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/d;->e0:Z

    .line 218
    iput p1, p0, Landroidx/constraintlayout/widget/d;->f0:I

    .line 219
    iput p1, p0, Landroidx/constraintlayout/widget/d;->g0:I

    .line 220
    iput p1, p0, Landroidx/constraintlayout/widget/d;->h0:I

    .line 221
    iput p1, p0, Landroidx/constraintlayout/widget/d;->i0:I

    .line 222
    iput v3, p0, Landroidx/constraintlayout/widget/d;->j0:I

    .line 223
    iput v3, p0, Landroidx/constraintlayout/widget/d;->k0:I

    .line 224
    iput v4, p0, Landroidx/constraintlayout/widget/d;->l0:F

    .line 225
    new-instance p1, Lh5/d;

    invoke-direct {p1}, Lh5/d;-><init>()V

    iput-object p1, p0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    return-object p0
.end method

.method public generateLayoutParams(Landroid/util/AttributeSet;)Landroidx/constraintlayout/widget/d;
    .locals 11

    .line 2
    new-instance v0, Landroidx/constraintlayout/widget/d;

    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p0

    .line 3
    invoke-direct {v0, p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    const/4 v1, -0x1

    .line 4
    iput v1, v0, Landroidx/constraintlayout/widget/d;->a:I

    .line 5
    iput v1, v0, Landroidx/constraintlayout/widget/d;->b:I

    const/high16 v2, -0x40800000    # -1.0f

    .line 6
    iput v2, v0, Landroidx/constraintlayout/widget/d;->c:F

    const/4 v3, 0x1

    .line 7
    iput-boolean v3, v0, Landroidx/constraintlayout/widget/d;->d:Z

    .line 8
    iput v1, v0, Landroidx/constraintlayout/widget/d;->e:I

    .line 9
    iput v1, v0, Landroidx/constraintlayout/widget/d;->f:I

    .line 10
    iput v1, v0, Landroidx/constraintlayout/widget/d;->g:I

    .line 11
    iput v1, v0, Landroidx/constraintlayout/widget/d;->h:I

    .line 12
    iput v1, v0, Landroidx/constraintlayout/widget/d;->i:I

    .line 13
    iput v1, v0, Landroidx/constraintlayout/widget/d;->j:I

    .line 14
    iput v1, v0, Landroidx/constraintlayout/widget/d;->k:I

    .line 15
    iput v1, v0, Landroidx/constraintlayout/widget/d;->l:I

    .line 16
    iput v1, v0, Landroidx/constraintlayout/widget/d;->m:I

    .line 17
    iput v1, v0, Landroidx/constraintlayout/widget/d;->n:I

    .line 18
    iput v1, v0, Landroidx/constraintlayout/widget/d;->o:I

    .line 19
    iput v1, v0, Landroidx/constraintlayout/widget/d;->p:I

    const/4 v4, 0x0

    .line 20
    iput v4, v0, Landroidx/constraintlayout/widget/d;->q:I

    const/4 v5, 0x0

    .line 21
    iput v5, v0, Landroidx/constraintlayout/widget/d;->r:F

    .line 22
    iput v1, v0, Landroidx/constraintlayout/widget/d;->s:I

    .line 23
    iput v1, v0, Landroidx/constraintlayout/widget/d;->t:I

    .line 24
    iput v1, v0, Landroidx/constraintlayout/widget/d;->u:I

    .line 25
    iput v1, v0, Landroidx/constraintlayout/widget/d;->v:I

    const/high16 v6, -0x80000000

    .line 26
    iput v6, v0, Landroidx/constraintlayout/widget/d;->w:I

    .line 27
    iput v6, v0, Landroidx/constraintlayout/widget/d;->x:I

    .line 28
    iput v6, v0, Landroidx/constraintlayout/widget/d;->y:I

    .line 29
    iput v6, v0, Landroidx/constraintlayout/widget/d;->z:I

    .line 30
    iput v6, v0, Landroidx/constraintlayout/widget/d;->A:I

    .line 31
    iput v6, v0, Landroidx/constraintlayout/widget/d;->B:I

    .line 32
    iput v6, v0, Landroidx/constraintlayout/widget/d;->C:I

    .line 33
    iput v4, v0, Landroidx/constraintlayout/widget/d;->D:I

    const/high16 v7, 0x3f000000    # 0.5f

    .line 34
    iput v7, v0, Landroidx/constraintlayout/widget/d;->E:F

    .line 35
    iput v7, v0, Landroidx/constraintlayout/widget/d;->F:F

    const/4 v8, 0x0

    .line 36
    iput-object v8, v0, Landroidx/constraintlayout/widget/d;->G:Ljava/lang/String;

    .line 37
    iput v2, v0, Landroidx/constraintlayout/widget/d;->H:F

    .line 38
    iput v2, v0, Landroidx/constraintlayout/widget/d;->I:F

    .line 39
    iput v4, v0, Landroidx/constraintlayout/widget/d;->J:I

    .line 40
    iput v4, v0, Landroidx/constraintlayout/widget/d;->K:I

    .line 41
    iput v4, v0, Landroidx/constraintlayout/widget/d;->L:I

    .line 42
    iput v4, v0, Landroidx/constraintlayout/widget/d;->M:I

    .line 43
    iput v4, v0, Landroidx/constraintlayout/widget/d;->N:I

    .line 44
    iput v4, v0, Landroidx/constraintlayout/widget/d;->O:I

    .line 45
    iput v4, v0, Landroidx/constraintlayout/widget/d;->P:I

    .line 46
    iput v4, v0, Landroidx/constraintlayout/widget/d;->Q:I

    const/high16 v2, 0x3f800000    # 1.0f

    .line 47
    iput v2, v0, Landroidx/constraintlayout/widget/d;->R:F

    .line 48
    iput v2, v0, Landroidx/constraintlayout/widget/d;->S:F

    .line 49
    iput v1, v0, Landroidx/constraintlayout/widget/d;->T:I

    .line 50
    iput v1, v0, Landroidx/constraintlayout/widget/d;->U:I

    .line 51
    iput v1, v0, Landroidx/constraintlayout/widget/d;->V:I

    .line 52
    iput-boolean v4, v0, Landroidx/constraintlayout/widget/d;->W:Z

    .line 53
    iput-boolean v4, v0, Landroidx/constraintlayout/widget/d;->X:Z

    .line 54
    iput-object v8, v0, Landroidx/constraintlayout/widget/d;->Y:Ljava/lang/String;

    .line 55
    iput v4, v0, Landroidx/constraintlayout/widget/d;->Z:I

    .line 56
    iput-boolean v3, v0, Landroidx/constraintlayout/widget/d;->a0:Z

    .line 57
    iput-boolean v3, v0, Landroidx/constraintlayout/widget/d;->b0:Z

    .line 58
    iput-boolean v4, v0, Landroidx/constraintlayout/widget/d;->c0:Z

    .line 59
    iput-boolean v4, v0, Landroidx/constraintlayout/widget/d;->d0:Z

    .line 60
    iput-boolean v4, v0, Landroidx/constraintlayout/widget/d;->e0:Z

    .line 61
    iput v1, v0, Landroidx/constraintlayout/widget/d;->f0:I

    .line 62
    iput v1, v0, Landroidx/constraintlayout/widget/d;->g0:I

    .line 63
    iput v1, v0, Landroidx/constraintlayout/widget/d;->h0:I

    .line 64
    iput v1, v0, Landroidx/constraintlayout/widget/d;->i0:I

    .line 65
    iput v6, v0, Landroidx/constraintlayout/widget/d;->j0:I

    .line 66
    iput v6, v0, Landroidx/constraintlayout/widget/d;->k0:I

    .line 67
    iput v7, v0, Landroidx/constraintlayout/widget/d;->l0:F

    .line 68
    new-instance v2, Lh5/d;

    invoke-direct {v2}, Lh5/d;-><init>()V

    iput-object v2, v0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 69
    sget-object v2, Landroidx/constraintlayout/widget/s;->b:[I

    invoke-virtual {p0, p1, v2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p0

    .line 70
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->getIndexCount()I

    move-result p1

    move v2, v4

    :goto_0
    if-ge v2, p1, :cond_1

    .line 71
    invoke-virtual {p0, v2}, Landroid/content/res/TypedArray;->getIndex(I)I

    move-result v6

    .line 72
    sget-object v7, Landroidx/constraintlayout/widget/c;->a:Landroid/util/SparseIntArray;

    invoke-virtual {v7, v6}, Landroid/util/SparseIntArray;->get(I)I

    move-result v7

    .line 73
    const-string v8, "ConstraintLayout"

    const/4 v9, 0x2

    const/4 v10, -0x2

    packed-switch v7, :pswitch_data_0

    packed-switch v7, :pswitch_data_1

    packed-switch v7, :pswitch_data_2

    goto/16 :goto_1

    .line 74
    :pswitch_0
    iget-boolean v7, v0, Landroidx/constraintlayout/widget/d;->d:Z

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v6

    iput-boolean v6, v0, Landroidx/constraintlayout/widget/d;->d:Z

    goto/16 :goto_1

    .line 75
    :pswitch_1
    iget v7, v0, Landroidx/constraintlayout/widget/d;->Z:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->Z:I

    goto/16 :goto_1

    .line 76
    :pswitch_2
    invoke-static {v0, p0, v6, v3}, Landroidx/constraintlayout/widget/o;->g(Ljava/lang/Object;Landroid/content/res/TypedArray;II)V

    goto/16 :goto_1

    .line 77
    :pswitch_3
    invoke-static {v0, p0, v6, v4}, Landroidx/constraintlayout/widget/o;->g(Ljava/lang/Object;Landroid/content/res/TypedArray;II)V

    goto/16 :goto_1

    .line 78
    :pswitch_4
    iget v7, v0, Landroidx/constraintlayout/widget/d;->C:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->C:I

    goto/16 :goto_1

    .line 79
    :pswitch_5
    iget v7, v0, Landroidx/constraintlayout/widget/d;->D:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->D:I

    goto/16 :goto_1

    .line 80
    :pswitch_6
    iget v7, v0, Landroidx/constraintlayout/widget/d;->o:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->o:I

    if-ne v7, v1, :cond_0

    .line 81
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->o:I

    goto/16 :goto_1

    .line 82
    :pswitch_7
    iget v7, v0, Landroidx/constraintlayout/widget/d;->n:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->n:I

    if-ne v7, v1, :cond_0

    .line 83
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->n:I

    goto/16 :goto_1

    .line 84
    :pswitch_8
    invoke-virtual {p0, v6}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v6

    iput-object v6, v0, Landroidx/constraintlayout/widget/d;->Y:Ljava/lang/String;

    goto/16 :goto_1

    .line 85
    :pswitch_9
    iget v7, v0, Landroidx/constraintlayout/widget/d;->U:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->U:I

    goto/16 :goto_1

    .line 86
    :pswitch_a
    iget v7, v0, Landroidx/constraintlayout/widget/d;->T:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->T:I

    goto/16 :goto_1

    .line 87
    :pswitch_b
    invoke-virtual {p0, v6, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->K:I

    goto/16 :goto_1

    .line 88
    :pswitch_c
    invoke-virtual {p0, v6, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->J:I

    goto/16 :goto_1

    .line 89
    :pswitch_d
    iget v7, v0, Landroidx/constraintlayout/widget/d;->I:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->I:F

    goto/16 :goto_1

    .line 90
    :pswitch_e
    iget v7, v0, Landroidx/constraintlayout/widget/d;->H:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->H:F

    goto/16 :goto_1

    .line 91
    :pswitch_f
    invoke-virtual {p0, v6}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v6

    invoke-static {v0, v6}, Landroidx/constraintlayout/widget/o;->h(Landroidx/constraintlayout/widget/d;Ljava/lang/String;)V

    goto/16 :goto_1

    .line 92
    :pswitch_10
    iget v7, v0, Landroidx/constraintlayout/widget/d;->S:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    invoke-static {v5, v6}, Ljava/lang/Math;->max(FF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->S:F

    .line 93
    iput v9, v0, Landroidx/constraintlayout/widget/d;->M:I

    goto/16 :goto_1

    .line 94
    :pswitch_11
    :try_start_0
    iget v7, v0, Landroidx/constraintlayout/widget/d;->Q:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->Q:I
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto/16 :goto_1

    .line 95
    :catch_0
    iget v7, v0, Landroidx/constraintlayout/widget/d;->Q:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    if-ne v6, v10, :cond_0

    .line 96
    iput v10, v0, Landroidx/constraintlayout/widget/d;->Q:I

    goto/16 :goto_1

    .line 97
    :pswitch_12
    :try_start_1
    iget v7, v0, Landroidx/constraintlayout/widget/d;->O:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->O:I
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto/16 :goto_1

    .line 98
    :catch_1
    iget v7, v0, Landroidx/constraintlayout/widget/d;->O:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    if-ne v6, v10, :cond_0

    .line 99
    iput v10, v0, Landroidx/constraintlayout/widget/d;->O:I

    goto/16 :goto_1

    .line 100
    :pswitch_13
    iget v7, v0, Landroidx/constraintlayout/widget/d;->R:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    invoke-static {v5, v6}, Ljava/lang/Math;->max(FF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->R:F

    .line 101
    iput v9, v0, Landroidx/constraintlayout/widget/d;->L:I

    goto/16 :goto_1

    .line 102
    :pswitch_14
    :try_start_2
    iget v7, v0, Landroidx/constraintlayout/widget/d;->P:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->P:I
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    goto/16 :goto_1

    .line 103
    :catch_2
    iget v7, v0, Landroidx/constraintlayout/widget/d;->P:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    if-ne v6, v10, :cond_0

    .line 104
    iput v10, v0, Landroidx/constraintlayout/widget/d;->P:I

    goto/16 :goto_1

    .line 105
    :pswitch_15
    :try_start_3
    iget v7, v0, Landroidx/constraintlayout/widget/d;->N:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->N:I
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    goto/16 :goto_1

    .line 106
    :catch_3
    iget v7, v0, Landroidx/constraintlayout/widget/d;->N:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    if-ne v6, v10, :cond_0

    .line 107
    iput v10, v0, Landroidx/constraintlayout/widget/d;->N:I

    goto/16 :goto_1

    .line 108
    :pswitch_16
    invoke-virtual {p0, v6, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->M:I

    if-ne v6, v3, :cond_0

    .line 109
    const-string v6, "layout_constraintHeight_default=\"wrap\" is deprecated.\nUse layout_height=\"WRAP_CONTENT\" and layout_constrainedHeight=\"true\" instead."

    invoke-static {v8, v6}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto/16 :goto_1

    .line 110
    :pswitch_17
    invoke-virtual {p0, v6, v4}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->L:I

    if-ne v6, v3, :cond_0

    .line 111
    const-string v6, "layout_constraintWidth_default=\"wrap\" is deprecated.\nUse layout_width=\"WRAP_CONTENT\" and layout_constrainedWidth=\"true\" instead."

    invoke-static {v8, v6}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto/16 :goto_1

    .line 112
    :pswitch_18
    iget v7, v0, Landroidx/constraintlayout/widget/d;->F:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->F:F

    goto/16 :goto_1

    .line 113
    :pswitch_19
    iget v7, v0, Landroidx/constraintlayout/widget/d;->E:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->E:F

    goto/16 :goto_1

    .line 114
    :pswitch_1a
    iget-boolean v7, v0, Landroidx/constraintlayout/widget/d;->X:Z

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v6

    iput-boolean v6, v0, Landroidx/constraintlayout/widget/d;->X:Z

    goto/16 :goto_1

    .line 115
    :pswitch_1b
    iget-boolean v7, v0, Landroidx/constraintlayout/widget/d;->W:Z

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v6

    iput-boolean v6, v0, Landroidx/constraintlayout/widget/d;->W:Z

    goto/16 :goto_1

    .line 116
    :pswitch_1c
    iget v7, v0, Landroidx/constraintlayout/widget/d;->B:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->B:I

    goto/16 :goto_1

    .line 117
    :pswitch_1d
    iget v7, v0, Landroidx/constraintlayout/widget/d;->A:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->A:I

    goto/16 :goto_1

    .line 118
    :pswitch_1e
    iget v7, v0, Landroidx/constraintlayout/widget/d;->z:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->z:I

    goto/16 :goto_1

    .line 119
    :pswitch_1f
    iget v7, v0, Landroidx/constraintlayout/widget/d;->y:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->y:I

    goto/16 :goto_1

    .line 120
    :pswitch_20
    iget v7, v0, Landroidx/constraintlayout/widget/d;->x:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->x:I

    goto/16 :goto_1

    .line 121
    :pswitch_21
    iget v7, v0, Landroidx/constraintlayout/widget/d;->w:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->w:I

    goto/16 :goto_1

    .line 122
    :pswitch_22
    iget v7, v0, Landroidx/constraintlayout/widget/d;->v:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->v:I

    if-ne v7, v1, :cond_0

    .line 123
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->v:I

    goto/16 :goto_1

    .line 124
    :pswitch_23
    iget v7, v0, Landroidx/constraintlayout/widget/d;->u:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->u:I

    if-ne v7, v1, :cond_0

    .line 125
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->u:I

    goto/16 :goto_1

    .line 126
    :pswitch_24
    iget v7, v0, Landroidx/constraintlayout/widget/d;->t:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->t:I

    if-ne v7, v1, :cond_0

    .line 127
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->t:I

    goto/16 :goto_1

    .line 128
    :pswitch_25
    iget v7, v0, Landroidx/constraintlayout/widget/d;->s:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->s:I

    if-ne v7, v1, :cond_0

    .line 129
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->s:I

    goto/16 :goto_1

    .line 130
    :pswitch_26
    iget v7, v0, Landroidx/constraintlayout/widget/d;->m:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->m:I

    if-ne v7, v1, :cond_0

    .line 131
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->m:I

    goto/16 :goto_1

    .line 132
    :pswitch_27
    iget v7, v0, Landroidx/constraintlayout/widget/d;->l:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->l:I

    if-ne v7, v1, :cond_0

    .line 133
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->l:I

    goto/16 :goto_1

    .line 134
    :pswitch_28
    iget v7, v0, Landroidx/constraintlayout/widget/d;->k:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->k:I

    if-ne v7, v1, :cond_0

    .line 135
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->k:I

    goto/16 :goto_1

    .line 136
    :pswitch_29
    iget v7, v0, Landroidx/constraintlayout/widget/d;->j:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->j:I

    if-ne v7, v1, :cond_0

    .line 137
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->j:I

    goto/16 :goto_1

    .line 138
    :pswitch_2a
    iget v7, v0, Landroidx/constraintlayout/widget/d;->i:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->i:I

    if-ne v7, v1, :cond_0

    .line 139
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->i:I

    goto/16 :goto_1

    .line 140
    :pswitch_2b
    iget v7, v0, Landroidx/constraintlayout/widget/d;->h:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->h:I

    if-ne v7, v1, :cond_0

    .line 141
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->h:I

    goto/16 :goto_1

    .line 142
    :pswitch_2c
    iget v7, v0, Landroidx/constraintlayout/widget/d;->g:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->g:I

    if-ne v7, v1, :cond_0

    .line 143
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->g:I

    goto/16 :goto_1

    .line 144
    :pswitch_2d
    iget v7, v0, Landroidx/constraintlayout/widget/d;->f:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->f:I

    if-ne v7, v1, :cond_0

    .line 145
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->f:I

    goto :goto_1

    .line 146
    :pswitch_2e
    iget v7, v0, Landroidx/constraintlayout/widget/d;->e:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->e:I

    if-ne v7, v1, :cond_0

    .line 147
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->e:I

    goto :goto_1

    .line 148
    :pswitch_2f
    iget v7, v0, Landroidx/constraintlayout/widget/d;->c:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->c:F

    goto :goto_1

    .line 149
    :pswitch_30
    iget v7, v0, Landroidx/constraintlayout/widget/d;->b:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->b:I

    goto :goto_1

    .line 150
    :pswitch_31
    iget v7, v0, Landroidx/constraintlayout/widget/d;->a:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelOffset(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->a:I

    goto :goto_1

    .line 151
    :pswitch_32
    iget v7, v0, Landroidx/constraintlayout/widget/d;->r:F

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v6

    const/high16 v7, 0x43b40000    # 360.0f

    rem-float/2addr v6, v7

    iput v6, v0, Landroidx/constraintlayout/widget/d;->r:F

    cmpg-float v8, v6, v5

    if-gez v8, :cond_0

    sub-float v6, v7, v6

    rem-float/2addr v6, v7

    .line 152
    iput v6, v0, Landroidx/constraintlayout/widget/d;->r:F

    goto :goto_1

    .line 153
    :pswitch_33
    iget v7, v0, Landroidx/constraintlayout/widget/d;->q:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->q:I

    goto :goto_1

    .line 154
    :pswitch_34
    iget v7, v0, Landroidx/constraintlayout/widget/d;->p:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v7

    iput v7, v0, Landroidx/constraintlayout/widget/d;->p:I

    if-ne v7, v1, :cond_0

    .line 155
    invoke-virtual {p0, v6, v1}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->p:I

    goto :goto_1

    .line 156
    :pswitch_35
    iget v7, v0, Landroidx/constraintlayout/widget/d;->V:I

    invoke-virtual {p0, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v6

    iput v6, v0, Landroidx/constraintlayout/widget/d;->V:I

    :cond_0
    :goto_1
    add-int/lit8 v2, v2, 0x1

    goto/16 :goto_0

    .line 157
    :cond_1
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    .line 158
    invoke-virtual {v0}, Landroidx/constraintlayout/widget/d;->a()V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x2c
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x40
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public getDesignInformation(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    instance-of p1, p2, Ljava/lang/String;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    check-cast p2, Ljava/lang/String;

    .line 8
    .line 9
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 20
    .line 21
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return-object p0
.end method

.method public getMaxHeight()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxWidth()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public getMinHeight()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 2
    .line 3
    return p0
.end method

.method public getMinWidth()I
    .locals 0

    .line 1
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public getOptimizationLevel()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 2
    .line 3
    iget p0, p0, Lh5/e;->E0:I

    .line 4
    .line 5
    return p0
.end method

.method public getSceneString()Ljava/lang/String;
    .locals 8

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 7
    .line 8
    iget-object v1, v1, Lh5/d;->k:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, -0x1

    .line 11
    if-nez v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getId()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eq v1, v2, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-virtual {v3, v1}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    iget-object v3, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 32
    .line 33
    iput-object v1, v3, Lh5/d;->k:Ljava/lang/String;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 37
    .line 38
    const-string v3, "parent"

    .line 39
    .line 40
    iput-object v3, v1, Lh5/d;->k:Ljava/lang/String;

    .line 41
    .line 42
    :cond_1
    :goto_0
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 43
    .line 44
    iget-object v3, v1, Lh5/d;->i0:Ljava/lang/String;

    .line 45
    .line 46
    const-string v4, " setDebugName "

    .line 47
    .line 48
    const-string v5, "ConstraintLayout"

    .line 49
    .line 50
    if-nez v3, :cond_2

    .line 51
    .line 52
    iget-object v3, v1, Lh5/d;->k:Ljava/lang/String;

    .line 53
    .line 54
    iput-object v3, v1, Lh5/d;->i0:Ljava/lang/String;

    .line 55
    .line 56
    new-instance v1, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v3, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 62
    .line 63
    iget-object v3, v3, Lh5/d;->i0:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-static {v5, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    :cond_2
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 76
    .line 77
    iget-object v1, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    :cond_3
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    if-eqz v3, :cond_5

    .line 88
    .line 89
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    check-cast v3, Lh5/d;

    .line 94
    .line 95
    iget-object v6, v3, Lh5/d;->g0:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v6, Landroid/view/View;

    .line 98
    .line 99
    if-eqz v6, :cond_3

    .line 100
    .line 101
    iget-object v7, v3, Lh5/d;->k:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v7, :cond_4

    .line 104
    .line 105
    invoke-virtual {v6}, Landroid/view/View;->getId()I

    .line 106
    .line 107
    .line 108
    move-result v6

    .line 109
    if-eq v6, v2, :cond_4

    .line 110
    .line 111
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    invoke-virtual {v7, v6}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v6

    .line 123
    iput-object v6, v3, Lh5/d;->k:Ljava/lang/String;

    .line 124
    .line 125
    :cond_4
    iget-object v6, v3, Lh5/d;->i0:Ljava/lang/String;

    .line 126
    .line 127
    if-nez v6, :cond_3

    .line 128
    .line 129
    iget-object v6, v3, Lh5/d;->k:Ljava/lang/String;

    .line 130
    .line 131
    iput-object v6, v3, Lh5/d;->i0:Ljava/lang/String;

    .line 132
    .line 133
    new-instance v6, Ljava/lang/StringBuilder;

    .line 134
    .line 135
    invoke-direct {v6, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    iget-object v3, v3, Lh5/d;->i0:Ljava/lang/String;

    .line 139
    .line 140
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    invoke-static {v5, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 148
    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_5
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 152
    .line 153
    invoke-virtual {p0, v0}, Lh5/e;->o(Ljava/lang/StringBuilder;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    return-object p0
.end method

.method public getViewById(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/view/View;

    .line 8
    .line 9
    return-object p0
.end method

.method public final getViewWidget(Landroid/view/View;)Lh5/d;
    .locals 1

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    if-eqz p1, :cond_2

    .line 7
    .line 8
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    instance-of v0, v0, Landroidx/constraintlayout/widget/d;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Landroidx/constraintlayout/widget/d;

    .line 21
    .line 22
    iget-object p0, p0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {p0, v0}, Landroidx/constraintlayout/widget/ConstraintLayout;->generateLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Landroid/view/ViewGroup$LayoutParams;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p1, p0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    instance-of p0, p0, Landroidx/constraintlayout/widget/d;

    .line 41
    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Landroidx/constraintlayout/widget/d;

    .line 49
    .line 50
    iget-object p0, p0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_2
    const/4 p0, 0x0

    .line 54
    return-object p0
.end method

.method public isRtl()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget v0, v0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 10
    .line 11
    const/high16 v1, 0x400000

    .line 12
    .line 13
    and-int/2addr v0, v1

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    const/4 v0, 0x1

    .line 21
    if-ne v0, p0, :cond_0

    .line 22
    .line 23
    return v0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public loadLayoutDescription(I)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    :try_start_0
    new-instance v1, Landroidx/constraintlayout/widget/h;

    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    invoke-direct {v1, v2, p0, p1}, Landroidx/constraintlayout/widget/h;-><init>(Landroid/content/Context;Landroidx/constraintlayout/widget/ConstraintLayout;I)V

    .line 11
    .line 12
    .line 13
    iput-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    return-void

    .line 16
    :catch_0
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    .line 20
    .line 21
    return-void
.end method

.method public onLayout(ZIIII)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    const/4 p3, 0x0

    .line 10
    move p4, p3

    .line 11
    :goto_0
    if-ge p4, p1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0, p4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object p5

    .line 17
    invoke-virtual {p5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Landroidx/constraintlayout/widget/d;

    .line 22
    .line 23
    iget-object v1, v0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 24
    .line 25
    invoke-virtual {p5}, Landroid/view/View;->getVisibility()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const/16 v3, 0x8

    .line 30
    .line 31
    if-ne v2, v3, :cond_0

    .line 32
    .line 33
    iget-boolean v2, v0, Landroidx/constraintlayout/widget/d;->d0:Z

    .line 34
    .line 35
    if-nez v2, :cond_0

    .line 36
    .line 37
    iget-boolean v0, v0, Landroidx/constraintlayout/widget/d;->e0:Z

    .line 38
    .line 39
    if-nez v0, :cond_0

    .line 40
    .line 41
    if-nez p2, :cond_0

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    invoke-virtual {v1}, Lh5/d;->s()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    invoke-virtual {v1}, Lh5/d;->t()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    add-int/2addr v3, v0

    .line 57
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    add-int/2addr v1, v2

    .line 62
    invoke-virtual {p5, v0, v2, v3, v1}, Landroid/view/View;->layout(IIII)V

    .line 63
    .line 64
    .line 65
    :goto_1
    add-int/lit8 p4, p4, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    if-lez p1, :cond_2

    .line 75
    .line 76
    :goto_2
    if-ge p3, p1, :cond_2

    .line 77
    .line 78
    iget-object p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 79
    .line 80
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    check-cast p2, Landroidx/constraintlayout/widget/b;

    .line 85
    .line 86
    invoke-virtual {p2}, Landroidx/constraintlayout/widget/b;->j()V

    .line 87
    .line 88
    .line 89
    add-int/lit8 p3, p3, 0x1

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_2
    return-void
.end method

.method public onMeasure(II)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v6, p1

    .line 4
    .line 5
    move/from16 v7, p2

    .line 6
    .line 7
    iget v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureWidthMeasureSpec:I

    .line 8
    .line 9
    if-ne v1, v6, :cond_0

    .line 10
    .line 11
    iget v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureHeightMeasureSpec:I

    .line 12
    .line 13
    :cond_0
    iget-boolean v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const/4 v3, 0x0

    .line 17
    if-nez v1, :cond_2

    .line 18
    .line 19
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    move v4, v3

    .line 24
    :goto_0
    if-ge v4, v1, :cond_2

    .line 25
    .line 26
    invoke-virtual {v0, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    invoke-virtual {v5}, Landroid/view/View;->isLayoutRequested()Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    iput-boolean v2, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    :goto_1
    iput v6, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureWidthMeasureSpec:I

    .line 43
    .line 44
    iput v7, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOnMeasureHeightMeasureSpec:I

    .line 45
    .line 46
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 47
    .line 48
    invoke-virtual {v0}, Landroidx/constraintlayout/widget/ConstraintLayout;->isRtl()Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    iput-boolean v4, v1, Lh5/e;->w0:Z

    .line 53
    .line 54
    iget-boolean v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 55
    .line 56
    if-eqz v1, :cond_19

    .line 57
    .line 58
    iput-boolean v3, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 59
    .line 60
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    move v4, v3

    .line 65
    :goto_2
    if-ge v4, v1, :cond_4

    .line 66
    .line 67
    invoke-virtual {v0, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-virtual {v5}, Landroid/view/View;->isLayoutRequested()Z

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    if-eqz v5, :cond_3

    .line 76
    .line 77
    move v8, v2

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    add-int/lit8 v4, v4, 0x1

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    move v8, v3

    .line 83
    :goto_3
    if-eqz v8, :cond_18

    .line 84
    .line 85
    invoke-virtual {v0}, Landroid/view/View;->isInEditMode()Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 90
    .line 91
    .line 92
    move-result v9

    .line 93
    move v2, v3

    .line 94
    :goto_4
    if-ge v2, v9, :cond_6

    .line 95
    .line 96
    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    invoke-virtual {v0, v4}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewWidget(Landroid/view/View;)Lh5/d;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    if-nez v4, :cond_5

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_5
    invoke-virtual {v4}, Lh5/d;->D()V

    .line 108
    .line 109
    .line 110
    :goto_5
    add-int/lit8 v2, v2, 0x1

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_6
    const/4 v2, 0x0

    .line 114
    const/4 v4, -0x1

    .line 115
    if-eqz v1, :cond_c

    .line 116
    .line 117
    move v5, v3

    .line 118
    :goto_6
    if-ge v5, v9, :cond_c

    .line 119
    .line 120
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 121
    .line 122
    .line 123
    move-result-object v10

    .line 124
    :try_start_0
    invoke-virtual {v0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 125
    .line 126
    .line 127
    move-result-object v11

    .line 128
    invoke-virtual {v10}, Landroid/view/View;->getId()I

    .line 129
    .line 130
    .line 131
    move-result v12

    .line 132
    invoke-virtual {v11, v12}, Landroid/content/res/Resources;->getResourceName(I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v11

    .line 136
    invoke-virtual {v10}, Landroid/view/View;->getId()I

    .line 137
    .line 138
    .line 139
    move-result v12

    .line 140
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 141
    .line 142
    .line 143
    move-result-object v12

    .line 144
    invoke-virtual {v0, v3, v11, v12}, Landroidx/constraintlayout/widget/ConstraintLayout;->setDesignInformation(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    const/16 v12, 0x2f

    .line 148
    .line 149
    invoke-virtual {v11, v12}, Ljava/lang/String;->indexOf(I)I

    .line 150
    .line 151
    .line 152
    move-result v12

    .line 153
    if-eq v12, v4, :cond_7

    .line 154
    .line 155
    add-int/lit8 v12, v12, 0x1

    .line 156
    .line 157
    invoke-virtual {v11, v12}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v11

    .line 161
    :cond_7
    invoke-virtual {v10}, Landroid/view/View;->getId()I

    .line 162
    .line 163
    .line 164
    move-result v10

    .line 165
    if-nez v10, :cond_8

    .line 166
    .line 167
    iget-object v10, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 168
    .line 169
    goto :goto_7

    .line 170
    :cond_8
    iget-object v12, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 171
    .line 172
    invoke-virtual {v12, v10}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v12

    .line 176
    check-cast v12, Landroid/view/View;

    .line 177
    .line 178
    if-nez v12, :cond_9

    .line 179
    .line 180
    invoke-virtual {v0, v10}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 181
    .line 182
    .line 183
    move-result-object v12

    .line 184
    if-eqz v12, :cond_9

    .line 185
    .line 186
    if-eq v12, v0, :cond_9

    .line 187
    .line 188
    invoke-virtual {v12}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 189
    .line 190
    .line 191
    move-result-object v10

    .line 192
    if-ne v10, v0, :cond_9

    .line 193
    .line 194
    invoke-virtual {v0, v12}, Landroidx/constraintlayout/widget/ConstraintLayout;->onViewAdded(Landroid/view/View;)V

    .line 195
    .line 196
    .line 197
    :cond_9
    if-ne v12, v0, :cond_a

    .line 198
    .line 199
    iget-object v10, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 200
    .line 201
    goto :goto_7

    .line 202
    :cond_a
    if-nez v12, :cond_b

    .line 203
    .line 204
    move-object v10, v2

    .line 205
    goto :goto_7

    .line 206
    :cond_b
    invoke-virtual {v12}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 207
    .line 208
    .line 209
    move-result-object v10

    .line 210
    check-cast v10, Landroidx/constraintlayout/widget/d;

    .line 211
    .line 212
    iget-object v10, v10, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 213
    .line 214
    :goto_7
    iput-object v11, v10, Lh5/d;->i0:Ljava/lang/String;
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 215
    .line 216
    :catch_0
    add-int/lit8 v5, v5, 0x1

    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_c
    iget v5, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSetId:I

    .line 220
    .line 221
    if-eq v5, v4, :cond_d

    .line 222
    .line 223
    move v4, v3

    .line 224
    :goto_8
    if-ge v4, v9, :cond_d

    .line 225
    .line 226
    invoke-virtual {v0, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 227
    .line 228
    .line 229
    move-result-object v5

    .line 230
    invoke-virtual {v5}, Landroid/view/View;->getId()I

    .line 231
    .line 232
    .line 233
    add-int/lit8 v4, v4, 0x1

    .line 234
    .line 235
    goto :goto_8

    .line 236
    :cond_d
    iget-object v4, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 237
    .line 238
    if-eqz v4, :cond_e

    .line 239
    .line 240
    invoke-virtual {v4, v0}, Landroidx/constraintlayout/widget/o;->a(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    .line 241
    .line 242
    .line 243
    :cond_e
    iget-object v4, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 244
    .line 245
    iget-object v4, v4, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 246
    .line 247
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 248
    .line 249
    .line 250
    iget-object v4, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 251
    .line 252
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 253
    .line 254
    .line 255
    move-result v4

    .line 256
    if-lez v4, :cond_14

    .line 257
    .line 258
    move v5, v3

    .line 259
    :goto_9
    if-ge v5, v4, :cond_14

    .line 260
    .line 261
    iget-object v10, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 262
    .line 263
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v10

    .line 267
    check-cast v10, Landroidx/constraintlayout/widget/b;

    .line 268
    .line 269
    iget-object v11, v10, Landroidx/constraintlayout/widget/b;->j:Ljava/util/HashMap;

    .line 270
    .line 271
    invoke-virtual {v10}, Landroid/view/View;->isInEditMode()Z

    .line 272
    .line 273
    .line 274
    move-result v12

    .line 275
    if-eqz v12, :cond_f

    .line 276
    .line 277
    iget-object v12, v10, Landroidx/constraintlayout/widget/b;->h:Ljava/lang/String;

    .line 278
    .line 279
    invoke-virtual {v10, v12}, Landroidx/constraintlayout/widget/b;->setIds(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    :cond_f
    iget-object v12, v10, Landroidx/constraintlayout/widget/b;->g:Lh5/i;

    .line 283
    .line 284
    if-nez v12, :cond_10

    .line 285
    .line 286
    goto :goto_b

    .line 287
    :cond_10
    iput v3, v12, Lh5/i;->s0:I

    .line 288
    .line 289
    iget-object v12, v12, Lh5/i;->r0:[Lh5/d;

    .line 290
    .line 291
    invoke-static {v12, v2}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    move v12, v3

    .line 295
    :goto_a
    iget v13, v10, Landroidx/constraintlayout/widget/b;->e:I

    .line 296
    .line 297
    if-ge v12, v13, :cond_13

    .line 298
    .line 299
    iget-object v13, v10, Landroidx/constraintlayout/widget/b;->d:[I

    .line 300
    .line 301
    aget v13, v13, v12

    .line 302
    .line 303
    invoke-virtual {v0, v13}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewById(I)Landroid/view/View;

    .line 304
    .line 305
    .line 306
    move-result-object v14

    .line 307
    if-nez v14, :cond_11

    .line 308
    .line 309
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 310
    .line 311
    .line 312
    move-result-object v13

    .line 313
    invoke-virtual {v11, v13}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v13

    .line 317
    check-cast v13, Ljava/lang/String;

    .line 318
    .line 319
    invoke-virtual {v10, v0, v13}, Landroidx/constraintlayout/widget/b;->g(Landroidx/constraintlayout/widget/ConstraintLayout;Ljava/lang/String;)I

    .line 320
    .line 321
    .line 322
    move-result v15

    .line 323
    if-eqz v15, :cond_11

    .line 324
    .line 325
    iget-object v14, v10, Landroidx/constraintlayout/widget/b;->d:[I

    .line 326
    .line 327
    aput v15, v14, v12

    .line 328
    .line 329
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 330
    .line 331
    .line 332
    move-result-object v14

    .line 333
    invoke-virtual {v11, v14, v13}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v0, v15}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewById(I)Landroid/view/View;

    .line 337
    .line 338
    .line 339
    move-result-object v14

    .line 340
    :cond_11
    if-eqz v14, :cond_12

    .line 341
    .line 342
    iget-object v13, v10, Landroidx/constraintlayout/widget/b;->g:Lh5/i;

    .line 343
    .line 344
    invoke-virtual {v0, v14}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewWidget(Landroid/view/View;)Lh5/d;

    .line 345
    .line 346
    .line 347
    move-result-object v14

    .line 348
    invoke-virtual {v13, v14}, Lh5/i;->V(Lh5/d;)V

    .line 349
    .line 350
    .line 351
    :cond_12
    add-int/lit8 v12, v12, 0x1

    .line 352
    .line 353
    goto :goto_a

    .line 354
    :cond_13
    iget-object v10, v10, Landroidx/constraintlayout/widget/b;->g:Lh5/i;

    .line 355
    .line 356
    invoke-virtual {v10}, Lh5/i;->X()V

    .line 357
    .line 358
    .line 359
    :goto_b
    add-int/lit8 v5, v5, 0x1

    .line 360
    .line 361
    goto :goto_9

    .line 362
    :cond_14
    move v2, v3

    .line 363
    :goto_c
    if-ge v2, v9, :cond_15

    .line 364
    .line 365
    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 366
    .line 367
    .line 368
    add-int/lit8 v2, v2, 0x1

    .line 369
    .line 370
    goto :goto_c

    .line 371
    :cond_15
    iget-object v2, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 372
    .line 373
    invoke-virtual {v2}, Landroid/util/SparseArray;->clear()V

    .line 374
    .line 375
    .line 376
    iget-object v2, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 377
    .line 378
    iget-object v4, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 379
    .line 380
    invoke-virtual {v2, v3, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 381
    .line 382
    .line 383
    iget-object v2, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 384
    .line 385
    invoke-virtual {v0}, Landroid/view/View;->getId()I

    .line 386
    .line 387
    .line 388
    move-result v4

    .line 389
    iget-object v5, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 390
    .line 391
    invoke-virtual {v2, v4, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    move v2, v3

    .line 395
    :goto_d
    if-ge v2, v9, :cond_16

    .line 396
    .line 397
    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 398
    .line 399
    .line 400
    move-result-object v4

    .line 401
    invoke-virtual {v0, v4}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewWidget(Landroid/view/View;)Lh5/d;

    .line 402
    .line 403
    .line 404
    move-result-object v5

    .line 405
    iget-object v10, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 406
    .line 407
    invoke-virtual {v4}, Landroid/view/View;->getId()I

    .line 408
    .line 409
    .line 410
    move-result v4

    .line 411
    invoke-virtual {v10, v4, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    add-int/lit8 v2, v2, 0x1

    .line 415
    .line 416
    goto :goto_d

    .line 417
    :cond_16
    move v10, v3

    .line 418
    :goto_e
    if-ge v10, v9, :cond_18

    .line 419
    .line 420
    invoke-virtual {v0, v10}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 421
    .line 422
    .line 423
    move-result-object v2

    .line 424
    invoke-virtual {v0, v2}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewWidget(Landroid/view/View;)Lh5/d;

    .line 425
    .line 426
    .line 427
    move-result-object v3

    .line 428
    if-nez v3, :cond_17

    .line 429
    .line 430
    goto :goto_f

    .line 431
    :cond_17
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 432
    .line 433
    .line 434
    move-result-object v4

    .line 435
    check-cast v4, Landroidx/constraintlayout/widget/d;

    .line 436
    .line 437
    iget-object v5, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 438
    .line 439
    invoke-virtual {v5, v3}, Lh5/e;->V(Lh5/d;)V

    .line 440
    .line 441
    .line 442
    iget-object v5, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mTempMapIdToWidget:Landroid/util/SparseArray;

    .line 443
    .line 444
    invoke-virtual/range {v0 .. v5}, Landroidx/constraintlayout/widget/ConstraintLayout;->applyConstraintsFromLayoutParams(ZLandroid/view/View;Lh5/d;Landroidx/constraintlayout/widget/d;Landroid/util/SparseArray;)V

    .line 445
    .line 446
    .line 447
    :goto_f
    add-int/lit8 v10, v10, 0x1

    .line 448
    .line 449
    goto :goto_e

    .line 450
    :cond_18
    if-eqz v8, :cond_19

    .line 451
    .line 452
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 453
    .line 454
    iget-object v2, v1, Lh5/e;->s0:Lgw0/c;

    .line 455
    .line 456
    invoke-virtual {v2, v1}, Lgw0/c;->D(Lh5/e;)V

    .line 457
    .line 458
    .line 459
    :cond_19
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 460
    .line 461
    iget v2, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    .line 462
    .line 463
    invoke-virtual {v0, v1, v2, v6, v7}, Landroidx/constraintlayout/widget/ConstraintLayout;->resolveSystem(Lh5/e;III)V

    .line 464
    .line 465
    .line 466
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 467
    .line 468
    invoke-virtual {v1}, Lh5/d;->r()I

    .line 469
    .line 470
    .line 471
    move-result v3

    .line 472
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 473
    .line 474
    invoke-virtual {v1}, Lh5/d;->l()I

    .line 475
    .line 476
    .line 477
    move-result v4

    .line 478
    iget-object v1, v0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 479
    .line 480
    iget-boolean v5, v1, Lh5/e;->F0:Z

    .line 481
    .line 482
    iget-boolean v1, v1, Lh5/e;->G0:Z

    .line 483
    .line 484
    move v2, v6

    .line 485
    move v6, v1

    .line 486
    move v1, v2

    .line 487
    move v2, v7

    .line 488
    invoke-virtual/range {v0 .. v6}, Landroidx/constraintlayout/widget/ConstraintLayout;->resolveMeasuredDimension(IIIIZZ)V

    .line 489
    .line 490
    .line 491
    return-void
.end method

.method public onViewAdded(Landroid/view/View;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->onViewAdded(Landroid/view/View;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewWidget(Landroid/view/View;)Lh5/d;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    instance-of v1, p1, Landroidx/constraintlayout/widget/q;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    instance-of v0, v0, Lh5/h;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Landroidx/constraintlayout/widget/d;

    .line 22
    .line 23
    new-instance v1, Lh5/h;

    .line 24
    .line 25
    invoke-direct {v1}, Lh5/h;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v1, v0, Landroidx/constraintlayout/widget/d;->p0:Lh5/d;

    .line 29
    .line 30
    iput-boolean v2, v0, Landroidx/constraintlayout/widget/d;->d0:Z

    .line 31
    .line 32
    iget v0, v0, Landroidx/constraintlayout/widget/d;->V:I

    .line 33
    .line 34
    invoke-virtual {v1, v0}, Lh5/h;->W(I)V

    .line 35
    .line 36
    .line 37
    :cond_0
    instance-of v0, p1, Landroidx/constraintlayout/widget/b;

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    move-object v0, p1

    .line 42
    check-cast v0, Landroidx/constraintlayout/widget/b;

    .line 43
    .line 44
    invoke-virtual {v0}, Landroidx/constraintlayout/widget/b;->k()V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Landroidx/constraintlayout/widget/d;

    .line 52
    .line 53
    iput-boolean v2, v1, Landroidx/constraintlayout/widget/d;->e0:Z

    .line 54
    .line 55
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 56
    .line 57
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_1

    .line 62
    .line 63
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    :cond_1
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 69
    .line 70
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    invoke-virtual {v0, v1, p1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 78
    .line 79
    return-void
.end method

.method public onViewRemoved(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->onViewRemoved(Landroid/view/View;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->remove(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayout;->getViewWidget(Landroid/view/View;)Lh5/d;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object v1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 18
    .line 19
    iget-object v1, v1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lh5/d;->D()V

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintHelpers:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    const/4 p1, 0x1

    .line 33
    iput-boolean p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 34
    .line 35
    return-void
.end method

.method public parseLayoutDescription(I)V
    .locals 2

    .line 1
    new-instance v0, Landroidx/constraintlayout/widget/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1, p0, p1}, Landroidx/constraintlayout/widget/h;-><init>(Landroid/content/Context;Landroidx/constraintlayout/widget/ConstraintLayout;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    .line 11
    .line 12
    return-void
.end method

.method public requestLayout()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDirtyHierarchy:Z

    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidth:I

    .line 6
    .line 7
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeight:I

    .line 8
    .line 9
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthSize:I

    .line 10
    .line 11
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightSize:I

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidthMode:I

    .line 15
    .line 16
    iput v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeightMode:I

    .line 17
    .line 18
    invoke-super {p0}, Landroid/view/View;->requestLayout()V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public resolveMeasuredDimension(IIIIZZ)V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 2
    .line 3
    iget v1, v0, Landroidx/constraintlayout/widget/e;->e:I

    .line 4
    .line 5
    iget v0, v0, Landroidx/constraintlayout/widget/e;->d:I

    .line 6
    .line 7
    add-int/2addr p3, v0

    .line 8
    add-int/2addr p4, v1

    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-static {p3, p1, v0}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    invoke-static {p4, p2, v0}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    const p3, 0xffffff

    .line 19
    .line 20
    .line 21
    and-int/2addr p1, p3

    .line 22
    and-int/2addr p2, p3

    .line 23
    iget p3, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 24
    .line 25
    invoke-static {p3, p1}, Ljava/lang/Math;->min(II)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    iget p3, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 30
    .line 31
    invoke-static {p3, p2}, Ljava/lang/Math;->min(II)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    const/high16 p3, 0x1000000

    .line 36
    .line 37
    if-eqz p5, :cond_0

    .line 38
    .line 39
    or-int/2addr p1, p3

    .line 40
    :cond_0
    if-eqz p6, :cond_1

    .line 41
    .line 42
    or-int/2addr p2, p3

    .line 43
    :cond_1
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 44
    .line 45
    .line 46
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureWidth:I

    .line 47
    .line 48
    iput p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLastMeasureHeight:I

    .line 49
    .line 50
    return-void
.end method

.method public resolveSystem(Lh5/e;III)V
    .locals 10

    .line 1
    invoke-static {p3}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 2
    .line 3
    .line 4
    move-result v2

    .line 5
    invoke-static {p3}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-static {p4}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 10
    .line 11
    .line 12
    move-result v4

    .line 13
    invoke-static {p4}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v5, 0x0

    .line 22
    invoke-static {v5, v3}, Ljava/lang/Math;->max(II)I

    .line 23
    .line 24
    .line 25
    move-result v7

    .line 26
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    invoke-static {v5, v3}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    add-int v6, v7, v3

    .line 35
    .line 36
    invoke-direct {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->getPaddingWidth()I

    .line 37
    .line 38
    .line 39
    move-result v8

    .line 40
    iget-object v9, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 41
    .line 42
    iput v7, v9, Landroidx/constraintlayout/widget/e;->b:I

    .line 43
    .line 44
    iput v3, v9, Landroidx/constraintlayout/widget/e;->c:I

    .line 45
    .line 46
    iput v8, v9, Landroidx/constraintlayout/widget/e;->d:I

    .line 47
    .line 48
    iput v6, v9, Landroidx/constraintlayout/widget/e;->e:I

    .line 49
    .line 50
    iput p3, v9, Landroidx/constraintlayout/widget/e;->f:I

    .line 51
    .line 52
    iput p4, v9, Landroidx/constraintlayout/widget/e;->g:I

    .line 53
    .line 54
    invoke-virtual {p0}, Landroid/view/View;->getPaddingStart()I

    .line 55
    .line 56
    .line 57
    move-result p3

    .line 58
    invoke-static {v5, p3}, Ljava/lang/Math;->max(II)I

    .line 59
    .line 60
    .line 61
    move-result p3

    .line 62
    invoke-virtual {p0}, Landroid/view/View;->getPaddingEnd()I

    .line 63
    .line 64
    .line 65
    move-result p4

    .line 66
    invoke-static {v5, p4}, Ljava/lang/Math;->max(II)I

    .line 67
    .line 68
    .line 69
    move-result p4

    .line 70
    if-gtz p3, :cond_1

    .line 71
    .line 72
    if-lez p4, :cond_0

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    invoke-static {v5, p3}, Ljava/lang/Math;->max(II)I

    .line 80
    .line 81
    .line 82
    move-result p3

    .line 83
    goto :goto_1

    .line 84
    :cond_1
    :goto_0
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->isRtl()Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-eqz v3, :cond_2

    .line 89
    .line 90
    move p3, p4

    .line 91
    :cond_2
    :goto_1
    sub-int v3, v0, v8

    .line 92
    .line 93
    sub-int v5, v1, v6

    .line 94
    .line 95
    move-object v0, p0

    .line 96
    move-object v1, p1

    .line 97
    invoke-virtual/range {v0 .. v5}, Landroidx/constraintlayout/widget/ConstraintLayout;->setSelfDimensionBehaviour(Lh5/e;IIII)V

    .line 98
    .line 99
    .line 100
    move v6, p3

    .line 101
    move-object v0, v1

    .line 102
    move v1, p2

    .line 103
    invoke-virtual/range {v0 .. v7}, Lh5/e;->a0(IIIIIII)V

    .line 104
    .line 105
    .line 106
    return-void
.end method

.method public setConstraintSet(Landroidx/constraintlayout/widget/o;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintSet:Landroidx/constraintlayout/widget/o;

    .line 2
    .line 3
    return-void
.end method

.method public setDesignInformation(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    if-nez p1, :cond_2

    .line 2
    .line 3
    instance-of p1, p2, Ljava/lang/String;

    .line 4
    .line 5
    if-eqz p1, :cond_2

    .line 6
    .line 7
    instance-of p1, p3, Ljava/lang/Integer;

    .line 8
    .line 9
    if-eqz p1, :cond_2

    .line 10
    .line 11
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 12
    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    new-instance p1, Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 21
    .line 22
    :cond_0
    check-cast p2, Ljava/lang/String;

    .line 23
    .line 24
    const-string p1, "/"

    .line 25
    .line 26
    invoke-virtual {p2, p1}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    const/4 v0, -0x1

    .line 31
    if-eq p1, v0, :cond_1

    .line 32
    .line 33
    add-int/lit8 p1, p1, 0x1

    .line 34
    .line 35
    invoke-virtual {p2, p1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    :cond_1
    check-cast p3, Ljava/lang/Integer;

    .line 40
    .line 41
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mDesignIds:Ljava/util/HashMap;

    .line 42
    .line 43
    invoke-virtual {p0, p2, p3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    :cond_2
    return-void
.end method

.method public setId(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getId()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->remove(I)V

    .line 8
    .line 9
    .line 10
    invoke-super {p0, p1}, Landroid/view/View;->setId(I)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mChildrenByIds:Landroid/util/SparseArray;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/view/View;->getId()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p1, v0, p0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public setMaxHeight(I)V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setMaxWidth(I)V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setMinHeight(I)V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setMinWidth(I)V
    .locals 1

    .line 1
    iget v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setOnConstraintsChanged(Landroidx/constraintlayout/widget/p;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public setOptimizationLevel(I)V
    .locals 0

    .line 1
    iput p1, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mOptimizationLevel:I

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mLayoutWidget:Lh5/e;

    .line 4
    .line 5
    iput p1, p0, Lh5/e;->E0:I

    .line 6
    .line 7
    const/16 p1, 0x200

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lh5/e;->c0(I)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    sput-boolean p0, La5/c;->q:Z

    .line 14
    .line 15
    return-void
.end method

.method public setSelfDimensionBehaviour(Lh5/e;IIII)V
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMeasurer:Landroidx/constraintlayout/widget/e;

    .line 2
    .line 3
    iget v1, v0, Landroidx/constraintlayout/widget/e;->e:I

    .line 4
    .line 5
    iget v0, v0, Landroidx/constraintlayout/widget/e;->d:I

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/high16 v3, 0x40000000    # 2.0f

    .line 12
    .line 13
    const/4 v4, 0x2

    .line 14
    const/4 v5, 0x1

    .line 15
    const/4 v6, 0x0

    .line 16
    const/high16 v7, -0x80000000

    .line 17
    .line 18
    if-eq p2, v7, :cond_4

    .line 19
    .line 20
    if-eqz p2, :cond_1

    .line 21
    .line 22
    if-eq p2, v3, :cond_0

    .line 23
    .line 24
    move p2, v5

    .line 25
    :goto_0
    move p3, v6

    .line 26
    goto :goto_2

    .line 27
    :cond_0
    iget p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 28
    .line 29
    sub-int/2addr p2, v0

    .line 30
    invoke-static {p2, p3}, Ljava/lang/Math;->min(II)I

    .line 31
    .line 32
    .line 33
    move-result p3

    .line 34
    move p2, v5

    .line 35
    goto :goto_2

    .line 36
    :cond_1
    if-nez v2, :cond_3

    .line 37
    .line 38
    iget p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 39
    .line 40
    invoke-static {v6, p2}, Ljava/lang/Math;->max(II)I

    .line 41
    .line 42
    .line 43
    move-result p3

    .line 44
    :cond_2
    :goto_1
    move p2, v4

    .line 45
    goto :goto_2

    .line 46
    :cond_3
    move p2, v4

    .line 47
    goto :goto_0

    .line 48
    :cond_4
    if-nez v2, :cond_2

    .line 49
    .line 50
    iget p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 51
    .line 52
    invoke-static {v6, p2}, Ljava/lang/Math;->max(II)I

    .line 53
    .line 54
    .line 55
    move-result p3

    .line 56
    goto :goto_1

    .line 57
    :goto_2
    if-eq p4, v7, :cond_8

    .line 58
    .line 59
    if-eqz p4, :cond_7

    .line 60
    .line 61
    if-eq p4, v3, :cond_6

    .line 62
    .line 63
    move v4, v5

    .line 64
    :cond_5
    move p5, v6

    .line 65
    goto :goto_3

    .line 66
    :cond_6
    iget p4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 67
    .line 68
    sub-int/2addr p4, v1

    .line 69
    invoke-static {p4, p5}, Ljava/lang/Math;->min(II)I

    .line 70
    .line 71
    .line 72
    move-result p5

    .line 73
    move v4, v5

    .line 74
    goto :goto_3

    .line 75
    :cond_7
    if-nez v2, :cond_5

    .line 76
    .line 77
    iget p4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 78
    .line 79
    invoke-static {v6, p4}, Ljava/lang/Math;->max(II)I

    .line 80
    .line 81
    .line 82
    move-result p5

    .line 83
    goto :goto_3

    .line 84
    :cond_8
    if-nez v2, :cond_9

    .line 85
    .line 86
    iget p4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 87
    .line 88
    invoke-static {v6, p4}, Ljava/lang/Math;->max(II)I

    .line 89
    .line 90
    .line 91
    move-result p5

    .line 92
    :cond_9
    :goto_3
    invoke-virtual {p1}, Lh5/d;->r()I

    .line 93
    .line 94
    .line 95
    move-result p4

    .line 96
    if-ne p3, p4, :cond_a

    .line 97
    .line 98
    invoke-virtual {p1}, Lh5/d;->l()I

    .line 99
    .line 100
    .line 101
    move-result p4

    .line 102
    if-eq p5, p4, :cond_b

    .line 103
    .line 104
    :cond_a
    iget-object p4, p1, Lh5/e;->t0:Li5/f;

    .line 105
    .line 106
    iput-boolean v5, p4, Li5/f;->c:Z

    .line 107
    .line 108
    :cond_b
    iput v6, p1, Lh5/d;->Z:I

    .line 109
    .line 110
    iput v6, p1, Lh5/d;->a0:I

    .line 111
    .line 112
    iget p4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxWidth:I

    .line 113
    .line 114
    sub-int/2addr p4, v0

    .line 115
    iget-object v2, p1, Lh5/d;->D:[I

    .line 116
    .line 117
    aput p4, v2, v6

    .line 118
    .line 119
    iget p4, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMaxHeight:I

    .line 120
    .line 121
    sub-int/2addr p4, v1

    .line 122
    aput p4, v2, v5

    .line 123
    .line 124
    iput v6, p1, Lh5/d;->c0:I

    .line 125
    .line 126
    iput v6, p1, Lh5/d;->d0:I

    .line 127
    .line 128
    invoke-virtual {p1, p2}, Lh5/d;->O(I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1, p3}, Lh5/d;->S(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1, v4}, Lh5/d;->Q(I)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {p1, p5}, Lh5/d;->N(I)V

    .line 138
    .line 139
    .line 140
    iget p2, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinWidth:I

    .line 141
    .line 142
    sub-int/2addr p2, v0

    .line 143
    if-gez p2, :cond_c

    .line 144
    .line 145
    iput v6, p1, Lh5/d;->c0:I

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_c
    iput p2, p1, Lh5/d;->c0:I

    .line 149
    .line 150
    :goto_4
    iget p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mMinHeight:I

    .line 151
    .line 152
    sub-int/2addr p0, v1

    .line 153
    if-gez p0, :cond_d

    .line 154
    .line 155
    iput v6, p1, Lh5/d;->d0:I

    .line 156
    .line 157
    return-void

    .line 158
    :cond_d
    iput p0, p1, Lh5/d;->d0:I

    .line 159
    .line 160
    return-void
.end method

.method public setState(III)V
    .locals 7

    .line 1
    iget-object p0, p0, Landroidx/constraintlayout/widget/ConstraintLayout;->mConstraintLayoutSpec:Landroidx/constraintlayout/widget/h;

    .line 2
    .line 3
    if-eqz p0, :cond_e

    .line 4
    .line 5
    int-to-float p2, p2

    .line 6
    int-to-float p3, p3

    .line 7
    iget-object v0, p0, Landroidx/constraintlayout/widget/h;->a:Landroidx/constraintlayout/widget/ConstraintLayout;

    .line 8
    .line 9
    iget-object v1, p0, Landroidx/constraintlayout/widget/h;->d:Landroid/util/SparseArray;

    .line 10
    .line 11
    iget v2, p0, Landroidx/constraintlayout/widget/h;->b:I

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, -0x1

    .line 16
    if-ne v2, p1, :cond_8

    .line 17
    .line 18
    if-ne p1, v5, :cond_0

    .line 19
    .line 20
    invoke-virtual {v1, v4}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Landroidx/constraintlayout/widget/f;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {v1, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    check-cast p1, Landroidx/constraintlayout/widget/f;

    .line 32
    .line 33
    :goto_0
    iget v1, p0, Landroidx/constraintlayout/widget/h;->c:I

    .line 34
    .line 35
    if-eq v1, v5, :cond_1

    .line 36
    .line 37
    iget-object v2, p1, Landroidx/constraintlayout/widget/f;->b:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Landroidx/constraintlayout/widget/g;

    .line 44
    .line 45
    invoke-virtual {v1, p2, p3}, Landroidx/constraintlayout/widget/g;->a(FF)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_1

    .line 50
    .line 51
    goto/16 :goto_9

    .line 52
    .line 53
    :cond_1
    iget-object v1, p1, Landroidx/constraintlayout/widget/f;->b:Ljava/util/ArrayList;

    .line 54
    .line 55
    :goto_1
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-ge v4, v2, :cond_3

    .line 60
    .line 61
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    check-cast v2, Landroidx/constraintlayout/widget/g;

    .line 66
    .line 67
    invoke-virtual {v2, p2, p3}, Landroidx/constraintlayout/widget/g;->a(FF)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_2

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_2
    add-int/lit8 v4, v4, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_3
    move v4, v5

    .line 78
    :goto_2
    iget-object p1, p1, Landroidx/constraintlayout/widget/f;->b:Ljava/util/ArrayList;

    .line 79
    .line 80
    iget p2, p0, Landroidx/constraintlayout/widget/h;->c:I

    .line 81
    .line 82
    if-ne p2, v4, :cond_4

    .line 83
    .line 84
    goto/16 :goto_9

    .line 85
    .line 86
    :cond_4
    if-ne v4, v5, :cond_5

    .line 87
    .line 88
    move-object p2, v3

    .line 89
    goto :goto_3

    .line 90
    :cond_5
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    check-cast p2, Landroidx/constraintlayout/widget/g;

    .line 95
    .line 96
    iget-object p2, p2, Landroidx/constraintlayout/widget/g;->f:Landroidx/constraintlayout/widget/o;

    .line 97
    .line 98
    :goto_3
    if-ne v4, v5, :cond_6

    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_6
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    check-cast p1, Landroidx/constraintlayout/widget/g;

    .line 106
    .line 107
    iget p1, p1, Landroidx/constraintlayout/widget/g;->e:I

    .line 108
    .line 109
    :goto_4
    if-nez p2, :cond_7

    .line 110
    .line 111
    goto/16 :goto_9

    .line 112
    .line 113
    :cond_7
    iput v4, p0, Landroidx/constraintlayout/widget/h;->c:I

    .line 114
    .line 115
    invoke-virtual {p2, v0}, Landroidx/constraintlayout/widget/o;->a(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, v3}, Landroidx/constraintlayout/widget/ConstraintLayout;->setConstraintSet(Landroidx/constraintlayout/widget/o;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_8
    iput p1, p0, Landroidx/constraintlayout/widget/h;->b:I

    .line 126
    .line 127
    invoke-virtual {v1, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    check-cast v1, Landroidx/constraintlayout/widget/f;

    .line 132
    .line 133
    iget-object v2, v1, Landroidx/constraintlayout/widget/f;->b:Ljava/util/ArrayList;

    .line 134
    .line 135
    :goto_5
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    if-ge v4, v6, :cond_a

    .line 140
    .line 141
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v6

    .line 145
    check-cast v6, Landroidx/constraintlayout/widget/g;

    .line 146
    .line 147
    invoke-virtual {v6, p2, p3}, Landroidx/constraintlayout/widget/g;->a(FF)Z

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    if-eqz v6, :cond_9

    .line 152
    .line 153
    goto :goto_6

    .line 154
    :cond_9
    add-int/lit8 v4, v4, 0x1

    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_a
    move v4, v5

    .line 158
    :goto_6
    iget-object v2, v1, Landroidx/constraintlayout/widget/f;->b:Ljava/util/ArrayList;

    .line 159
    .line 160
    if-ne v4, v5, :cond_b

    .line 161
    .line 162
    iget-object v1, v1, Landroidx/constraintlayout/widget/f;->d:Landroidx/constraintlayout/widget/o;

    .line 163
    .line 164
    goto :goto_7

    .line 165
    :cond_b
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v1

    .line 169
    check-cast v1, Landroidx/constraintlayout/widget/g;

    .line 170
    .line 171
    iget-object v1, v1, Landroidx/constraintlayout/widget/g;->f:Landroidx/constraintlayout/widget/o;

    .line 172
    .line 173
    :goto_7
    if-ne v4, v5, :cond_c

    .line 174
    .line 175
    goto :goto_8

    .line 176
    :cond_c
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    check-cast v2, Landroidx/constraintlayout/widget/g;

    .line 181
    .line 182
    iget v2, v2, Landroidx/constraintlayout/widget/g;->e:I

    .line 183
    .line 184
    :goto_8
    if-nez v1, :cond_d

    .line 185
    .line 186
    new-instance p0, Ljava/lang/StringBuilder;

    .line 187
    .line 188
    const-string v0, "NO Constraint set found ! id="

    .line 189
    .line 190
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    const-string p1, ", dim ="

    .line 197
    .line 198
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    const-string p1, ", "

    .line 205
    .line 206
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 210
    .line 211
    .line 212
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    const-string p1, "ConstraintLayoutStates"

    .line 217
    .line 218
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 219
    .line 220
    .line 221
    return-void

    .line 222
    :cond_d
    iput v4, p0, Landroidx/constraintlayout/widget/h;->c:I

    .line 223
    .line 224
    invoke-virtual {v1, v0}, Landroidx/constraintlayout/widget/o;->a(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v0, v3}, Landroidx/constraintlayout/widget/ConstraintLayout;->setConstraintSet(Landroidx/constraintlayout/widget/o;)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v0}, Landroidx/constraintlayout/widget/ConstraintLayout;->requestLayout()V

    .line 231
    .line 232
    .line 233
    :cond_e
    :goto_9
    return-void
.end method

.method public shouldDelayChildPressedState()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
