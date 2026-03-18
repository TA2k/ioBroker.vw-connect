.class public Landroidx/coordinatorlayout/widget/CoordinatorLayout;
.super Landroid/view/ViewGroup;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/q;
.implements Ld6/r;


# static fields
.field public static final A:Lc6/c;

.field public static final w:Ljava/lang/String;

.field public static final x:[Ljava/lang/Class;

.field public static final y:Ljava/lang/ThreadLocal;

.field public static final z:La5/f;


# instance fields
.field public final d:Ljava/util/ArrayList;

.field public final e:Lcom/google/firebase/messaging/w;

.field public final f:Ljava/util/ArrayList;

.field public final g:Ljava/util/ArrayList;

.field public final h:[I

.field public final i:[I

.field public j:Z

.field public k:Z

.field public final l:[I

.field public m:Landroid/view/View;

.field public n:Landroid/view/View;

.field public o:Ll5/d;

.field public p:Z

.field public q:Ld6/w1;

.field public r:Z

.field public s:Landroid/graphics/drawable/Drawable;

.field public t:Landroid/view/ViewGroup$OnHierarchyChangeListener;

.field public u:Lh6/e;

.field public final v:Lb8/i;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getPackage()Ljava/lang/Package;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Package;->getName()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    :goto_0
    sput-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->w:Ljava/lang/String;

    .line 16
    .line 17
    new-instance v0, La5/f;

    .line 18
    .line 19
    const/16 v1, 0x15

    .line 20
    .line 21
    invoke-direct {v0, v1}, La5/f;-><init>(I)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->z:La5/f;

    .line 25
    .line 26
    const-class v0, Landroid/content/Context;

    .line 27
    .line 28
    const-class v1, Landroid/util/AttributeSet;

    .line 29
    .line 30
    filled-new-array {v0, v1}, [Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    sput-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->x:[Ljava/lang/Class;

    .line 35
    .line 36
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 37
    .line 38
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 39
    .line 40
    .line 41
    sput-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->y:Ljava/lang/ThreadLocal;

    .line 42
    .line 43
    new-instance v0, Lc6/c;

    .line 44
    .line 45
    invoke-direct {v0}, Lc6/c;-><init>()V

    .line 46
    .line 47
    .line 48
    sput-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->A:Lc6/c;

    .line 49
    .line 50
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 9

    .line 1
    const v5, 0x7f040185

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p1, p2, v5}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d:Ljava/util/ArrayList;

    .line 13
    .line 14
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 15
    .line 16
    const/16 v1, 0x12

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->e:Lcom/google/firebase/messaging/w;

    .line 22
    .line 23
    new-instance v0, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->f:Ljava/util/ArrayList;

    .line 29
    .line 30
    new-instance v0, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->g:Ljava/util/ArrayList;

    .line 36
    .line 37
    const/4 v0, 0x2

    .line 38
    new-array v1, v0, [I

    .line 39
    .line 40
    iput-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->h:[I

    .line 41
    .line 42
    new-array v0, v0, [I

    .line 43
    .line 44
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->i:[I

    .line 45
    .line 46
    new-instance v0, Lb8/i;

    .line 47
    .line 48
    const/4 v7, 0x1

    .line 49
    invoke-direct {v0, v7}, Lb8/i;-><init>(I)V

    .line 50
    .line 51
    .line 52
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v:Lb8/i;

    .line 53
    .line 54
    sget-object v2, Lk5/a;->a:[I

    .line 55
    .line 56
    const/4 v8, 0x0

    .line 57
    invoke-virtual {p1, p2, v2, v5, v8}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    const/4 v6, 0x0

    .line 62
    move-object v0, p0

    .line 63
    move-object v1, p1

    .line 64
    move-object v3, p2

    .line 65
    invoke-virtual/range {v0 .. v6}, Landroid/view/View;->saveAttributeDataForStyleable(Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v4, v8, v8}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_0

    .line 73
    .line 74
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getIntArray(I)[I

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    iput-object p0, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->l:[I

    .line 83
    .line 84
    invoke-virtual {p1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    iget p1, p1, Landroid/util/DisplayMetrics;->density:F

    .line 89
    .line 90
    array-length p0, p0

    .line 91
    :goto_0
    if-ge v8, p0, :cond_0

    .line 92
    .line 93
    iget-object p2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->l:[I

    .line 94
    .line 95
    aget v1, p2, v8

    .line 96
    .line 97
    int-to-float v1, v1

    .line 98
    mul-float/2addr v1, p1

    .line 99
    float-to-int v1, v1

    .line 100
    aput v1, p2, v8

    .line 101
    .line 102
    add-int/lit8 v8, v8, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_0
    invoke-virtual {v4, v7}, Landroid/content/res/TypedArray;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    iput-object p0, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 110
    .line 111
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->w()V

    .line 115
    .line 116
    .line 117
    new-instance p0, La6/d;

    .line 118
    .line 119
    invoke-direct {p0, v0}, La6/d;-><init>(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)V

    .line 120
    .line 121
    .line 122
    invoke-super {v0, p0}, Landroid/view/ViewGroup;->setOnHierarchyChangeListener(Landroid/view/ViewGroup$OnHierarchyChangeListener;)V

    .line 123
    .line 124
    .line 125
    sget-object p0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 126
    .line 127
    invoke-virtual {v0}, Landroid/view/View;->getImportantForAccessibility()I

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-nez p0, :cond_1

    .line 132
    .line 133
    invoke-virtual {v0, v7}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 134
    .line 135
    .line 136
    :cond_1
    return-void
.end method

.method public static a()Landroid/graphics/Rect;
    .locals 1

    .line 1
    sget-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->A:Lc6/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lc6/c;->a()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/graphics/Rect;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v0, Landroid/graphics/Rect;

    .line 12
    .line 13
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-object v0
.end method

.method public static l(ILandroid/graphics/Rect;Landroid/graphics/Rect;Ll5/c;II)V
    .locals 6

    .line 1
    iget v0, p3, Ll5/c;->c:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/16 v0, 0x11

    .line 6
    .line 7
    :cond_0
    invoke-static {v0, p0}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget p3, p3, Ll5/c;->d:I

    .line 12
    .line 13
    and-int/lit8 v1, p3, 0x7

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    const v1, 0x800003

    .line 18
    .line 19
    .line 20
    or-int/2addr p3, v1

    .line 21
    :cond_1
    and-int/lit8 v1, p3, 0x70

    .line 22
    .line 23
    if-nez v1, :cond_2

    .line 24
    .line 25
    or-int/lit8 p3, p3, 0x30

    .line 26
    .line 27
    :cond_2
    invoke-static {p3, p0}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    and-int/lit8 p3, v0, 0x7

    .line 32
    .line 33
    and-int/lit8 v0, v0, 0x70

    .line 34
    .line 35
    and-int/lit8 v1, p0, 0x7

    .line 36
    .line 37
    and-int/lit8 p0, p0, 0x70

    .line 38
    .line 39
    const/4 v2, 0x5

    .line 40
    const/4 v3, 0x1

    .line 41
    if-eq v1, v3, :cond_4

    .line 42
    .line 43
    if-eq v1, v2, :cond_3

    .line 44
    .line 45
    iget v1, p1, Landroid/graphics/Rect;->left:I

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    iget v1, p1, Landroid/graphics/Rect;->right:I

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_4
    iget v1, p1, Landroid/graphics/Rect;->left:I

    .line 52
    .line 53
    invoke-virtual {p1}, Landroid/graphics/Rect;->width()I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    div-int/lit8 v4, v4, 0x2

    .line 58
    .line 59
    add-int/2addr v1, v4

    .line 60
    :goto_0
    const/16 v4, 0x50

    .line 61
    .line 62
    const/16 v5, 0x10

    .line 63
    .line 64
    if-eq p0, v5, :cond_6

    .line 65
    .line 66
    if-eq p0, v4, :cond_5

    .line 67
    .line 68
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_5
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_6
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 75
    .line 76
    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    div-int/lit8 p1, p1, 0x2

    .line 81
    .line 82
    add-int/2addr p0, p1

    .line 83
    :goto_1
    if-eq p3, v3, :cond_7

    .line 84
    .line 85
    if-eq p3, v2, :cond_8

    .line 86
    .line 87
    sub-int/2addr v1, p4

    .line 88
    goto :goto_2

    .line 89
    :cond_7
    div-int/lit8 p1, p4, 0x2

    .line 90
    .line 91
    sub-int/2addr v1, p1

    .line 92
    :cond_8
    :goto_2
    if-eq v0, v5, :cond_9

    .line 93
    .line 94
    if-eq v0, v4, :cond_a

    .line 95
    .line 96
    sub-int/2addr p0, p5

    .line 97
    goto :goto_3

    .line 98
    :cond_9
    div-int/lit8 p1, p5, 0x2

    .line 99
    .line 100
    sub-int/2addr p0, p1

    .line 101
    :cond_a
    :goto_3
    add-int/2addr p4, v1

    .line 102
    add-int/2addr p5, p0

    .line 103
    invoke-virtual {p2, v1, p0, p4, p5}, Landroid/graphics/Rect;->set(IIII)V

    .line 104
    .line 105
    .line 106
    return-void
.end method

.method public static n(Landroid/view/View;)Ll5/c;
    .locals 5

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ll5/c;

    .line 6
    .line 7
    iget-boolean v1, v0, Ll5/c;->b:Z

    .line 8
    .line 9
    if-nez v1, :cond_3

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const/4 v1, 0x0

    .line 16
    move-object v2, v1

    .line 17
    :goto_0
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const-class v2, Ll5/b;

    .line 20
    .line 21
    invoke-virtual {p0, v2}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Ll5/b;

    .line 26
    .line 27
    if-nez v2, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p0, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    :try_start_0
    invoke-interface {v2}, Ll5/b;->value()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-virtual {v3, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-virtual {v3, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    check-cast v1, Ll5/a;

    .line 50
    .line 51
    iget-object v3, v0, Ll5/c;->a:Ll5/a;

    .line 52
    .line 53
    if-eq v3, v1, :cond_2

    .line 54
    .line 55
    if-eqz v3, :cond_1

    .line 56
    .line 57
    invoke-virtual {v3}, Ll5/a;->e()V

    .line 58
    .line 59
    .line 60
    :cond_1
    iput-object v1, v0, Ll5/c;->a:Ll5/a;

    .line 61
    .line 62
    iput-boolean p0, v0, Ll5/c;->b:Z

    .line 63
    .line 64
    if-eqz v1, :cond_2

    .line 65
    .line 66
    invoke-virtual {v1, v0}, Ll5/a;->c(Ll5/c;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :catch_0
    move-exception v1

    .line 71
    new-instance v3, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v4, "Default behavior class "

    .line 74
    .line 75
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-interface {v2}, Ll5/b;->value()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v2, " could not be instantiated. Did you forget a default constructor?"

    .line 90
    .line 91
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    const-string v3, "CoordinatorLayout"

    .line 99
    .line 100
    invoke-static {v3, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 101
    .line 102
    .line 103
    :cond_2
    :goto_1
    iput-boolean p0, v0, Ll5/c;->b:Z

    .line 104
    .line 105
    :cond_3
    return-object v0
.end method

.method public static u(Landroid/view/View;I)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ll5/c;

    .line 6
    .line 7
    iget v1, v0, Ll5/c;->i:I

    .line 8
    .line 9
    if-eq v1, p1, :cond_0

    .line 10
    .line 11
    sub-int v1, p1, v1

    .line 12
    .line 13
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 16
    .line 17
    .line 18
    iput p1, v0, Ll5/c;->i:I

    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public static v(Landroid/view/View;I)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ll5/c;

    .line 6
    .line 7
    iget v1, v0, Ll5/c;->j:I

    .line 8
    .line 9
    if-eq v1, p1, :cond_0

    .line 10
    .line 11
    sub-int v1, p1, v1

    .line 12
    .line 13
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Landroid/view/View;->offsetTopAndBottom(I)V

    .line 16
    .line 17
    .line 18
    iput p1, v0, Ll5/c;->j:I

    .line 19
    .line 20
    :cond_0
    return-void
.end method


# virtual methods
.method public final b(Landroid/view/View;Landroid/view/View;II)V
    .locals 1

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v:Lb8/i;

    .line 3
    .line 4
    if-ne p4, p1, :cond_0

    .line 5
    .line 6
    iput p3, v0, Lb8/i;->c:I

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iput p3, v0, Lb8/i;->b:I

    .line 10
    .line 11
    :goto_0
    iput-object p2, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->n:Landroid/view/View;

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    const/4 p2, 0x0

    .line 18
    :goto_1
    if-ge p2, p1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, p2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 21
    .line 22
    .line 23
    move-result-object p3

    .line 24
    invoke-virtual {p3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    check-cast p3, Ll5/c;

    .line 29
    .line 30
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    add-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    return-void
.end method

.method public final c(Landroid/view/View;I)V
    .locals 7

    .line 1
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v:Lb8/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne p2, v2, :cond_0

    .line 6
    .line 7
    iput v1, v0, Lb8/i;->c:I

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iput v1, v0, Lb8/i;->b:I

    .line 11
    .line 12
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    move v3, v1

    .line 17
    :goto_1
    if-ge v3, v0, :cond_5

    .line 18
    .line 19
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    check-cast v5, Ll5/c;

    .line 28
    .line 29
    invoke-virtual {v5, p2}, Ll5/c;->a(I)Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-nez v6, :cond_1

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_1
    iget-object v6, v5, Ll5/c;->a:Ll5/a;

    .line 37
    .line 38
    if-eqz v6, :cond_2

    .line 39
    .line 40
    invoke-virtual {v6, v4, p1, p2}, Ll5/a;->p(Landroid/view/View;Landroid/view/View;I)V

    .line 41
    .line 42
    .line 43
    :cond_2
    if-eqz p2, :cond_4

    .line 44
    .line 45
    if-eq p2, v2, :cond_3

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_3
    iput-boolean v1, v5, Ll5/c;->n:Z

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_4
    iput-boolean v1, v5, Ll5/c;->m:Z

    .line 52
    .line 53
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_5
    const/4 p1, 0x0

    .line 57
    iput-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->n:Landroid/view/View;

    .line 58
    .line 59
    return-void
.end method

.method public final checkLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ll5/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->checkLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final d(Landroid/view/View;II[II)V
    .locals 14

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v8

    .line 5
    const/4 v9, 0x0

    .line 6
    move v0, v9

    .line 7
    move v10, v0

    .line 8
    move v11, v10

    .line 9
    move v12, v11

    .line 10
    :goto_0
    const/4 v13, 0x1

    .line 11
    if-ge v10, v8, :cond_5

    .line 12
    .line 13
    invoke-virtual {p0, v10}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/16 v4, 0x8

    .line 22
    .line 23
    if-ne v3, v4, :cond_0

    .line 24
    .line 25
    goto :goto_5

    .line 26
    :cond_0
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    check-cast v3, Ll5/c;

    .line 31
    .line 32
    move/from16 v7, p5

    .line 33
    .line 34
    invoke-virtual {v3, v7}, Ll5/c;->a(I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-nez v4, :cond_1

    .line 39
    .line 40
    goto :goto_5

    .line 41
    :cond_1
    iget-object v3, v3, Ll5/c;->a:Ll5/a;

    .line 42
    .line 43
    if-eqz v3, :cond_4

    .line 44
    .line 45
    iget-object v6, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->h:[I

    .line 46
    .line 47
    aput v9, v6, v9

    .line 48
    .line 49
    aput v9, v6, v13

    .line 50
    .line 51
    move-object v1, p0

    .line 52
    move/from16 v4, p2

    .line 53
    .line 54
    move/from16 v5, p3

    .line 55
    .line 56
    move-object v0, v3

    .line 57
    move-object v3, p1

    .line 58
    invoke-virtual/range {v0 .. v7}, Ll5/a;->j(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/view/View;II[II)V

    .line 59
    .line 60
    .line 61
    if-lez p2, :cond_2

    .line 62
    .line 63
    aget v0, v6, v9

    .line 64
    .line 65
    invoke-static {v11, v0}, Ljava/lang/Math;->max(II)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    :goto_1
    move v11, v0

    .line 70
    goto :goto_2

    .line 71
    :cond_2
    aget v0, v6, v9

    .line 72
    .line 73
    invoke-static {v11, v0}, Ljava/lang/Math;->min(II)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    goto :goto_1

    .line 78
    :goto_2
    if-lez p3, :cond_3

    .line 79
    .line 80
    aget v0, v6, v13

    .line 81
    .line 82
    invoke-static {v12, v0}, Ljava/lang/Math;->max(II)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    :goto_3
    move v12, v0

    .line 87
    goto :goto_4

    .line 88
    :cond_3
    aget v0, v6, v13

    .line 89
    .line 90
    invoke-static {v12, v0}, Ljava/lang/Math;->min(II)I

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    goto :goto_3

    .line 95
    :goto_4
    move v0, v13

    .line 96
    :cond_4
    :goto_5
    add-int/lit8 v10, v10, 0x1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_5
    aput v11, p4, v9

    .line 100
    .line 101
    aput v12, p4, v13

    .line 102
    .line 103
    if-eqz v0, :cond_6

    .line 104
    .line 105
    invoke-virtual {p0, v13}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p(I)V

    .line 106
    .line 107
    .line 108
    :cond_6
    return-void
.end method

.method public final drawChild(Landroid/graphics/Canvas;Landroid/view/View;J)Z
    .locals 1

    .line 1
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ll5/c;

    .line 6
    .line 7
    iget-object v0, v0, Ll5/c;->a:Ll5/a;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-super {p0, p1, p2, p3, p4}, Landroid/view/ViewGroup;->drawChild(Landroid/graphics/Canvas;Landroid/view/View;J)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public final drawableStateChanged()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->drawableStateChanged()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->getDrawableState()[I

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    invoke-virtual {v1}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {v1, v0}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x0

    .line 24
    :goto_0
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public final e(Ll5/c;Landroid/graphics/Rect;II)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    iget v3, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 14
    .line 15
    add-int/2addr v2, v3

    .line 16
    iget v3, p2, Landroid/graphics/Rect;->left:I

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    sub-int/2addr v0, v4

    .line 23
    sub-int/2addr v0, p3

    .line 24
    iget v4, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 25
    .line 26
    sub-int/2addr v0, v4

    .line 27
    invoke-static {v3, v0}, Ljava/lang/Math;->min(II)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-static {v2, v0}, Ljava/lang/Math;->max(II)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    iget v3, p1, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 40
    .line 41
    add-int/2addr v2, v3

    .line 42
    iget v3, p2, Landroid/graphics/Rect;->top:I

    .line 43
    .line 44
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    sub-int/2addr v1, p0

    .line 49
    sub-int/2addr v1, p4

    .line 50
    iget p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 51
    .line 52
    sub-int/2addr v1, p0

    .line 53
    invoke-static {v3, v1}, Ljava/lang/Math;->min(II)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-static {v2, p0}, Ljava/lang/Math;->max(II)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    add-int/2addr p3, v0

    .line 62
    add-int/2addr p4, p0

    .line 63
    invoke-virtual {p2, v0, p0, p3, p4}, Landroid/graphics/Rect;->set(IIII)V

    .line 64
    .line 65
    .line 66
    return-void
.end method

.method public final f(Landroid/view/View;Landroid/graphics/Rect;Z)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->isLayoutRequested()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_2

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getVisibility()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/16 v1, 0x8

    .line 12
    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    if-eqz p3, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, p1, p2}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 27
    .line 28
    .line 29
    move-result p3

    .line 30
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-virtual {p1}, Landroid/view/View;->getBottom()I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    invoke-virtual {p2, p0, p3, v0, p1}, Landroid/graphics/Rect;->set(IIII)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_2
    :goto_0
    invoke-virtual {p2}, Landroid/graphics/Rect;->setEmpty()V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final g(Landroid/view/View;IIIII[I)V
    .locals 14

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x0

    .line 6
    move v1, v0

    .line 7
    move v2, v1

    .line 8
    move v3, v2

    .line 9
    move v4, v3

    .line 10
    :goto_0
    const/4 v5, 0x1

    .line 11
    if-ge v1, p1, :cond_5

    .line 12
    .line 13
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v8

    .line 17
    invoke-virtual {v8}, Landroid/view/View;->getVisibility()I

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    const/16 v7, 0x8

    .line 22
    .line 23
    if-ne v6, v7, :cond_0

    .line 24
    .line 25
    move/from16 v13, p6

    .line 26
    .line 27
    goto :goto_3

    .line 28
    :cond_0
    invoke-virtual {v8}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    check-cast v6, Ll5/c;

    .line 33
    .line 34
    move/from16 v13, p6

    .line 35
    .line 36
    invoke-virtual {v6, v13}, Ll5/c;->a(I)Z

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    if-nez v7, :cond_1

    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    iget-object v6, v6, Ll5/c;->a:Ll5/a;

    .line 44
    .line 45
    if-eqz v6, :cond_4

    .line 46
    .line 47
    iget-object v12, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->h:[I

    .line 48
    .line 49
    aput v0, v12, v0

    .line 50
    .line 51
    aput v0, v12, v5

    .line 52
    .line 53
    move-object v7, p0

    .line 54
    move/from16 v9, p3

    .line 55
    .line 56
    move/from16 v10, p4

    .line 57
    .line 58
    move/from16 v11, p5

    .line 59
    .line 60
    invoke-virtual/range {v6 .. v12}, Ll5/a;->k(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;III[I)V

    .line 61
    .line 62
    .line 63
    if-lez p4, :cond_2

    .line 64
    .line 65
    aget v4, v12, v0

    .line 66
    .line 67
    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    goto :goto_1

    .line 72
    :cond_2
    aget v4, v12, v0

    .line 73
    .line 74
    invoke-static {v2, v4}, Ljava/lang/Math;->min(II)I

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    :goto_1
    if-lez p5, :cond_3

    .line 79
    .line 80
    aget v4, v12, v5

    .line 81
    .line 82
    invoke-static {v3, v4}, Ljava/lang/Math;->max(II)I

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    goto :goto_2

    .line 87
    :cond_3
    aget v4, v12, v5

    .line 88
    .line 89
    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    :goto_2
    move v4, v5

    .line 94
    :cond_4
    :goto_3
    add-int/lit8 v1, v1, 0x1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_5
    aget p1, p7, v0

    .line 98
    .line 99
    add-int/2addr p1, v2

    .line 100
    aput p1, p7, v0

    .line 101
    .line 102
    aget p1, p7, v5

    .line 103
    .line 104
    add-int/2addr p1, v3

    .line 105
    aput p1, p7, v5

    .line 106
    .line 107
    if-eqz v4, :cond_6

    .line 108
    .line 109
    invoke-virtual {p0, v5}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p(I)V

    .line 110
    .line 111
    .line 112
    :cond_6
    return-void
.end method

.method public final generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 1
    new-instance p0, Ll5/c;

    .line 2
    .line 3
    invoke-direct {p0}, Ll5/c;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final generateLayoutParams(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;
    .locals 1

    .line 1
    new-instance v0, Ll5/c;

    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p0

    invoke-direct {v0, p0, p1}, Ll5/c;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-object v0
.end method

.method public final generateLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 2
    instance-of p0, p1, Ll5/c;

    if-eqz p0, :cond_0

    .line 3
    new-instance p0, Ll5/c;

    check-cast p1, Ll5/c;

    invoke-direct {p0, p1}, Ll5/c;-><init>(Ll5/c;)V

    return-object p0

    .line 4
    :cond_0
    instance-of p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;

    if-eqz p0, :cond_1

    .line 5
    new-instance p0, Ll5/c;

    check-cast p1, Landroid/view/ViewGroup$MarginLayoutParams;

    invoke-direct {p0, p1}, Ll5/c;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    return-object p0

    .line 6
    :cond_1
    new-instance p0, Ll5/c;

    invoke-direct {p0, p1}, Ll5/c;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    return-object p0
.end method

.method public final getDependencySortedChildren()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroid/view/View;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final getLastWindowInsets()Ld6/w1;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 2
    .line 3
    return-object p0
.end method

.method public getNestedScrollAxes()I
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v:Lb8/i;

    .line 2
    .line 3
    iget v0, p0, Lb8/i;->b:I

    .line 4
    .line 5
    iget p0, p0, Lb8/i;->c:I

    .line 6
    .line 7
    or-int/2addr p0, v0

    .line 8
    return p0
.end method

.method public getStatusBarBackground()Landroid/graphics/drawable/Drawable;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSuggestedMinimumHeight()I
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/view/View;->getSuggestedMinimumHeight()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/2addr p0, v1

    .line 14
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getSuggestedMinimumWidth()I
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/view/View;->getSuggestedMinimumWidth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/2addr p0, v1

    .line 14
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public final h(Landroid/view/View;IIIII)V
    .locals 8

    .line 1
    const/4 v6, 0x0

    .line 2
    iget-object v7, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->i:[I

    .line 3
    .line 4
    move-object v0, p0

    .line 5
    move-object v1, p1

    .line 6
    move v2, p2

    .line 7
    move v3, p3

    .line 8
    move v4, p4

    .line 9
    move v5, p5

    .line 10
    invoke-virtual/range {v0 .. v7}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->g(Landroid/view/View;IIIII[I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final i(Landroid/view/View;Landroid/view/View;II)Z
    .locals 6

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 p2, 0x0

    .line 6
    move v0, p2

    .line 7
    move v1, v0

    .line 8
    :goto_0
    if-ge v0, p1, :cond_6

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/16 v4, 0x8

    .line 19
    .line 20
    if-ne v3, v4, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ll5/c;

    .line 28
    .line 29
    iget-object v4, v3, Ll5/c;->a:Ll5/a;

    .line 30
    .line 31
    const/4 v5, 0x1

    .line 32
    if-eqz v4, :cond_3

    .line 33
    .line 34
    invoke-virtual {v4, v2, p3, p4}, Ll5/a;->o(Landroid/view/View;II)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    or-int/2addr v1, v2

    .line 39
    if-eqz p4, :cond_2

    .line 40
    .line 41
    if-eq p4, v5, :cond_1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    iput-boolean v2, v3, Ll5/c;->n:Z

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    iput-boolean v2, v3, Ll5/c;->m:Z

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    if-eqz p4, :cond_5

    .line 51
    .line 52
    if-eq p4, v5, :cond_4

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_4
    iput-boolean p2, v3, Ll5/c;->n:Z

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_5
    iput-boolean p2, v3, Ll5/c;->m:Z

    .line 59
    .line 60
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_6
    return v1
.end method

.method public final j(Landroid/view/View;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->e:Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Landroidx/collection/a1;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroidx/collection/a1;->size()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    :goto_0
    if-ge v3, v1, :cond_2

    .line 14
    .line 15
    invoke-virtual {v0, v3}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    check-cast v4, Ljava/util/ArrayList;

    .line 20
    .line 21
    if-eqz v4, :cond_1

    .line 22
    .line 23
    invoke-virtual {v4, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_1

    .line 28
    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    new-instance v2, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 34
    .line 35
    .line 36
    :cond_0
    invoke-virtual {v0, v3}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->g:Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 49
    .line 50
    .line 51
    if-eqz v2, :cond_3

    .line 52
    .line 53
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 54
    .line 55
    .line 56
    :cond_3
    return-object p0
.end method

.method public final k(Landroid/view/View;Landroid/graphics/Rect;)V
    .locals 3

    .line 1
    sget-object v0, Ll5/f;->a:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {p2, v2, v2, v0, v1}, Landroid/graphics/Rect;->set(IIII)V

    .line 13
    .line 14
    .line 15
    sget-object v0, Ll5/f;->a:Ljava/lang/ThreadLocal;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Landroid/graphics/Matrix;

    .line 22
    .line 23
    if-nez v1, :cond_0

    .line 24
    .line 25
    new-instance v1, Landroid/graphics/Matrix;

    .line 26
    .line 27
    invoke-direct {v1}, Landroid/graphics/Matrix;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {v1}, Landroid/graphics/Matrix;->reset()V

    .line 35
    .line 36
    .line 37
    :goto_0
    invoke-static {p0, p1, v1}, Ll5/f;->a(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/graphics/Matrix;)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Ll5/f;->b:Ljava/lang/ThreadLocal;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    check-cast p1, Landroid/graphics/RectF;

    .line 47
    .line 48
    if-nez p1, :cond_1

    .line 49
    .line 50
    new-instance p1, Landroid/graphics/RectF;

    .line 51
    .line 52
    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    invoke-virtual {p1, p2}, Landroid/graphics/RectF;->set(Landroid/graphics/Rect;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, p1}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 62
    .line 63
    .line 64
    iget p0, p1, Landroid/graphics/RectF;->left:F

    .line 65
    .line 66
    const/high16 v0, 0x3f000000    # 0.5f

    .line 67
    .line 68
    add-float/2addr p0, v0

    .line 69
    float-to-int p0, p0

    .line 70
    iget v1, p1, Landroid/graphics/RectF;->top:F

    .line 71
    .line 72
    add-float/2addr v1, v0

    .line 73
    float-to-int v1, v1

    .line 74
    iget v2, p1, Landroid/graphics/RectF;->right:F

    .line 75
    .line 76
    add-float/2addr v2, v0

    .line 77
    float-to-int v2, v2

    .line 78
    iget p1, p1, Landroid/graphics/RectF;->bottom:F

    .line 79
    .line 80
    add-float/2addr p1, v0

    .line 81
    float-to-int p1, p1

    .line 82
    invoke-virtual {p2, p0, v1, v2, p1}, Landroid/graphics/Rect;->set(IIII)V

    .line 83
    .line 84
    .line 85
    return-void
.end method

.method public final m(I)I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    const-string v1, "CoordinatorLayout"

    .line 3
    .line 4
    iget-object v2, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->l:[I

    .line 5
    .line 6
    if-nez v2, :cond_0

    .line 7
    .line 8
    new-instance v2, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v3, "No keylines defined for "

    .line 11
    .line 12
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string p0, " - attempted index lookup "

    .line 19
    .line 20
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-static {v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    return v0

    .line 34
    :cond_0
    if-ltz p1, :cond_2

    .line 35
    .line 36
    array-length v3, v2

    .line 37
    if-lt p1, v3, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    aget p0, v2, p1

    .line 41
    .line 42
    return p0

    .line 43
    :cond_2
    :goto_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v3, "Keyline index "

    .line 46
    .line 47
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p1, " out of range for "

    .line 54
    .line 55
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-static {v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    return v0
.end method

.method public final o(Landroid/view/View;II)Z
    .locals 2

    .line 1
    sget-object v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->A:Lc6/c;

    .line 2
    .line 3
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0, p1, v1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    invoke-virtual {v1, p2, p3}, Landroid/graphics/Rect;->contains(II)Z

    .line 11
    .line 12
    .line 13
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    invoke-virtual {v1}, Landroid/graphics/Rect;->setEmpty()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    return p0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    invoke-virtual {v1}, Landroid/graphics/Rect;->setEmpty()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public final onAttachedToWindow()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-virtual {p0, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t(Z)V

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p:Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    new-instance v0, Ll5/d;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Ll5/d;-><init>(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->addOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 33
    .line 34
    if-nez v0, :cond_2

    .line 35
    .line 36
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 37
    .line 38
    invoke-virtual {p0}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    invoke-static {p0}, Ld6/i0;->c(Landroid/view/View;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    const/4 v0, 0x1

    .line 48
    iput-boolean v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k:Z

    .line 49
    .line 50
    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->onDetachedFromWindow()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-virtual {p0, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t(Z)V

    .line 6
    .line 7
    .line 8
    iget-boolean v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p:Z

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iget-object v2, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Landroid/view/ViewTreeObserver;->removeOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->n:Landroid/view/View;

    .line 26
    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, v1, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->c(Landroid/view/View;I)V

    .line 30
    .line 31
    .line 32
    :cond_1
    iput-boolean v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k:Z

    .line 33
    .line 34
    return-void
.end method

.method public final onDraw(Landroid/graphics/Canvas;)V
    .locals 4

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->onDraw(Landroid/graphics/Canvas;)V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->r:Z

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0}, Ld6/w1;->d()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    if-lez v0, :cond_1

    .line 24
    .line 25
    iget-object v2, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-virtual {v2, v1, v1, v3, v0}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    return-void
.end method

.method public final onInterceptTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t(Z)V

    .line 9
    .line 10
    .line 11
    :cond_0
    const/4 v2, 0x0

    .line 12
    invoke-virtual {p0, p1, v2}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->r(Landroid/view/MotionEvent;I)Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eq v0, v1, :cond_2

    .line 17
    .line 18
    const/4 v2, 0x3

    .line 19
    if-ne v0, v2, :cond_1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    return p1

    .line 23
    :cond_2
    :goto_0
    invoke-virtual {p0, v1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t(Z)V

    .line 24
    .line 25
    .line 26
    return p1
.end method

.method public final onLayout(ZIIII)V
    .locals 2

    .line 1
    sget-object p1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iget-object p2, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    const/4 p4, 0x0

    .line 14
    :goto_0
    if-ge p4, p3, :cond_3

    .line 15
    .line 16
    invoke-virtual {p2, p4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p5

    .line 20
    check-cast p5, Landroid/view/View;

    .line 21
    .line 22
    invoke-virtual {p5}, Landroid/view/View;->getVisibility()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/16 v1, 0x8

    .line 27
    .line 28
    if-ne v0, v1, :cond_0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    invoke-virtual {p5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Ll5/c;

    .line 36
    .line 37
    iget-object v0, v0, Ll5/c;->a:Ll5/a;

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    invoke-virtual {v0, p0, p5, p1}, Ll5/a;->g(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;I)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-nez v0, :cond_2

    .line 46
    .line 47
    :cond_1
    invoke-virtual {p0, p5, p1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q(Landroid/view/View;I)V

    .line 48
    .line 49
    .line 50
    :cond_2
    :goto_1
    add-int/lit8 p4, p4, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    return-void
.end method

.method public final onMeasure(II)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v6, 0x0

    .line 11
    move v2, v6

    .line 12
    :goto_0
    const/4 v3, 0x1

    .line 13
    if-ge v2, v1, :cond_2

    .line 14
    .line 15
    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    iget-object v5, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->e:Lcom/google/firebase/messaging/w;

    .line 20
    .line 21
    iget-object v5, v5, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v5, Landroidx/collection/a1;

    .line 24
    .line 25
    invoke-virtual {v5}, Landroidx/collection/a1;->size()I

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    move v8, v6

    .line 30
    :goto_1
    if-ge v8, v7, :cond_1

    .line 31
    .line 32
    invoke-virtual {v5, v8}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v9

    .line 36
    check-cast v9, Ljava/util/ArrayList;

    .line 37
    .line 38
    if-eqz v9, :cond_0

    .line 39
    .line 40
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v9

    .line 44
    if-eqz v9, :cond_0

    .line 45
    .line 46
    move v1, v3

    .line 47
    goto :goto_2

    .line 48
    :cond_0
    add-int/lit8 v8, v8, 0x1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    move v1, v6

    .line 55
    :goto_2
    iget-boolean v2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p:Z

    .line 56
    .line 57
    if-eq v1, v2, :cond_7

    .line 58
    .line 59
    if-eqz v1, :cond_5

    .line 60
    .line 61
    iget-boolean v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k:Z

    .line 62
    .line 63
    if-eqz v1, :cond_4

    .line 64
    .line 65
    iget-object v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 66
    .line 67
    if-nez v1, :cond_3

    .line 68
    .line 69
    new-instance v1, Ll5/d;

    .line 70
    .line 71
    invoke-direct {v1, v0}, Ll5/d;-><init>(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)V

    .line 72
    .line 73
    .line 74
    iput-object v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 75
    .line 76
    :cond_3
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    iget-object v2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 81
    .line 82
    invoke-virtual {v1, v2}, Landroid/view/ViewTreeObserver;->addOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 83
    .line 84
    .line 85
    :cond_4
    iput-boolean v3, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p:Z

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    iget-boolean v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k:Z

    .line 89
    .line 90
    if-eqz v1, :cond_6

    .line 91
    .line 92
    iget-object v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 93
    .line 94
    if-eqz v1, :cond_6

    .line 95
    .line 96
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    iget-object v2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->o:Ll5/d;

    .line 101
    .line 102
    invoke-virtual {v1, v2}, Landroid/view/ViewTreeObserver;->removeOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 103
    .line 104
    .line 105
    :cond_6
    iput-boolean v6, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->p:Z

    .line 106
    .line 107
    :cond_7
    :goto_3
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 108
    .line 109
    .line 110
    move-result v7

    .line 111
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 116
    .line 117
    .line 118
    move-result v8

    .line 119
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    sget-object v4, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 124
    .line 125
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 126
    .line 127
    .line 128
    move-result v9

    .line 129
    if-ne v9, v3, :cond_8

    .line 130
    .line 131
    move v10, v3

    .line 132
    goto :goto_4

    .line 133
    :cond_8
    move v10, v6

    .line 134
    :goto_4
    invoke-static/range {p1 .. p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 135
    .line 136
    .line 137
    move-result v11

    .line 138
    invoke-static/range {p1 .. p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 139
    .line 140
    .line 141
    move-result v12

    .line 142
    invoke-static/range {p2 .. p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 143
    .line 144
    .line 145
    move-result v13

    .line 146
    invoke-static/range {p2 .. p2}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 147
    .line 148
    .line 149
    move-result v14

    .line 150
    add-int v15, v7, v8

    .line 151
    .line 152
    add-int v16, v1, v2

    .line 153
    .line 154
    invoke-virtual {v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->getSuggestedMinimumWidth()I

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    invoke-virtual {v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->getSuggestedMinimumHeight()I

    .line 159
    .line 160
    .line 161
    move-result v2

    .line 162
    iget-object v4, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 163
    .line 164
    if-eqz v4, :cond_9

    .line 165
    .line 166
    invoke-virtual {v0}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    if-eqz v4, :cond_9

    .line 171
    .line 172
    move/from16 v17, v3

    .line 173
    .line 174
    goto :goto_5

    .line 175
    :cond_9
    move/from16 v17, v6

    .line 176
    .line 177
    :goto_5
    iget-object v3, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d:Ljava/util/ArrayList;

    .line 178
    .line 179
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    move v5, v6

    .line 184
    move/from16 v18, v5

    .line 185
    .line 186
    :goto_6
    if-ge v5, v4, :cond_16

    .line 187
    .line 188
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v19

    .line 192
    check-cast v19, Landroid/view/View;

    .line 193
    .line 194
    invoke-virtual/range {v19 .. v19}, Landroid/view/View;->getVisibility()I

    .line 195
    .line 196
    .line 197
    move-result v6

    .line 198
    move/from16 v21, v1

    .line 199
    .line 200
    const/16 v1, 0x8

    .line 201
    .line 202
    if-ne v6, v1, :cond_a

    .line 203
    .line 204
    move-object/from16 v23, v3

    .line 205
    .line 206
    move/from16 v22, v4

    .line 207
    .line 208
    move/from16 v19, v5

    .line 209
    .line 210
    move/from16 v20, v7

    .line 211
    .line 212
    move/from16 v1, v21

    .line 213
    .line 214
    const/16 v24, 0x0

    .line 215
    .line 216
    move/from16 v21, v8

    .line 217
    .line 218
    goto/16 :goto_e

    .line 219
    .line 220
    :cond_a
    invoke-virtual/range {v19 .. v19}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 221
    .line 222
    .line 223
    move-result-object v1

    .line 224
    move-object v6, v1

    .line 225
    check-cast v6, Ll5/c;

    .line 226
    .line 227
    iget v1, v6, Ll5/c;->e:I

    .line 228
    .line 229
    if-ltz v1, :cond_12

    .line 230
    .line 231
    if-eqz v11, :cond_12

    .line 232
    .line 233
    invoke-virtual {v0, v1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m(I)I

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    move/from16 v22, v1

    .line 238
    .line 239
    iget v1, v6, Ll5/c;->c:I

    .line 240
    .line 241
    if-nez v1, :cond_b

    .line 242
    .line 243
    const v1, 0x800035

    .line 244
    .line 245
    .line 246
    :cond_b
    invoke-static {v1, v9}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 247
    .line 248
    .line 249
    move-result v1

    .line 250
    and-int/lit8 v1, v1, 0x7

    .line 251
    .line 252
    move/from16 v23, v2

    .line 253
    .line 254
    const/4 v2, 0x3

    .line 255
    if-ne v1, v2, :cond_c

    .line 256
    .line 257
    if-eqz v10, :cond_d

    .line 258
    .line 259
    :cond_c
    const/4 v2, 0x5

    .line 260
    if-ne v1, v2, :cond_e

    .line 261
    .line 262
    if-eqz v10, :cond_e

    .line 263
    .line 264
    :cond_d
    sub-int v1, v12, v8

    .line 265
    .line 266
    sub-int v1, v1, v22

    .line 267
    .line 268
    const/4 v2, 0x0

    .line 269
    invoke-static {v2, v1}, Ljava/lang/Math;->max(II)I

    .line 270
    .line 271
    .line 272
    move-result v1

    .line 273
    :goto_7
    move/from16 v25, v4

    .line 274
    .line 275
    move v4, v1

    .line 276
    move/from16 v1, v25

    .line 277
    .line 278
    goto :goto_a

    .line 279
    :cond_e
    if-ne v1, v2, :cond_f

    .line 280
    .line 281
    if-eqz v10, :cond_10

    .line 282
    .line 283
    :cond_f
    const/4 v2, 0x3

    .line 284
    if-ne v1, v2, :cond_11

    .line 285
    .line 286
    if-eqz v10, :cond_11

    .line 287
    .line 288
    :cond_10
    sub-int v1, v22, v7

    .line 289
    .line 290
    const/4 v2, 0x0

    .line 291
    invoke-static {v2, v1}, Ljava/lang/Math;->max(II)I

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    goto :goto_7

    .line 296
    :cond_11
    :goto_8
    const/4 v2, 0x0

    .line 297
    goto :goto_9

    .line 298
    :cond_12
    move/from16 v23, v2

    .line 299
    .line 300
    goto :goto_8

    .line 301
    :goto_9
    move v1, v4

    .line 302
    move v4, v2

    .line 303
    :goto_a
    if-eqz v17, :cond_13

    .line 304
    .line 305
    invoke-virtual/range {v19 .. v19}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 306
    .line 307
    .line 308
    move-result v20

    .line 309
    if-nez v20, :cond_13

    .line 310
    .line 311
    iget-object v2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 312
    .line 313
    invoke-virtual {v2}, Ld6/w1;->b()I

    .line 314
    .line 315
    .line 316
    move-result v2

    .line 317
    move/from16 v22, v1

    .line 318
    .line 319
    iget-object v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 320
    .line 321
    invoke-virtual {v1}, Ld6/w1;->c()I

    .line 322
    .line 323
    .line 324
    move-result v1

    .line 325
    add-int/2addr v1, v2

    .line 326
    iget-object v2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 327
    .line 328
    invoke-virtual {v2}, Ld6/w1;->d()I

    .line 329
    .line 330
    .line 331
    move-result v2

    .line 332
    move/from16 v24, v1

    .line 333
    .line 334
    iget-object v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 335
    .line 336
    invoke-virtual {v1}, Ld6/w1;->a()I

    .line 337
    .line 338
    .line 339
    move-result v1

    .line 340
    add-int/2addr v1, v2

    .line 341
    sub-int v2, v12, v24

    .line 342
    .line 343
    invoke-static {v2, v11}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 344
    .line 345
    .line 346
    move-result v2

    .line 347
    sub-int v1, v14, v1

    .line 348
    .line 349
    invoke-static {v1, v13}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 350
    .line 351
    .line 352
    move-result v1

    .line 353
    goto :goto_b

    .line 354
    :cond_13
    move/from16 v22, v1

    .line 355
    .line 356
    move/from16 v2, p1

    .line 357
    .line 358
    move/from16 v1, p2

    .line 359
    .line 360
    :goto_b
    iget-object v0, v6, Ll5/c;->a:Ll5/a;

    .line 361
    .line 362
    if-eqz v0, :cond_15

    .line 363
    .line 364
    const/16 v24, 0x0

    .line 365
    .line 366
    move/from16 v20, v7

    .line 367
    .line 368
    move/from16 v7, v21

    .line 369
    .line 370
    move/from16 v21, v8

    .line 371
    .line 372
    move/from16 v8, v23

    .line 373
    .line 374
    move-object/from16 v23, v3

    .line 375
    .line 376
    move v3, v2

    .line 377
    move-object/from16 v2, v19

    .line 378
    .line 379
    move/from16 v19, v5

    .line 380
    .line 381
    move v5, v1

    .line 382
    move-object/from16 v1, p0

    .line 383
    .line 384
    invoke-virtual/range {v0 .. v5}, Ll5/a;->h(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;III)Z

    .line 385
    .line 386
    .line 387
    move-result v0

    .line 388
    move-object v1, v2

    .line 389
    move v2, v3

    .line 390
    move v3, v4

    .line 391
    move v4, v5

    .line 392
    if-nez v0, :cond_14

    .line 393
    .line 394
    goto :goto_c

    .line 395
    :cond_14
    move-object/from16 v0, p0

    .line 396
    .line 397
    goto :goto_d

    .line 398
    :cond_15
    move/from16 v20, v7

    .line 399
    .line 400
    move/from16 v7, v21

    .line 401
    .line 402
    const/16 v24, 0x0

    .line 403
    .line 404
    move/from16 v21, v8

    .line 405
    .line 406
    move/from16 v8, v23

    .line 407
    .line 408
    move-object/from16 v23, v3

    .line 409
    .line 410
    move v3, v4

    .line 411
    move v4, v1

    .line 412
    move-object/from16 v1, v19

    .line 413
    .line 414
    move/from16 v19, v5

    .line 415
    .line 416
    :goto_c
    const/4 v5, 0x0

    .line 417
    move-object/from16 v0, p0

    .line 418
    .line 419
    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    .line 420
    .line 421
    .line 422
    :goto_d
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    .line 423
    .line 424
    .line 425
    move-result v2

    .line 426
    add-int/2addr v2, v15

    .line 427
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 428
    .line 429
    add-int/2addr v2, v3

    .line 430
    iget v3, v6, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 431
    .line 432
    add-int/2addr v2, v3

    .line 433
    invoke-static {v7, v2}, Ljava/lang/Math;->max(II)I

    .line 434
    .line 435
    .line 436
    move-result v2

    .line 437
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 438
    .line 439
    .line 440
    move-result v3

    .line 441
    add-int v3, v3, v16

    .line 442
    .line 443
    iget v4, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 444
    .line 445
    add-int/2addr v3, v4

    .line 446
    iget v4, v6, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 447
    .line 448
    add-int/2addr v3, v4

    .line 449
    invoke-static {v8, v3}, Ljava/lang/Math;->max(II)I

    .line 450
    .line 451
    .line 452
    move-result v3

    .line 453
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredState()I

    .line 454
    .line 455
    .line 456
    move-result v1

    .line 457
    move/from16 v6, v18

    .line 458
    .line 459
    invoke-static {v6, v1}, Landroid/view/View;->combineMeasuredStates(II)I

    .line 460
    .line 461
    .line 462
    move-result v18

    .line 463
    move v1, v2

    .line 464
    move v2, v3

    .line 465
    :goto_e
    add-int/lit8 v5, v19, 0x1

    .line 466
    .line 467
    move/from16 v7, v20

    .line 468
    .line 469
    move/from16 v8, v21

    .line 470
    .line 471
    move/from16 v4, v22

    .line 472
    .line 473
    move-object/from16 v3, v23

    .line 474
    .line 475
    move/from16 v6, v24

    .line 476
    .line 477
    goto/16 :goto_6

    .line 478
    .line 479
    :cond_16
    move v7, v1

    .line 480
    move v8, v2

    .line 481
    move/from16 v6, v18

    .line 482
    .line 483
    const/high16 v1, -0x1000000

    .line 484
    .line 485
    and-int/2addr v1, v6

    .line 486
    move/from16 v2, p1

    .line 487
    .line 488
    invoke-static {v7, v2, v1}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 489
    .line 490
    .line 491
    move-result v1

    .line 492
    shl-int/lit8 v2, v6, 0x10

    .line 493
    .line 494
    move/from16 v3, p2

    .line 495
    .line 496
    invoke-static {v8, v3, v2}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 497
    .line 498
    .line 499
    move-result v2

    .line 500
    invoke-virtual {v0, v1, v2}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 501
    .line 502
    .line 503
    return-void
.end method

.method public final onNestedFling(Landroid/view/View;FFZ)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 p2, 0x0

    .line 6
    move p3, p2

    .line 7
    :goto_0
    if-ge p3, p1, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, p3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object p4

    .line 13
    invoke-virtual {p4}, Landroid/view/View;->getVisibility()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/16 v1, 0x8

    .line 18
    .line 19
    if-ne v0, v1, :cond_0

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    invoke-virtual {p4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 23
    .line 24
    .line 25
    move-result-object p4

    .line 26
    check-cast p4, Ll5/c;

    .line 27
    .line 28
    invoke-virtual {p4, p2}, Ll5/c;->a(I)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget-object p4, p4, Ll5/c;->a:Ll5/a;

    .line 36
    .line 37
    :goto_1
    add-int/lit8 p3, p3, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    return p2
.end method

.method public final onNestedPreFling(Landroid/view/View;FF)Z
    .locals 5

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    const/4 p3, 0x0

    .line 6
    move v0, p3

    .line 7
    move v1, v0

    .line 8
    :goto_0
    if-ge v0, p2, :cond_3

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/16 v4, 0x8

    .line 19
    .line 20
    if-ne v3, v4, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Ll5/c;

    .line 28
    .line 29
    invoke-virtual {v2, p3}, Ll5/c;->a(I)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-nez v3, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    iget-object v2, v2, Ll5/c;->a:Ll5/a;

    .line 37
    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    invoke-virtual {v2, p1}, Ll5/a;->i(Landroid/view/View;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    or-int/2addr v1, v2

    .line 45
    :cond_2
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_3
    return v1
.end method

.method public final onNestedPreScroll(Landroid/view/View;II[I)V
    .locals 6

    .line 1
    const/4 v5, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-object v1, p1

    .line 4
    move v2, p2

    .line 5
    move v3, p3

    .line 6
    move-object v4, p4

    .line 7
    invoke-virtual/range {v0 .. v5}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d(Landroid/view/View;II[II)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final onNestedScroll(Landroid/view/View;IIII)V
    .locals 7

    .line 1
    const/4 v6, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-object v1, p1

    .line 4
    move v2, p2

    .line 5
    move v3, p3

    .line 6
    move v4, p4

    .line 7
    move v5, p5

    .line 8
    invoke-virtual/range {v0 .. v6}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->h(Landroid/view/View;IIIII)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final onNestedScrollAccepted(Landroid/view/View;Landroid/view/View;I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->b(Landroid/view/View;Landroid/view/View;II)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final onRestoreInstanceState(Landroid/os/Parcelable;)V
    .locals 6

    .line 1
    instance-of v0, p1, Ll5/e;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Landroid/view/View;->onRestoreInstanceState(Landroid/os/Parcelable;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    check-cast p1, Ll5/e;

    .line 10
    .line 11
    iget-object v0, p1, Lj6/b;->d:Landroid/os/Parcelable;

    .line 12
    .line 13
    invoke-super {p0, v0}, Landroid/view/View;->onRestoreInstanceState(Landroid/os/Parcelable;)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p1, Ll5/e;->f:Landroid/util/SparseArray;

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, 0x0

    .line 23
    :goto_0
    if-ge v1, v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-virtual {v2}, Landroid/view/View;->getId()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    invoke-static {v2}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->n(Landroid/view/View;)Ll5/c;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iget-object v4, v4, Ll5/c;->a:Ll5/a;

    .line 38
    .line 39
    const/4 v5, -0x1

    .line 40
    if-eq v3, v5, :cond_1

    .line 41
    .line 42
    if-eqz v4, :cond_1

    .line 43
    .line 44
    invoke-virtual {p1, v3}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    check-cast v3, Landroid/os/Parcelable;

    .line 49
    .line 50
    if-eqz v3, :cond_1

    .line 51
    .line 52
    invoke-virtual {v4, v2, v3}, Ll5/a;->m(Landroid/view/View;Landroid/os/Parcelable;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    return-void
.end method

.method public final onSaveInstanceState()Landroid/os/Parcelable;
    .locals 8

    .line 1
    new-instance v0, Ll5/e;

    .line 2
    .line 3
    invoke-super {p0}, Landroid/view/View;->onSaveInstanceState()Landroid/os/Parcelable;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lj6/b;-><init>(Landroid/os/Parcelable;)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Landroid/util/SparseArray;

    .line 11
    .line 12
    invoke-direct {v1}, Landroid/util/SparseArray;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/4 v3, 0x0

    .line 20
    :goto_0
    if-ge v3, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-virtual {v4}, Landroid/view/View;->getId()I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    check-cast v6, Ll5/c;

    .line 35
    .line 36
    iget-object v6, v6, Ll5/c;->a:Ll5/a;

    .line 37
    .line 38
    const/4 v7, -0x1

    .line 39
    if-eq v5, v7, :cond_0

    .line 40
    .line 41
    if-eqz v6, :cond_0

    .line 42
    .line 43
    invoke-virtual {v6, v4}, Ll5/a;->n(Landroid/view/View;)Landroid/os/Parcelable;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    if-eqz v4, :cond_0

    .line 48
    .line 49
    invoke-virtual {v1, v5, v4}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    iput-object v1, v0, Ll5/e;->f:Landroid/util/SparseArray;

    .line 56
    .line 57
    return-object v0
.end method

.method public final onStartNestedScroll(Landroid/view/View;Landroid/view/View;I)Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->i(Landroid/view/View;Landroid/view/View;II)Z

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public final onStopNestedScroll(Landroid/view/View;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->c(Landroid/view/View;I)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    iget-object v3, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m:Landroid/view/View;

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    const/4 v5, 0x0

    .line 13
    if-nez v3, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0, v1, v4}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->r(Landroid/view/MotionEvent;I)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v6, v5

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v3, v5

    .line 25
    :goto_0
    iget-object v6, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m:Landroid/view/View;

    .line 26
    .line 27
    invoke-virtual {v6}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    check-cast v6, Ll5/c;

    .line 32
    .line 33
    iget-object v6, v6, Ll5/c;->a:Ll5/a;

    .line 34
    .line 35
    if-eqz v6, :cond_0

    .line 36
    .line 37
    iget-object v7, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m:Landroid/view/View;

    .line 38
    .line 39
    invoke-virtual {v6, v7, v1}, Ll5/a;->q(Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    :goto_1
    iget-object v7, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m:Landroid/view/View;

    .line 44
    .line 45
    const/4 v8, 0x0

    .line 46
    if-nez v7, :cond_2

    .line 47
    .line 48
    invoke-super/range {p0 .. p1}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    or-int/2addr v6, v1

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    if-eqz v3, :cond_3

    .line 55
    .line 56
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 57
    .line 58
    .line 59
    move-result-wide v9

    .line 60
    const/4 v15, 0x0

    .line 61
    const/16 v16, 0x0

    .line 62
    .line 63
    const/4 v13, 0x3

    .line 64
    const/4 v14, 0x0

    .line 65
    move-wide v11, v9

    .line 66
    invoke-static/range {v9 .. v16}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    invoke-super {v0, v8}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    .line 71
    .line 72
    .line 73
    :cond_3
    :goto_2
    if-eqz v8, :cond_4

    .line 74
    .line 75
    invoke-virtual {v8}, Landroid/view/MotionEvent;->recycle()V

    .line 76
    .line 77
    .line 78
    :cond_4
    if-eq v2, v4, :cond_6

    .line 79
    .line 80
    const/4 v1, 0x3

    .line 81
    if-ne v2, v1, :cond_5

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_5
    return v6

    .line 85
    :cond_6
    :goto_3
    invoke-virtual {v0, v5}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t(Z)V

    .line 86
    .line 87
    .line 88
    return v6
.end method

.method public final p(I)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    iget-object v2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 18
    .line 19
    .line 20
    move-result-object v10

    .line 21
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 22
    .line 23
    .line 24
    move-result-object v11

    .line 25
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 26
    .line 27
    .line 28
    move-result-object v12

    .line 29
    const/4 v14, 0x0

    .line 30
    :goto_0
    sget-object v15, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->A:Lc6/c;

    .line 31
    .line 32
    if-ge v14, v9, :cond_1d

    .line 33
    .line 34
    invoke-virtual {v2, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    check-cast v4, Landroid/view/View;

    .line 39
    .line 40
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    check-cast v5, Ll5/c;

    .line 45
    .line 46
    if-nez v1, :cond_0

    .line 47
    .line 48
    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    const/16 v7, 0x8

    .line 53
    .line 54
    if-ne v6, v7, :cond_0

    .line 55
    .line 56
    move-object v5, v2

    .line 57
    move v2, v9

    .line 58
    move-object v4, v12

    .line 59
    move/from16 v20, v14

    .line 60
    .line 61
    const/4 v6, 0x0

    .line 62
    goto/16 :goto_e

    .line 63
    .line 64
    :cond_0
    const/4 v6, 0x0

    .line 65
    :goto_1
    if-ge v6, v14, :cond_7

    .line 66
    .line 67
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v8

    .line 71
    check-cast v8, Landroid/view/View;

    .line 72
    .line 73
    iget-object v7, v5, Ll5/c;->l:Landroid/view/View;

    .line 74
    .line 75
    if-ne v7, v8, :cond_6

    .line 76
    .line 77
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    check-cast v7, Ll5/c;

    .line 82
    .line 83
    iget-object v8, v7, Ll5/c;->k:Landroid/view/View;

    .line 84
    .line 85
    if-eqz v8, :cond_6

    .line 86
    .line 87
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 92
    .line 93
    .line 94
    move-result-object v13

    .line 95
    move-object/from16 v17, v5

    .line 96
    .line 97
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    move/from16 v18, v3

    .line 102
    .line 103
    iget-object v3, v7, Ll5/c;->k:Landroid/view/View;

    .line 104
    .line 105
    invoke-virtual {v0, v3, v8}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 106
    .line 107
    .line 108
    const/4 v3, 0x0

    .line 109
    invoke-virtual {v0, v4, v13, v3}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->f(Landroid/view/View;Landroid/graphics/Rect;Z)V

    .line 110
    .line 111
    .line 112
    move v3, v6

    .line 113
    move-object v6, v7

    .line 114
    invoke-virtual {v4}, Landroid/view/View;->getMeasuredWidth()I

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    move-object/from16 v19, v4

    .line 119
    .line 120
    move-object v4, v8

    .line 121
    invoke-virtual/range {v19 .. v19}, Landroid/view/View;->getMeasuredHeight()I

    .line 122
    .line 123
    .line 124
    move-result v8

    .line 125
    move-object/from16 v20, v17

    .line 126
    .line 127
    move-object/from16 v17, v2

    .line 128
    .line 129
    move-object/from16 v2, v20

    .line 130
    .line 131
    move/from16 v20, v18

    .line 132
    .line 133
    move/from16 v18, v3

    .line 134
    .line 135
    move/from16 v3, v20

    .line 136
    .line 137
    move/from16 v20, v14

    .line 138
    .line 139
    move-object/from16 v14, v19

    .line 140
    .line 141
    invoke-static/range {v3 .. v8}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->l(ILandroid/graphics/Rect;Landroid/graphics/Rect;Ll5/c;II)V

    .line 142
    .line 143
    .line 144
    move/from16 v19, v9

    .line 145
    .line 146
    iget v9, v5, Landroid/graphics/Rect;->left:I

    .line 147
    .line 148
    move-object/from16 v21, v12

    .line 149
    .line 150
    iget v12, v13, Landroid/graphics/Rect;->left:I

    .line 151
    .line 152
    if-ne v9, v12, :cond_2

    .line 153
    .line 154
    iget v9, v5, Landroid/graphics/Rect;->top:I

    .line 155
    .line 156
    iget v12, v13, Landroid/graphics/Rect;->top:I

    .line 157
    .line 158
    if-eq v9, v12, :cond_1

    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_1
    const/16 v16, 0x0

    .line 162
    .line 163
    goto :goto_3

    .line 164
    :cond_2
    :goto_2
    const/16 v16, 0x1

    .line 165
    .line 166
    :goto_3
    invoke-virtual {v0, v6, v5, v7, v8}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->e(Ll5/c;Landroid/graphics/Rect;II)V

    .line 167
    .line 168
    .line 169
    iget v7, v5, Landroid/graphics/Rect;->left:I

    .line 170
    .line 171
    iget v8, v13, Landroid/graphics/Rect;->left:I

    .line 172
    .line 173
    sub-int/2addr v7, v8

    .line 174
    iget v8, v5, Landroid/graphics/Rect;->top:I

    .line 175
    .line 176
    iget v9, v13, Landroid/graphics/Rect;->top:I

    .line 177
    .line 178
    sub-int/2addr v8, v9

    .line 179
    if-eqz v7, :cond_3

    .line 180
    .line 181
    sget-object v9, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 182
    .line 183
    invoke-virtual {v14, v7}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 184
    .line 185
    .line 186
    :cond_3
    if-eqz v8, :cond_4

    .line 187
    .line 188
    sget-object v7, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 189
    .line 190
    invoke-virtual {v14, v8}, Landroid/view/View;->offsetTopAndBottom(I)V

    .line 191
    .line 192
    .line 193
    :cond_4
    if-eqz v16, :cond_5

    .line 194
    .line 195
    iget-object v7, v6, Ll5/c;->a:Ll5/a;

    .line 196
    .line 197
    if-eqz v7, :cond_5

    .line 198
    .line 199
    iget-object v6, v6, Ll5/c;->k:Landroid/view/View;

    .line 200
    .line 201
    invoke-virtual {v7, v0, v14, v6}, Ll5/a;->d(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/view/View;)Z

    .line 202
    .line 203
    .line 204
    :cond_5
    invoke-virtual {v4}, Landroid/graphics/Rect;->setEmpty()V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v15, v4}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    invoke-virtual {v13}, Landroid/graphics/Rect;->setEmpty()V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v15, v13}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    invoke-virtual {v5}, Landroid/graphics/Rect;->setEmpty()V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v15, v5}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    goto :goto_4

    .line 223
    :cond_6
    move-object/from16 v17, v2

    .line 224
    .line 225
    move-object v2, v5

    .line 226
    move/from16 v18, v6

    .line 227
    .line 228
    move/from16 v19, v9

    .line 229
    .line 230
    move-object/from16 v21, v12

    .line 231
    .line 232
    move/from16 v20, v14

    .line 233
    .line 234
    move-object v14, v4

    .line 235
    :goto_4
    add-int/lit8 v6, v18, 0x1

    .line 236
    .line 237
    move-object v5, v2

    .line 238
    move-object v4, v14

    .line 239
    move-object/from16 v2, v17

    .line 240
    .line 241
    move/from16 v9, v19

    .line 242
    .line 243
    move/from16 v14, v20

    .line 244
    .line 245
    move-object/from16 v12, v21

    .line 246
    .line 247
    goto/16 :goto_1

    .line 248
    .line 249
    :cond_7
    move-object/from16 v17, v2

    .line 250
    .line 251
    move-object v2, v5

    .line 252
    move/from16 v19, v9

    .line 253
    .line 254
    move-object/from16 v21, v12

    .line 255
    .line 256
    move/from16 v20, v14

    .line 257
    .line 258
    move-object v14, v4

    .line 259
    const/4 v4, 0x1

    .line 260
    invoke-virtual {v0, v14, v11, v4}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->f(Landroid/view/View;Landroid/graphics/Rect;Z)V

    .line 261
    .line 262
    .line 263
    iget v5, v2, Ll5/c;->g:I

    .line 264
    .line 265
    const/4 v6, 0x5

    .line 266
    const/4 v7, 0x3

    .line 267
    const/16 v8, 0x50

    .line 268
    .line 269
    const/16 v9, 0x30

    .line 270
    .line 271
    if-eqz v5, :cond_c

    .line 272
    .line 273
    invoke-virtual {v11}, Landroid/graphics/Rect;->isEmpty()Z

    .line 274
    .line 275
    .line 276
    move-result v5

    .line 277
    if-nez v5, :cond_c

    .line 278
    .line 279
    iget v5, v2, Ll5/c;->g:I

    .line 280
    .line 281
    invoke-static {v5, v3}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 282
    .line 283
    .line 284
    move-result v5

    .line 285
    and-int/lit8 v12, v5, 0x70

    .line 286
    .line 287
    if-eq v12, v9, :cond_9

    .line 288
    .line 289
    if-eq v12, v8, :cond_8

    .line 290
    .line 291
    goto :goto_5

    .line 292
    :cond_8
    iget v12, v10, Landroid/graphics/Rect;->bottom:I

    .line 293
    .line 294
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 295
    .line 296
    .line 297
    move-result v13

    .line 298
    iget v4, v11, Landroid/graphics/Rect;->top:I

    .line 299
    .line 300
    sub-int/2addr v13, v4

    .line 301
    invoke-static {v12, v13}, Ljava/lang/Math;->max(II)I

    .line 302
    .line 303
    .line 304
    move-result v4

    .line 305
    iput v4, v10, Landroid/graphics/Rect;->bottom:I

    .line 306
    .line 307
    goto :goto_5

    .line 308
    :cond_9
    iget v4, v10, Landroid/graphics/Rect;->top:I

    .line 309
    .line 310
    iget v12, v11, Landroid/graphics/Rect;->bottom:I

    .line 311
    .line 312
    invoke-static {v4, v12}, Ljava/lang/Math;->max(II)I

    .line 313
    .line 314
    .line 315
    move-result v4

    .line 316
    iput v4, v10, Landroid/graphics/Rect;->top:I

    .line 317
    .line 318
    :goto_5
    and-int/lit8 v4, v5, 0x7

    .line 319
    .line 320
    if-eq v4, v7, :cond_b

    .line 321
    .line 322
    if-eq v4, v6, :cond_a

    .line 323
    .line 324
    goto :goto_6

    .line 325
    :cond_a
    iget v4, v10, Landroid/graphics/Rect;->right:I

    .line 326
    .line 327
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 328
    .line 329
    .line 330
    move-result v5

    .line 331
    iget v12, v11, Landroid/graphics/Rect;->left:I

    .line 332
    .line 333
    sub-int/2addr v5, v12

    .line 334
    invoke-static {v4, v5}, Ljava/lang/Math;->max(II)I

    .line 335
    .line 336
    .line 337
    move-result v4

    .line 338
    iput v4, v10, Landroid/graphics/Rect;->right:I

    .line 339
    .line 340
    goto :goto_6

    .line 341
    :cond_b
    iget v4, v10, Landroid/graphics/Rect;->left:I

    .line 342
    .line 343
    iget v5, v11, Landroid/graphics/Rect;->right:I

    .line 344
    .line 345
    invoke-static {v4, v5}, Ljava/lang/Math;->max(II)I

    .line 346
    .line 347
    .line 348
    move-result v4

    .line 349
    iput v4, v10, Landroid/graphics/Rect;->left:I

    .line 350
    .line 351
    :cond_c
    :goto_6
    iget v2, v2, Ll5/c;->h:I

    .line 352
    .line 353
    if-eqz v2, :cond_18

    .line 354
    .line 355
    invoke-virtual {v14}, Landroid/view/View;->getVisibility()I

    .line 356
    .line 357
    .line 358
    move-result v2

    .line 359
    if-nez v2, :cond_18

    .line 360
    .line 361
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 362
    .line 363
    invoke-virtual {v14}, Landroid/view/View;->isLaidOut()Z

    .line 364
    .line 365
    .line 366
    move-result v2

    .line 367
    if-nez v2, :cond_d

    .line 368
    .line 369
    goto/16 :goto_a

    .line 370
    .line 371
    :cond_d
    invoke-virtual {v14}, Landroid/view/View;->getWidth()I

    .line 372
    .line 373
    .line 374
    move-result v2

    .line 375
    if-lez v2, :cond_18

    .line 376
    .line 377
    invoke-virtual {v14}, Landroid/view/View;->getHeight()I

    .line 378
    .line 379
    .line 380
    move-result v2

    .line 381
    if-gtz v2, :cond_e

    .line 382
    .line 383
    goto/16 :goto_a

    .line 384
    .line 385
    :cond_e
    invoke-virtual {v14}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 386
    .line 387
    .line 388
    move-result-object v2

    .line 389
    check-cast v2, Ll5/c;

    .line 390
    .line 391
    iget-object v4, v2, Ll5/c;->a:Ll5/a;

    .line 392
    .line 393
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 394
    .line 395
    .line 396
    move-result-object v5

    .line 397
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 398
    .line 399
    .line 400
    move-result-object v12

    .line 401
    invoke-virtual {v14}, Landroid/view/View;->getLeft()I

    .line 402
    .line 403
    .line 404
    move-result v13

    .line 405
    invoke-virtual {v14}, Landroid/view/View;->getTop()I

    .line 406
    .line 407
    .line 408
    move-result v6

    .line 409
    invoke-virtual {v14}, Landroid/view/View;->getRight()I

    .line 410
    .line 411
    .line 412
    move-result v7

    .line 413
    invoke-virtual {v14}, Landroid/view/View;->getBottom()I

    .line 414
    .line 415
    .line 416
    move-result v8

    .line 417
    invoke-virtual {v12, v13, v6, v7, v8}, Landroid/graphics/Rect;->set(IIII)V

    .line 418
    .line 419
    .line 420
    if-eqz v4, :cond_10

    .line 421
    .line 422
    invoke-virtual {v4, v14}, Ll5/a;->a(Landroid/view/View;)Z

    .line 423
    .line 424
    .line 425
    move-result v4

    .line 426
    if-eqz v4, :cond_10

    .line 427
    .line 428
    invoke-virtual {v12, v5}, Landroid/graphics/Rect;->contains(Landroid/graphics/Rect;)Z

    .line 429
    .line 430
    .line 431
    move-result v4

    .line 432
    if-eqz v4, :cond_f

    .line 433
    .line 434
    goto :goto_7

    .line 435
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 436
    .line 437
    new-instance v1, Ljava/lang/StringBuilder;

    .line 438
    .line 439
    const-string v2, "Rect should be within the child\'s bounds. Rect:"

    .line 440
    .line 441
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v5}, Landroid/graphics/Rect;->toShortString()Ljava/lang/String;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 449
    .line 450
    .line 451
    const-string v2, " | Bounds:"

    .line 452
    .line 453
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 454
    .line 455
    .line 456
    invoke-virtual {v12}, Landroid/graphics/Rect;->toShortString()Ljava/lang/String;

    .line 457
    .line 458
    .line 459
    move-result-object v2

    .line 460
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 461
    .line 462
    .line 463
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object v1

    .line 467
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 468
    .line 469
    .line 470
    throw v0

    .line 471
    :cond_10
    invoke-virtual {v5, v12}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 472
    .line 473
    .line 474
    :goto_7
    invoke-virtual {v12}, Landroid/graphics/Rect;->setEmpty()V

    .line 475
    .line 476
    .line 477
    invoke-virtual {v15, v12}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    invoke-virtual {v5}, Landroid/graphics/Rect;->isEmpty()Z

    .line 481
    .line 482
    .line 483
    move-result v4

    .line 484
    if-eqz v4, :cond_11

    .line 485
    .line 486
    invoke-virtual {v5}, Landroid/graphics/Rect;->setEmpty()V

    .line 487
    .line 488
    .line 489
    invoke-virtual {v15, v5}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 490
    .line 491
    .line 492
    goto/16 :goto_a

    .line 493
    .line 494
    :cond_11
    iget v4, v2, Ll5/c;->h:I

    .line 495
    .line 496
    invoke-static {v4, v3}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 497
    .line 498
    .line 499
    move-result v4

    .line 500
    and-int/lit8 v6, v4, 0x30

    .line 501
    .line 502
    if-ne v6, v9, :cond_12

    .line 503
    .line 504
    iget v6, v5, Landroid/graphics/Rect;->top:I

    .line 505
    .line 506
    iget v7, v2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 507
    .line 508
    sub-int/2addr v6, v7

    .line 509
    iget v7, v2, Ll5/c;->j:I

    .line 510
    .line 511
    sub-int/2addr v6, v7

    .line 512
    iget v7, v10, Landroid/graphics/Rect;->top:I

    .line 513
    .line 514
    if-ge v6, v7, :cond_12

    .line 515
    .line 516
    sub-int/2addr v7, v6

    .line 517
    invoke-static {v14, v7}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v(Landroid/view/View;I)V

    .line 518
    .line 519
    .line 520
    const/4 v7, 0x1

    .line 521
    goto :goto_8

    .line 522
    :cond_12
    const/4 v7, 0x0

    .line 523
    :goto_8
    and-int/lit8 v6, v4, 0x50

    .line 524
    .line 525
    const/16 v8, 0x50

    .line 526
    .line 527
    if-ne v6, v8, :cond_13

    .line 528
    .line 529
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 530
    .line 531
    .line 532
    move-result v6

    .line 533
    iget v8, v5, Landroid/graphics/Rect;->bottom:I

    .line 534
    .line 535
    sub-int/2addr v6, v8

    .line 536
    iget v8, v2, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 537
    .line 538
    sub-int/2addr v6, v8

    .line 539
    iget v8, v2, Ll5/c;->j:I

    .line 540
    .line 541
    add-int/2addr v6, v8

    .line 542
    iget v8, v10, Landroid/graphics/Rect;->bottom:I

    .line 543
    .line 544
    if-ge v6, v8, :cond_13

    .line 545
    .line 546
    sub-int/2addr v6, v8

    .line 547
    invoke-static {v14, v6}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v(Landroid/view/View;I)V

    .line 548
    .line 549
    .line 550
    const/4 v7, 0x1

    .line 551
    :cond_13
    if-nez v7, :cond_14

    .line 552
    .line 553
    const/4 v6, 0x0

    .line 554
    invoke-static {v14, v6}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->v(Landroid/view/View;I)V

    .line 555
    .line 556
    .line 557
    :cond_14
    and-int/lit8 v6, v4, 0x3

    .line 558
    .line 559
    const/4 v7, 0x3

    .line 560
    if-ne v6, v7, :cond_15

    .line 561
    .line 562
    iget v6, v5, Landroid/graphics/Rect;->left:I

    .line 563
    .line 564
    iget v7, v2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 565
    .line 566
    sub-int/2addr v6, v7

    .line 567
    iget v7, v2, Ll5/c;->i:I

    .line 568
    .line 569
    sub-int/2addr v6, v7

    .line 570
    iget v7, v10, Landroid/graphics/Rect;->left:I

    .line 571
    .line 572
    if-ge v6, v7, :cond_15

    .line 573
    .line 574
    sub-int/2addr v7, v6

    .line 575
    invoke-static {v14, v7}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u(Landroid/view/View;I)V

    .line 576
    .line 577
    .line 578
    const/4 v7, 0x1

    .line 579
    goto :goto_9

    .line 580
    :cond_15
    const/4 v7, 0x0

    .line 581
    :goto_9
    and-int/lit8 v4, v4, 0x5

    .line 582
    .line 583
    const/4 v6, 0x5

    .line 584
    if-ne v4, v6, :cond_16

    .line 585
    .line 586
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 587
    .line 588
    .line 589
    move-result v4

    .line 590
    iget v6, v5, Landroid/graphics/Rect;->right:I

    .line 591
    .line 592
    sub-int/2addr v4, v6

    .line 593
    iget v6, v2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 594
    .line 595
    sub-int/2addr v4, v6

    .line 596
    iget v2, v2, Ll5/c;->i:I

    .line 597
    .line 598
    add-int/2addr v4, v2

    .line 599
    iget v2, v10, Landroid/graphics/Rect;->right:I

    .line 600
    .line 601
    if-ge v4, v2, :cond_16

    .line 602
    .line 603
    sub-int/2addr v4, v2

    .line 604
    invoke-static {v14, v4}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u(Landroid/view/View;I)V

    .line 605
    .line 606
    .line 607
    const/4 v7, 0x1

    .line 608
    :cond_16
    const/4 v6, 0x0

    .line 609
    if-nez v7, :cond_17

    .line 610
    .line 611
    invoke-static {v14, v6}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u(Landroid/view/View;I)V

    .line 612
    .line 613
    .line 614
    :cond_17
    invoke-virtual {v5}, Landroid/graphics/Rect;->setEmpty()V

    .line 615
    .line 616
    .line 617
    invoke-virtual {v15, v5}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 618
    .line 619
    .line 620
    goto :goto_b

    .line 621
    :cond_18
    :goto_a
    const/4 v6, 0x0

    .line 622
    :goto_b
    const/4 v2, 0x2

    .line 623
    if-eq v1, v2, :cond_1a

    .line 624
    .line 625
    invoke-virtual {v14}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 626
    .line 627
    .line 628
    move-result-object v2

    .line 629
    check-cast v2, Ll5/c;

    .line 630
    .line 631
    iget-object v2, v2, Ll5/c;->o:Landroid/graphics/Rect;

    .line 632
    .line 633
    move-object/from16 v4, v21

    .line 634
    .line 635
    invoke-virtual {v4, v2}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 636
    .line 637
    .line 638
    invoke-virtual {v4, v11}, Landroid/graphics/Rect;->equals(Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    move-result v2

    .line 642
    if-eqz v2, :cond_19

    .line 643
    .line 644
    move-object/from16 v5, v17

    .line 645
    .line 646
    move/from16 v2, v19

    .line 647
    .line 648
    goto :goto_e

    .line 649
    :cond_19
    invoke-virtual {v14}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 650
    .line 651
    .line 652
    move-result-object v2

    .line 653
    check-cast v2, Ll5/c;

    .line 654
    .line 655
    iget-object v2, v2, Ll5/c;->o:Landroid/graphics/Rect;

    .line 656
    .line 657
    invoke-virtual {v2, v11}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 658
    .line 659
    .line 660
    goto :goto_c

    .line 661
    :cond_1a
    move-object/from16 v4, v21

    .line 662
    .line 663
    :goto_c
    add-int/lit8 v14, v20, 0x1

    .line 664
    .line 665
    move/from16 v2, v19

    .line 666
    .line 667
    :goto_d
    move-object/from16 v5, v17

    .line 668
    .line 669
    if-ge v14, v2, :cond_1c

    .line 670
    .line 671
    invoke-virtual {v5, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    move-result-object v7

    .line 675
    check-cast v7, Landroid/view/View;

    .line 676
    .line 677
    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 678
    .line 679
    .line 680
    move-result-object v8

    .line 681
    check-cast v8, Ll5/c;

    .line 682
    .line 683
    iget-object v8, v8, Ll5/c;->a:Ll5/a;

    .line 684
    .line 685
    if-eqz v8, :cond_1b

    .line 686
    .line 687
    invoke-virtual {v8, v7}, Ll5/a;->b(Landroid/view/View;)V

    .line 688
    .line 689
    .line 690
    :cond_1b
    add-int/lit8 v14, v14, 0x1

    .line 691
    .line 692
    move-object/from16 v17, v5

    .line 693
    .line 694
    goto :goto_d

    .line 695
    :cond_1c
    :goto_e
    add-int/lit8 v14, v20, 0x1

    .line 696
    .line 697
    move v9, v2

    .line 698
    move-object v12, v4

    .line 699
    move-object v2, v5

    .line 700
    goto/16 :goto_0

    .line 701
    .line 702
    :cond_1d
    move-object v4, v12

    .line 703
    invoke-virtual {v10}, Landroid/graphics/Rect;->setEmpty()V

    .line 704
    .line 705
    .line 706
    invoke-virtual {v15, v10}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 707
    .line 708
    .line 709
    invoke-virtual {v11}, Landroid/graphics/Rect;->setEmpty()V

    .line 710
    .line 711
    .line 712
    invoke-virtual {v15, v11}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 713
    .line 714
    .line 715
    invoke-virtual {v4}, Landroid/graphics/Rect;->setEmpty()V

    .line 716
    .line 717
    .line 718
    invoke-virtual {v15, v4}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 719
    .line 720
    .line 721
    return-void
.end method

.method public final q(Landroid/view/View;I)V
    .locals 12

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ll5/c;

    .line 6
    .line 7
    iget-object v1, v0, Ll5/c;->k:Landroid/view/View;

    .line 8
    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    iget v2, v0, Ll5/c;->f:I

    .line 12
    .line 13
    const/4 v3, -0x1

    .line 14
    if-ne v2, v3, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string p1, "An anchor may not be changed after CoordinatorLayout measurement begins before layout is complete."

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    sget-object v2, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->A:Lc6/c;

    .line 26
    .line 27
    if-eqz v1, :cond_2

    .line 28
    .line 29
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    :try_start_0
    invoke-virtual {p0, v1, v4}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->k(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    move-object v6, v0

    .line 45
    check-cast v6, Ll5/c;

    .line 46
    .line 47
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredWidth()I

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    .line 52
    .line 53
    .line 54
    move-result v8

    .line 55
    move v3, p2

    .line 56
    invoke-static/range {v3 .. v8}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->l(ILandroid/graphics/Rect;Landroid/graphics/Rect;Ll5/c;II)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0, v6, v5, v7, v8}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->e(Ll5/c;Landroid/graphics/Rect;II)V

    .line 60
    .line 61
    .line 62
    iget p0, v5, Landroid/graphics/Rect;->left:I

    .line 63
    .line 64
    iget p2, v5, Landroid/graphics/Rect;->top:I

    .line 65
    .line 66
    iget v0, v5, Landroid/graphics/Rect;->right:I

    .line 67
    .line 68
    iget v1, v5, Landroid/graphics/Rect;->bottom:I

    .line 69
    .line 70
    invoke-virtual {p1, p0, p2, v0, v1}, Landroid/view/View;->layout(IIII)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    .line 72
    .line 73
    invoke-virtual {v4}, Landroid/graphics/Rect;->setEmpty()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2, v4}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    invoke-virtual {v5}, Landroid/graphics/Rect;->setEmpty()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v2, v5}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :catchall_0
    move-exception v0

    .line 87
    move-object p0, v0

    .line 88
    invoke-virtual {v4}, Landroid/graphics/Rect;->setEmpty()V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v2, v4}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    invoke-virtual {v5}, Landroid/graphics/Rect;->setEmpty()V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2, v5}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :cond_2
    move v3, p2

    .line 102
    iget p2, v0, Ll5/c;->e:I

    .line 103
    .line 104
    if-ltz p2, :cond_9

    .line 105
    .line 106
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    check-cast v0, Ll5/c;

    .line 111
    .line 112
    iget v1, v0, Ll5/c;->c:I

    .line 113
    .line 114
    if-nez v1, :cond_3

    .line 115
    .line 116
    const v1, 0x800035

    .line 117
    .line 118
    .line 119
    :cond_3
    invoke-static {v1, v3}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    and-int/lit8 v2, v1, 0x7

    .line 124
    .line 125
    and-int/lit8 v1, v1, 0x70

    .line 126
    .line 127
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 128
    .line 129
    .line 130
    move-result v4

    .line 131
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 132
    .line 133
    .line 134
    move-result v5

    .line 135
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredWidth()I

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    const/4 v8, 0x1

    .line 144
    if-ne v3, v8, :cond_4

    .line 145
    .line 146
    sub-int p2, v4, p2

    .line 147
    .line 148
    :cond_4
    invoke-virtual {p0, p2}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m(I)I

    .line 149
    .line 150
    .line 151
    move-result p2

    .line 152
    sub-int/2addr p2, v6

    .line 153
    if-eq v2, v8, :cond_6

    .line 154
    .line 155
    const/4 v3, 0x5

    .line 156
    if-eq v2, v3, :cond_5

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_5
    add-int/2addr p2, v6

    .line 160
    goto :goto_1

    .line 161
    :cond_6
    div-int/lit8 v2, v6, 0x2

    .line 162
    .line 163
    add-int/2addr p2, v2

    .line 164
    :goto_1
    const/16 v2, 0x10

    .line 165
    .line 166
    if-eq v1, v2, :cond_8

    .line 167
    .line 168
    const/16 v2, 0x50

    .line 169
    .line 170
    if-eq v1, v2, :cond_7

    .line 171
    .line 172
    const/4 v1, 0x0

    .line 173
    goto :goto_2

    .line 174
    :cond_7
    move v1, v7

    .line 175
    goto :goto_2

    .line 176
    :cond_8
    div-int/lit8 v1, v7, 0x2

    .line 177
    .line 178
    :goto_2
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    iget v3, v0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 183
    .line 184
    add-int/2addr v2, v3

    .line 185
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    sub-int/2addr v4, v3

    .line 190
    sub-int/2addr v4, v6

    .line 191
    iget v3, v0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 192
    .line 193
    sub-int/2addr v4, v3

    .line 194
    invoke-static {p2, v4}, Ljava/lang/Math;->min(II)I

    .line 195
    .line 196
    .line 197
    move-result p2

    .line 198
    invoke-static {v2, p2}, Ljava/lang/Math;->max(II)I

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 203
    .line 204
    .line 205
    move-result v2

    .line 206
    iget v3, v0, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 207
    .line 208
    add-int/2addr v2, v3

    .line 209
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    sub-int/2addr v5, p0

    .line 214
    sub-int/2addr v5, v7

    .line 215
    iget p0, v0, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 216
    .line 217
    sub-int/2addr v5, p0

    .line 218
    invoke-static {v1, v5}, Ljava/lang/Math;->min(II)I

    .line 219
    .line 220
    .line 221
    move-result p0

    .line 222
    invoke-static {v2, p0}, Ljava/lang/Math;->max(II)I

    .line 223
    .line 224
    .line 225
    move-result p0

    .line 226
    add-int/2addr v6, p2

    .line 227
    add-int/2addr v7, p0

    .line 228
    invoke-virtual {p1, p2, p0, v6, v7}, Landroid/view/View;->layout(IIII)V

    .line 229
    .line 230
    .line 231
    return-void

    .line 232
    :cond_9
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 233
    .line 234
    .line 235
    move-result-object p2

    .line 236
    check-cast p2, Ll5/c;

    .line 237
    .line 238
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 239
    .line 240
    .line 241
    move-result-object v9

    .line 242
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 243
    .line 244
    .line 245
    move-result v0

    .line 246
    iget v1, p2, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 247
    .line 248
    add-int/2addr v0, v1

    .line 249
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    iget v4, p2, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 254
    .line 255
    add-int/2addr v1, v4

    .line 256
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 257
    .line 258
    .line 259
    move-result v4

    .line 260
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 261
    .line 262
    .line 263
    move-result v5

    .line 264
    sub-int/2addr v4, v5

    .line 265
    iget v5, p2, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 266
    .line 267
    sub-int/2addr v4, v5

    .line 268
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 269
    .line 270
    .line 271
    move-result v5

    .line 272
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 273
    .line 274
    .line 275
    move-result v6

    .line 276
    sub-int/2addr v5, v6

    .line 277
    iget v6, p2, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 278
    .line 279
    sub-int/2addr v5, v6

    .line 280
    invoke-virtual {v9, v0, v1, v4, v5}, Landroid/graphics/Rect;->set(IIII)V

    .line 281
    .line 282
    .line 283
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 284
    .line 285
    if-eqz v0, :cond_a

    .line 286
    .line 287
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 288
    .line 289
    invoke-virtual {p0}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 290
    .line 291
    .line 292
    move-result v0

    .line 293
    if-eqz v0, :cond_a

    .line 294
    .line 295
    invoke-virtual {p1}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 296
    .line 297
    .line 298
    move-result v0

    .line 299
    if-nez v0, :cond_a

    .line 300
    .line 301
    iget v0, v9, Landroid/graphics/Rect;->left:I

    .line 302
    .line 303
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 304
    .line 305
    invoke-virtual {v1}, Ld6/w1;->b()I

    .line 306
    .line 307
    .line 308
    move-result v1

    .line 309
    add-int/2addr v1, v0

    .line 310
    iput v1, v9, Landroid/graphics/Rect;->left:I

    .line 311
    .line 312
    iget v0, v9, Landroid/graphics/Rect;->top:I

    .line 313
    .line 314
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 315
    .line 316
    invoke-virtual {v1}, Ld6/w1;->d()I

    .line 317
    .line 318
    .line 319
    move-result v1

    .line 320
    add-int/2addr v1, v0

    .line 321
    iput v1, v9, Landroid/graphics/Rect;->top:I

    .line 322
    .line 323
    iget v0, v9, Landroid/graphics/Rect;->right:I

    .line 324
    .line 325
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 326
    .line 327
    invoke-virtual {v1}, Ld6/w1;->c()I

    .line 328
    .line 329
    .line 330
    move-result v1

    .line 331
    sub-int/2addr v0, v1

    .line 332
    iput v0, v9, Landroid/graphics/Rect;->right:I

    .line 333
    .line 334
    iget v0, v9, Landroid/graphics/Rect;->bottom:I

    .line 335
    .line 336
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 337
    .line 338
    invoke-virtual {p0}, Ld6/w1;->a()I

    .line 339
    .line 340
    .line 341
    move-result p0

    .line 342
    sub-int/2addr v0, p0

    .line 343
    iput v0, v9, Landroid/graphics/Rect;->bottom:I

    .line 344
    .line 345
    :cond_a
    invoke-static {}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->a()Landroid/graphics/Rect;

    .line 346
    .line 347
    .line 348
    move-result-object v10

    .line 349
    iget p0, p2, Ll5/c;->c:I

    .line 350
    .line 351
    and-int/lit8 p2, p0, 0x7

    .line 352
    .line 353
    if-nez p2, :cond_b

    .line 354
    .line 355
    const p2, 0x800003

    .line 356
    .line 357
    .line 358
    or-int/2addr p0, p2

    .line 359
    :cond_b
    and-int/lit8 p2, p0, 0x70

    .line 360
    .line 361
    if-nez p2, :cond_c

    .line 362
    .line 363
    or-int/lit8 p0, p0, 0x30

    .line 364
    .line 365
    :cond_c
    move v6, p0

    .line 366
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredWidth()I

    .line 367
    .line 368
    .line 369
    move-result v7

    .line 370
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    .line 371
    .line 372
    .line 373
    move-result v8

    .line 374
    move v11, v3

    .line 375
    invoke-static/range {v6 .. v11}, Landroid/view/Gravity;->apply(IIILandroid/graphics/Rect;Landroid/graphics/Rect;I)V

    .line 376
    .line 377
    .line 378
    iget p0, v10, Landroid/graphics/Rect;->left:I

    .line 379
    .line 380
    iget p2, v10, Landroid/graphics/Rect;->top:I

    .line 381
    .line 382
    iget v0, v10, Landroid/graphics/Rect;->right:I

    .line 383
    .line 384
    iget v1, v10, Landroid/graphics/Rect;->bottom:I

    .line 385
    .line 386
    invoke-virtual {p1, p0, p2, v0, v1}, Landroid/view/View;->layout(IIII)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {v9}, Landroid/graphics/Rect;->setEmpty()V

    .line 390
    .line 391
    .line 392
    invoke-virtual {v2, v9}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    invoke-virtual {v10}, Landroid/graphics/Rect;->setEmpty()V

    .line 396
    .line 397
    .line 398
    invoke-virtual {v2, v10}, Lc6/c;->c(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    return-void
.end method

.method public final r(Landroid/view/MotionEvent;I)Z
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    iget-object v4, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->f:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/view/ViewGroup;->isChildrenDrawingOrderEnabled()Z

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 21
    .line 22
    .line 23
    move-result v6

    .line 24
    add-int/lit8 v7, v6, -0x1

    .line 25
    .line 26
    :goto_0
    if-ltz v7, :cond_1

    .line 27
    .line 28
    if-eqz v5, :cond_0

    .line 29
    .line 30
    invoke-virtual {v0, v6, v7}, Landroid/view/ViewGroup;->getChildDrawingOrder(II)I

    .line 31
    .line 32
    .line 33
    move-result v8

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    move v8, v7

    .line 36
    :goto_1
    invoke-virtual {v0, v8}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 37
    .line 38
    .line 39
    move-result-object v8

    .line 40
    invoke-interface {v4, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    add-int/lit8 v7, v7, -0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    sget-object v5, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->z:La5/f;

    .line 47
    .line 48
    if-eqz v5, :cond_2

    .line 49
    .line 50
    invoke-static {v4, v5}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 51
    .line 52
    .line 53
    :cond_2
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    const/4 v6, 0x0

    .line 58
    const/4 v7, 0x0

    .line 59
    move-object v8, v7

    .line 60
    move v7, v6

    .line 61
    :goto_2
    if-ge v6, v5, :cond_b

    .line 62
    .line 63
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    check-cast v9, Landroid/view/View;

    .line 68
    .line 69
    invoke-virtual {v9}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 70
    .line 71
    .line 72
    move-result-object v10

    .line 73
    check-cast v10, Ll5/c;

    .line 74
    .line 75
    iget-object v10, v10, Ll5/c;->a:Ll5/a;

    .line 76
    .line 77
    const/4 v11, 0x1

    .line 78
    if-nez v7, :cond_3

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_3
    if-eqz v3, :cond_7

    .line 82
    .line 83
    if-eqz v10, :cond_a

    .line 84
    .line 85
    if-nez v8, :cond_4

    .line 86
    .line 87
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 88
    .line 89
    .line 90
    move-result-wide v12

    .line 91
    const/16 v18, 0x0

    .line 92
    .line 93
    const/16 v19, 0x0

    .line 94
    .line 95
    const/16 v16, 0x3

    .line 96
    .line 97
    const/16 v17, 0x0

    .line 98
    .line 99
    move-wide v14, v12

    .line 100
    invoke-static/range {v12 .. v19}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    .line 101
    .line 102
    .line 103
    move-result-object v8

    .line 104
    :cond_4
    if-eqz v2, :cond_6

    .line 105
    .line 106
    if-eq v2, v11, :cond_5

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_5
    invoke-virtual {v10, v9, v8}, Ll5/a;->q(Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 110
    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_6
    invoke-virtual {v10, v0, v9, v8}, Ll5/a;->f(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 114
    .line 115
    .line 116
    goto :goto_5

    .line 117
    :cond_7
    :goto_3
    if-nez v7, :cond_a

    .line 118
    .line 119
    if-eqz v10, :cond_a

    .line 120
    .line 121
    if-eqz v2, :cond_9

    .line 122
    .line 123
    if-eq v2, v11, :cond_8

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_8
    invoke-virtual {v10, v9, v1}, Ll5/a;->q(Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 127
    .line 128
    .line 129
    move-result v7

    .line 130
    goto :goto_4

    .line 131
    :cond_9
    invoke-virtual {v10, v0, v9, v1}, Ll5/a;->f(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 132
    .line 133
    .line 134
    move-result v7

    .line 135
    :goto_4
    if-eqz v7, :cond_a

    .line 136
    .line 137
    iput-object v9, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m:Landroid/view/View;

    .line 138
    .line 139
    :cond_a
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_b
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 143
    .line 144
    .line 145
    return v7
.end method

.method public final requestChildRectangleOnScreen(Landroid/view/View;Landroid/graphics/Rect;Z)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ll5/c;

    .line 6
    .line 7
    iget-object v0, v0, Ll5/c;->a:Ll5/a;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, p0, p1}, Ll5/a;->l(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-super {p0, p1, p2, p3}, Landroid/view/ViewGroup;->requestChildRectangleOnScreen(Landroid/view/View;Landroid/graphics/Rect;Z)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public final requestDisallowInterceptTouchEvent(Z)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->requestDisallowInterceptTouchEvent(Z)V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iget-boolean p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->j:Z

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-virtual {p0, p1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t(Z)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    iput-boolean p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->j:Z

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final s()V
    .locals 15

    .line 1
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->e:Lcom/google/firebase/messaging/w;

    .line 7
    .line 8
    iget-object v2, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v2, Landroidx/collection/a1;

    .line 11
    .line 12
    iget-object v3, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v3, La5/e;

    .line 15
    .line 16
    iget-object v4, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v4, Landroidx/collection/a1;

    .line 19
    .line 20
    invoke-virtual {v2}, Landroidx/collection/a1;->size()I

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    const/4 v6, 0x0

    .line 25
    move v7, v6

    .line 26
    :goto_0
    if-ge v7, v5, :cond_1

    .line 27
    .line 28
    invoke-virtual {v2, v7}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v8

    .line 32
    check-cast v8, Ljava/util/ArrayList;

    .line 33
    .line 34
    if-eqz v8, :cond_0

    .line 35
    .line 36
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v3, v8}, La5/e;->c(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    :cond_0
    add-int/lit8 v7, v7, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-virtual {v2}, Landroidx/collection/a1;->clear()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    move v5, v6

    .line 53
    :goto_1
    if-ge v5, v2, :cond_1b

    .line 54
    .line 55
    invoke-virtual {p0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 56
    .line 57
    .line 58
    move-result-object v7

    .line 59
    invoke-static {v7}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->n(Landroid/view/View;)Ll5/c;

    .line 60
    .line 61
    .line 62
    move-result-object v8

    .line 63
    iget v9, v8, Ll5/c;->f:I

    .line 64
    .line 65
    const/4 v10, -0x1

    .line 66
    const/4 v11, 0x0

    .line 67
    if-ne v9, v10, :cond_2

    .line 68
    .line 69
    iput-object v11, v8, Ll5/c;->l:Landroid/view/View;

    .line 70
    .line 71
    iput-object v11, v8, Ll5/c;->k:Landroid/view/View;

    .line 72
    .line 73
    goto/16 :goto_6

    .line 74
    .line 75
    :cond_2
    iget-object v10, v8, Ll5/c;->k:Landroid/view/View;

    .line 76
    .line 77
    if-eqz v10, :cond_8

    .line 78
    .line 79
    invoke-virtual {v10}, Landroid/view/View;->getId()I

    .line 80
    .line 81
    .line 82
    move-result v10

    .line 83
    if-eq v10, v9, :cond_3

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_3
    iget-object v10, v8, Ll5/c;->k:Landroid/view/View;

    .line 87
    .line 88
    invoke-virtual {v10}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 89
    .line 90
    .line 91
    move-result-object v12

    .line 92
    :goto_2
    if-eq v12, p0, :cond_7

    .line 93
    .line 94
    if-eqz v12, :cond_6

    .line 95
    .line 96
    if-ne v12, v7, :cond_4

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_4
    instance-of v13, v12, Landroid/view/View;

    .line 100
    .line 101
    if-eqz v13, :cond_5

    .line 102
    .line 103
    move-object v10, v12

    .line 104
    check-cast v10, Landroid/view/View;

    .line 105
    .line 106
    :cond_5
    invoke-interface {v12}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    .line 107
    .line 108
    .line 109
    move-result-object v12

    .line 110
    goto :goto_2

    .line 111
    :cond_6
    :goto_3
    iput-object v11, v8, Ll5/c;->l:Landroid/view/View;

    .line 112
    .line 113
    iput-object v11, v8, Ll5/c;->k:Landroid/view/View;

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_7
    iput-object v10, v8, Ll5/c;->l:Landroid/view/View;

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_8
    :goto_4
    invoke-virtual {p0, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 120
    .line 121
    .line 122
    move-result-object v10

    .line 123
    iput-object v10, v8, Ll5/c;->k:Landroid/view/View;

    .line 124
    .line 125
    if-eqz v10, :cond_f

    .line 126
    .line 127
    if-ne v10, p0, :cond_a

    .line 128
    .line 129
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    if-eqz v9, :cond_9

    .line 134
    .line 135
    iput-object v11, v8, Ll5/c;->l:Landroid/view/View;

    .line 136
    .line 137
    iput-object v11, v8, Ll5/c;->k:Landroid/view/View;

    .line 138
    .line 139
    goto :goto_6

    .line 140
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 141
    .line 142
    const-string v0, "View can not be anchored to the the parent CoordinatorLayout"

    .line 143
    .line 144
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0

    .line 148
    :cond_a
    invoke-virtual {v10}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 149
    .line 150
    .line 151
    move-result-object v9

    .line 152
    :goto_5
    if-eq v9, p0, :cond_e

    .line 153
    .line 154
    if-eqz v9, :cond_e

    .line 155
    .line 156
    if-ne v9, v7, :cond_c

    .line 157
    .line 158
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 159
    .line 160
    .line 161
    move-result v9

    .line 162
    if-eqz v9, :cond_b

    .line 163
    .line 164
    iput-object v11, v8, Ll5/c;->l:Landroid/view/View;

    .line 165
    .line 166
    iput-object v11, v8, Ll5/c;->k:Landroid/view/View;

    .line 167
    .line 168
    goto :goto_6

    .line 169
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 170
    .line 171
    const-string v0, "Anchor must not be a descendant of the anchored view"

    .line 172
    .line 173
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    throw p0

    .line 177
    :cond_c
    instance-of v12, v9, Landroid/view/View;

    .line 178
    .line 179
    if-eqz v12, :cond_d

    .line 180
    .line 181
    move-object v10, v9

    .line 182
    check-cast v10, Landroid/view/View;

    .line 183
    .line 184
    :cond_d
    invoke-interface {v9}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    .line 185
    .line 186
    .line 187
    move-result-object v9

    .line 188
    goto :goto_5

    .line 189
    :cond_e
    iput-object v10, v8, Ll5/c;->l:Landroid/view/View;

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_f
    invoke-virtual {p0}, Landroid/view/View;->isInEditMode()Z

    .line 193
    .line 194
    .line 195
    move-result v10

    .line 196
    if-eqz v10, :cond_1a

    .line 197
    .line 198
    iput-object v11, v8, Ll5/c;->l:Landroid/view/View;

    .line 199
    .line 200
    iput-object v11, v8, Ll5/c;->k:Landroid/view/View;

    .line 201
    .line 202
    :goto_6
    invoke-virtual {v4, v7}, Landroidx/collection/a1;->containsKey(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v9

    .line 206
    if-nez v9, :cond_10

    .line 207
    .line 208
    invoke-virtual {v4, v7, v11}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    :cond_10
    move v9, v6

    .line 212
    :goto_7
    if-ge v9, v2, :cond_19

    .line 213
    .line 214
    if-ne v9, v5, :cond_11

    .line 215
    .line 216
    goto :goto_9

    .line 217
    :cond_11
    invoke-virtual {p0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 218
    .line 219
    .line 220
    move-result-object v10

    .line 221
    iget-object v12, v8, Ll5/c;->l:Landroid/view/View;

    .line 222
    .line 223
    if-eq v10, v12, :cond_13

    .line 224
    .line 225
    sget-object v12, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 226
    .line 227
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 228
    .line 229
    .line 230
    move-result v12

    .line 231
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 232
    .line 233
    .line 234
    move-result-object v13

    .line 235
    check-cast v13, Ll5/c;

    .line 236
    .line 237
    iget v13, v13, Ll5/c;->g:I

    .line 238
    .line 239
    invoke-static {v13, v12}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 240
    .line 241
    .line 242
    move-result v13

    .line 243
    if-eqz v13, :cond_12

    .line 244
    .line 245
    iget v14, v8, Ll5/c;->h:I

    .line 246
    .line 247
    invoke-static {v14, v12}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 248
    .line 249
    .line 250
    move-result v12

    .line 251
    and-int/2addr v12, v13

    .line 252
    if-ne v12, v13, :cond_12

    .line 253
    .line 254
    goto :goto_8

    .line 255
    :cond_12
    iget-object v10, v8, Ll5/c;->a:Ll5/a;

    .line 256
    .line 257
    if-eqz v10, :cond_17

    .line 258
    .line 259
    invoke-virtual {v10, v7}, Ll5/a;->b(Landroid/view/View;)V

    .line 260
    .line 261
    .line 262
    goto :goto_9

    .line 263
    :cond_13
    :goto_8
    invoke-virtual {v4, v10}, Landroidx/collection/a1;->containsKey(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result v12

    .line 267
    if-nez v12, :cond_14

    .line 268
    .line 269
    invoke-virtual {v4, v10}, Landroidx/collection/a1;->containsKey(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result v12

    .line 273
    if-nez v12, :cond_14

    .line 274
    .line 275
    invoke-virtual {v4, v10, v11}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    :cond_14
    invoke-virtual {v4, v10}, Landroidx/collection/a1;->containsKey(Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    move-result v12

    .line 282
    if-eqz v12, :cond_18

    .line 283
    .line 284
    invoke-virtual {v4, v7}, Landroidx/collection/a1;->containsKey(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v12

    .line 288
    if-eqz v12, :cond_18

    .line 289
    .line 290
    invoke-virtual {v4, v10}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v12

    .line 294
    check-cast v12, Ljava/util/ArrayList;

    .line 295
    .line 296
    if-nez v12, :cond_16

    .line 297
    .line 298
    invoke-virtual {v3}, La5/e;->a()Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v12

    .line 302
    check-cast v12, Ljava/util/ArrayList;

    .line 303
    .line 304
    if-nez v12, :cond_15

    .line 305
    .line 306
    new-instance v12, Ljava/util/ArrayList;

    .line 307
    .line 308
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 309
    .line 310
    .line 311
    :cond_15
    invoke-virtual {v4, v10, v12}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    :cond_16
    invoke-virtual {v12, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 315
    .line 316
    .line 317
    :cond_17
    :goto_9
    add-int/lit8 v9, v9, 0x1

    .line 318
    .line 319
    goto :goto_7

    .line 320
    :cond_18
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 321
    .line 322
    const-string v0, "All nodes must be present in the graph before being added as an edge"

    .line 323
    .line 324
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw p0

    .line 328
    :cond_19
    add-int/lit8 v5, v5, 0x1

    .line 329
    .line 330
    goto/16 :goto_1

    .line 331
    .line 332
    :cond_1a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 333
    .line 334
    new-instance v1, Ljava/lang/StringBuilder;

    .line 335
    .line 336
    const-string v2, "Could not find CoordinatorLayout descendant view with id "

    .line 337
    .line 338
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 342
    .line 343
    .line 344
    move-result-object p0

    .line 345
    invoke-virtual {p0, v9}, Landroid/content/res/Resources;->getResourceName(I)Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object p0

    .line 349
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 350
    .line 351
    .line 352
    const-string p0, " to anchor view "

    .line 353
    .line 354
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 355
    .line 356
    .line 357
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 358
    .line 359
    .line 360
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object p0

    .line 364
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    throw v0

    .line 368
    :cond_1b
    iget-object p0, v1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 369
    .line 370
    check-cast p0, Ljava/util/ArrayList;

    .line 371
    .line 372
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 373
    .line 374
    .line 375
    iget-object v2, v1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 376
    .line 377
    check-cast v2, Ljava/util/HashSet;

    .line 378
    .line 379
    invoke-virtual {v2}, Ljava/util/HashSet;->clear()V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v4}, Landroidx/collection/a1;->size()I

    .line 383
    .line 384
    .line 385
    move-result v3

    .line 386
    :goto_a
    if-ge v6, v3, :cond_1c

    .line 387
    .line 388
    invoke-virtual {v4, v6}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v5

    .line 392
    invoke-virtual {v1, v5, p0, v2}, Lcom/google/firebase/messaging/w;->e(Ljava/lang/Object;Ljava/util/ArrayList;Ljava/util/HashSet;)V

    .line 393
    .line 394
    .line 395
    add-int/lit8 v6, v6, 0x1

    .line 396
    .line 397
    goto :goto_a

    .line 398
    :cond_1c
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 399
    .line 400
    .line 401
    invoke-static {v0}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 402
    .line 403
    .line 404
    return-void
.end method

.method public setFitsSystemWindows(Z)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->setFitsSystemWindows(Z)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->w()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public setOnHierarchyChangeListener(Landroid/view/ViewGroup$OnHierarchyChangeListener;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->t:Landroid/view/ViewGroup$OnHierarchyChangeListener;

    .line 2
    .line 3
    return-void
.end method

.method public setStatusBarBackground(Landroid/graphics/drawable/Drawable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    if-eq v0, p1, :cond_5

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->setCallback(Landroid/graphics/drawable/Drawable$Callback;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    if-eqz p1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :cond_1
    iput-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 18
    .line 19
    if-eqz v1, :cond_4

    .line 20
    .line 21
    invoke-virtual {v1}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-eqz p1, :cond_2

    .line 26
    .line 27
    iget-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 28
    .line 29
    invoke-virtual {p0}, Landroid/view/View;->getDrawableState()[I

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 34
    .line 35
    .line 36
    :cond_2
    iget-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 37
    .line 38
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 39
    .line 40
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setLayoutDirection(I)Z

    .line 45
    .line 46
    .line 47
    iget-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 48
    .line 49
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    const/4 v1, 0x0

    .line 54
    if-nez v0, :cond_3

    .line 55
    .line 56
    const/4 v0, 0x1

    .line 57
    goto :goto_0

    .line 58
    :cond_3
    move v0, v1

    .line 59
    :goto_0
    invoke-virtual {p1, v0, v1}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 63
    .line 64
    invoke-virtual {p1, p0}, Landroid/graphics/drawable/Drawable;->setCallback(Landroid/graphics/drawable/Drawable$Callback;)V

    .line 65
    .line 66
    .line 67
    :cond_4
    sget-object p1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 68
    .line 69
    invoke-virtual {p0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 70
    .line 71
    .line 72
    :cond_5
    return-void
.end method

.method public setStatusBarBackgroundColor(I)V
    .locals 1

    .line 1
    new-instance v0, Landroid/graphics/drawable/ColorDrawable;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroid/graphics/drawable/ColorDrawable;-><init>(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->setStatusBarBackground(Landroid/graphics/drawable/Drawable;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public setStatusBarBackgroundResource(I)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p1}, Landroid/content/Context;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p1, 0x0

    .line 13
    :goto_0
    invoke-virtual {p0, p1}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->setStatusBarBackground(Landroid/graphics/drawable/Drawable;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setVisibility(I)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->setVisibility(I)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move p1, v0

    .line 10
    :goto_0
    iget-object v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 11
    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {v1}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eq v1, p1, :cond_1

    .line 19
    .line 20
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 21
    .line 22
    invoke-virtual {p0, p1, v0}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 23
    .line 24
    .line 25
    :cond_1
    return-void
.end method

.method public final t(Z)V
    .locals 13

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    if-ge v2, v0, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-virtual {v3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    check-cast v4, Ll5/c;

    .line 18
    .line 19
    iget-object v4, v4, Ll5/c;->a:Ll5/a;

    .line 20
    .line 21
    if-eqz v4, :cond_1

    .line 22
    .line 23
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 24
    .line 25
    .line 26
    move-result-wide v5

    .line 27
    const/4 v11, 0x0

    .line 28
    const/4 v12, 0x0

    .line 29
    const/4 v9, 0x3

    .line 30
    const/4 v10, 0x0

    .line 31
    move-wide v7, v5

    .line 32
    invoke-static/range {v5 .. v12}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    if-eqz p1, :cond_0

    .line 37
    .line 38
    invoke-virtual {v4, p0, v3, v5}, Ll5/a;->f(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_0
    invoke-virtual {v4, v3, v5}, Ll5/a;->q(Landroid/view/View;Landroid/view/MotionEvent;)Z

    .line 43
    .line 44
    .line 45
    :goto_1
    invoke-virtual {v5}, Landroid/view/MotionEvent;->recycle()V

    .line 46
    .line 47
    .line 48
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    move p1, v1

    .line 52
    :goto_2
    if-ge p1, v0, :cond_3

    .line 53
    .line 54
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Ll5/c;

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    add-int/lit8 p1, p1, 0x1

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    const/4 p1, 0x0

    .line 71
    iput-object p1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->m:Landroid/view/View;

    .line 72
    .line 73
    iput-boolean v1, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->j:Z

    .line 74
    .line 75
    return-void
.end method

.method public final verifyDrawable(Landroid/graphics/drawable/Drawable;)Z
    .locals 1

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->verifyDrawable(Landroid/graphics/drawable/Drawable;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->s:Landroid/graphics/drawable/Drawable;

    .line 8
    .line 9
    if-ne p1, p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public final w()V
    .locals 2

    .line 1
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u:Lh6/e;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    new-instance v0, Lh6/e;

    .line 14
    .line 15
    const/16 v1, 0x10

    .line 16
    .line 17
    invoke-direct {v0, p0, v1}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u:Lh6/e;

    .line 21
    .line 22
    :cond_0
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->u:Lh6/e;

    .line 23
    .line 24
    invoke-static {p0, v0}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 25
    .line 26
    .line 27
    const/16 v0, 0x500

    .line 28
    .line 29
    invoke-virtual {p0, v0}, Landroid/view/View;->setSystemUiVisibility(I)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    const/4 v0, 0x0

    .line 34
    invoke-static {p0, v0}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
