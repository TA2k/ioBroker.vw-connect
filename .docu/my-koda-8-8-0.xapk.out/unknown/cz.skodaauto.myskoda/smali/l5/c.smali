.class public final Ll5/c;
.super Landroid/view/ViewGroup$MarginLayoutParams;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ll5/a;

.field public b:Z

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I

.field public final g:I

.field public h:I

.field public i:I

.field public j:I

.field public k:Landroid/view/View;

.field public l:Landroid/view/View;

.field public m:Z

.field public n:Z

.field public final o:Landroid/graphics/Rect;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, -0x2

    .line 1
    invoke-direct {p0, v0, v0}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(II)V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Ll5/c;->b:Z

    .line 3
    iput v0, p0, Ll5/c;->c:I

    .line 4
    iput v0, p0, Ll5/c;->d:I

    const/4 v1, -0x1

    .line 5
    iput v1, p0, Ll5/c;->e:I

    .line 6
    iput v1, p0, Ll5/c;->f:I

    .line 7
    iput v0, p0, Ll5/c;->g:I

    .line 8
    iput v0, p0, Ll5/c;->h:I

    .line 9
    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    iput-object v0, p0, Ll5/c;->o:Landroid/graphics/Rect;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 7

    .line 10
    invoke-direct {p0, p1, p2}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    const/4 v0, 0x0

    .line 11
    iput-boolean v0, p0, Ll5/c;->b:Z

    .line 12
    iput v0, p0, Ll5/c;->c:I

    .line 13
    iput v0, p0, Ll5/c;->d:I

    const/4 v1, -0x1

    .line 14
    iput v1, p0, Ll5/c;->e:I

    .line 15
    iput v1, p0, Ll5/c;->f:I

    .line 16
    iput v0, p0, Ll5/c;->g:I

    .line 17
    iput v0, p0, Ll5/c;->h:I

    .line 18
    new-instance v2, Landroid/graphics/Rect;

    invoke-direct {v2}, Landroid/graphics/Rect;-><init>()V

    iput-object v2, p0, Ll5/c;->o:Landroid/graphics/Rect;

    .line 19
    sget-object v2, Lk5/a;->b:[I

    invoke-virtual {p1, p2, v2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v2

    .line 20
    invoke-virtual {v2, v0, v0}, Landroid/content/res/TypedArray;->getInteger(II)I

    move-result v3

    iput v3, p0, Ll5/c;->c:I

    const/4 v3, 0x1

    .line 21
    invoke-virtual {v2, v3, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v4

    iput v4, p0, Ll5/c;->f:I

    const/4 v4, 0x2

    .line 22
    invoke-virtual {v2, v4, v0}, Landroid/content/res/TypedArray;->getInteger(II)I

    move-result v4

    iput v4, p0, Ll5/c;->d:I

    const/4 v4, 0x6

    .line 23
    invoke-virtual {v2, v4, v1}, Landroid/content/res/TypedArray;->getInteger(II)I

    move-result v1

    iput v1, p0, Ll5/c;->e:I

    const/4 v1, 0x5

    .line 24
    invoke-virtual {v2, v1, v0}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v1

    iput v1, p0, Ll5/c;->g:I

    const/4 v1, 0x4

    .line 25
    invoke-virtual {v2, v1, v0}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v1

    iput v1, p0, Ll5/c;->h:I

    const/4 v1, 0x3

    .line 26
    invoke-virtual {v2, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v4

    iput-boolean v4, p0, Ll5/c;->b:Z

    if-eqz v4, :cond_6

    .line 27
    invoke-virtual {v2, v1}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v1

    sget-object v4, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->w:Ljava/lang/String;

    .line 28
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 p1, 0x0

    goto/16 :goto_2

    .line 29
    :cond_0
    const-string v4, "."

    invoke-virtual {v1, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_1

    .line 30
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_1
    const/16 v4, 0x2e

    .line 31
    invoke-virtual {v1, v4}, Ljava/lang/String;->indexOf(I)I

    move-result v5

    if-ltz v5, :cond_2

    goto :goto_0

    .line 32
    :cond_2
    sget-object v5, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->w:Ljava/lang/String;

    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v6

    if-nez v6, :cond_3

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 33
    :cond_3
    :goto_0
    :try_start_0
    sget-object v4, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->y:Ljava/lang/ThreadLocal;

    invoke-virtual {v4}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/Map;

    if-nez v5, :cond_4

    .line 34
    new-instance v5, Ljava/util/HashMap;

    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 35
    invoke-virtual {v4, v5}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    goto :goto_1

    :catch_0
    move-exception p0

    goto :goto_3

    .line 36
    :cond_4
    :goto_1
    invoke-interface {v5, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Constructor;

    if-nez v4, :cond_5

    .line 37
    invoke-virtual {p1}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v4

    invoke-static {v1, v0, v4}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    move-result-object v0

    .line 38
    sget-object v4, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->x:[Ljava/lang/Class;

    invoke-virtual {v0, v4}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v4

    .line 39
    invoke-virtual {v4, v3}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 40
    invoke-interface {v5, v1, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    :cond_5
    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v4, p1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ll5/a;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    :goto_2
    iput-object p1, p0, Ll5/c;->a:Ll5/a;

    goto :goto_4

    .line 43
    :goto_3
    new-instance p1, Ljava/lang/RuntimeException;

    const-string p2, "Could not inflate Behavior subclass "

    .line 44
    invoke-static {p2, v1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 45
    invoke-direct {p1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1

    .line 46
    :cond_6
    :goto_4
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 47
    iget-object p1, p0, Ll5/c;->a:Ll5/a;

    if-eqz p1, :cond_7

    .line 48
    invoke-virtual {p1, p0}, Ll5/a;->c(Ll5/c;)V

    :cond_7
    return-void
.end method

.method public constructor <init>(Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    .line 71
    invoke-direct {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    const/4 p1, 0x0

    .line 72
    iput-boolean p1, p0, Ll5/c;->b:Z

    .line 73
    iput p1, p0, Ll5/c;->c:I

    .line 74
    iput p1, p0, Ll5/c;->d:I

    const/4 v0, -0x1

    .line 75
    iput v0, p0, Ll5/c;->e:I

    .line 76
    iput v0, p0, Ll5/c;->f:I

    .line 77
    iput p1, p0, Ll5/c;->g:I

    .line 78
    iput p1, p0, Ll5/c;->h:I

    .line 79
    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    iput-object p1, p0, Ll5/c;->o:Landroid/graphics/Rect;

    return-void
.end method

.method public constructor <init>(Landroid/view/ViewGroup$MarginLayoutParams;)V
    .locals 1

    .line 62
    invoke-direct {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    const/4 p1, 0x0

    .line 63
    iput-boolean p1, p0, Ll5/c;->b:Z

    .line 64
    iput p1, p0, Ll5/c;->c:I

    .line 65
    iput p1, p0, Ll5/c;->d:I

    const/4 v0, -0x1

    .line 66
    iput v0, p0, Ll5/c;->e:I

    .line 67
    iput v0, p0, Ll5/c;->f:I

    .line 68
    iput p1, p0, Ll5/c;->g:I

    .line 69
    iput p1, p0, Ll5/c;->h:I

    .line 70
    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    iput-object p1, p0, Ll5/c;->o:Landroid/graphics/Rect;

    return-void
.end method

.method public constructor <init>(Ll5/c;)V
    .locals 1

    .line 53
    invoke-direct {p0, p1}, Landroid/view/ViewGroup$MarginLayoutParams;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    const/4 p1, 0x0

    .line 54
    iput-boolean p1, p0, Ll5/c;->b:Z

    .line 55
    iput p1, p0, Ll5/c;->c:I

    .line 56
    iput p1, p0, Ll5/c;->d:I

    const/4 v0, -0x1

    .line 57
    iput v0, p0, Ll5/c;->e:I

    .line 58
    iput v0, p0, Ll5/c;->f:I

    .line 59
    iput p1, p0, Ll5/c;->g:I

    .line 60
    iput p1, p0, Ll5/c;->h:I

    .line 61
    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    iput-object p1, p0, Ll5/c;->o:Landroid/graphics/Rect;

    return-void
.end method


# virtual methods
.method public final a(I)Z
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p1, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :cond_0
    iget-boolean p0, p0, Ll5/c;->n:Z

    .line 9
    .line 10
    return p0

    .line 11
    :cond_1
    iget-boolean p0, p0, Ll5/c;->m:Z

    .line 12
    .line 13
    return p0
.end method
