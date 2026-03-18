.class public Ld6/l1;
.super Ld6/s1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static i:Z = false

.field public static j:Ljava/lang/reflect/Method;

.field public static k:Ljava/lang/Class;

.field public static l:Ljava/lang/reflect/Field;

.field public static m:Ljava/lang/reflect/Field;


# instance fields
.field public final c:Landroid/view/WindowInsets;

.field public d:[Ls5/b;

.field public e:Ls5/b;

.field public f:Ld6/w1;

.field public g:Ls5/b;

.field public h:I


# direct methods
.method public constructor <init>(Ld6/w1;Landroid/view/WindowInsets;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ld6/s1;-><init>(Ld6/w1;)V

    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Ld6/l1;->e:Ls5/b;

    .line 3
    iput-object p2, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    return-void
.end method

.method public constructor <init>(Ld6/w1;Ld6/l1;)V
    .locals 1

    .line 4
    new-instance v0, Landroid/view/WindowInsets;

    iget-object p2, p2, Ld6/l1;->c:Landroid/view/WindowInsets;

    invoke-direct {v0, p2}, Landroid/view/WindowInsets;-><init>(Landroid/view/WindowInsets;)V

    invoke-direct {p0, p1, v0}, Ld6/l1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    return-void
.end method

.method private static A()V
    .locals 4
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "PrivateApi"
        }
    .end annotation

    .line 1
    const/4 v0, 0x1

    .line 2
    :try_start_0
    const-class v1, Landroid/view/View;

    .line 3
    .line 4
    const-string v2, "getViewRootImpl"

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    sput-object v1, Ld6/l1;->j:Ljava/lang/reflect/Method;

    .line 12
    .line 13
    const-string v1, "android.view.View$AttachInfo"

    .line 14
    .line 15
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sput-object v1, Ld6/l1;->k:Ljava/lang/Class;

    .line 20
    .line 21
    const-string v2, "mVisibleInsets"

    .line 22
    .line 23
    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    sput-object v1, Ld6/l1;->l:Ljava/lang/reflect/Field;

    .line 28
    .line 29
    const-string v1, "android.view.ViewRootImpl"

    .line 30
    .line 31
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    const-string v2, "mAttachInfo"

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    sput-object v1, Ld6/l1;->m:Ljava/lang/reflect/Field;

    .line 42
    .line 43
    sget-object v1, Ld6/l1;->l:Ljava/lang/reflect/Field;

    .line 44
    .line 45
    invoke-virtual {v1, v0}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 46
    .line 47
    .line 48
    sget-object v1, Ld6/l1;->m:Ljava/lang/reflect/Field;

    .line 49
    .line 50
    invoke-virtual {v1, v0}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_0
    .catch Ljava/lang/ReflectiveOperationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :catch_0
    move-exception v1

    .line 55
    new-instance v2, Ljava/lang/StringBuilder;

    .line 56
    .line 57
    const-string v3, "Failed to get visible insets. (Reflection error). "

    .line 58
    .line 59
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    const-string v3, "WindowInsetsCompat"

    .line 74
    .line 75
    invoke-static {v3, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 76
    .line 77
    .line 78
    :goto_0
    sput-boolean v0, Ld6/l1;->i:Z

    .line 79
    .line 80
    return-void
.end method

.method public static B(II)Z
    .locals 0

    .line 1
    and-int/lit8 p0, p0, 0x6

    .line 2
    .line 3
    and-int/lit8 p1, p1, 0x6

    .line 4
    .line 5
    if-ne p0, p1, :cond_0

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

.method private v(IZ)Ls5/b;
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "WrongConstant"
        }
    .end annotation

    .line 1
    sget-object v0, Ls5/b;->e:Ls5/b;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    :goto_0
    const/16 v2, 0x200

    .line 5
    .line 6
    if-gt v1, v2, :cond_1

    .line 7
    .line 8
    and-int v2, p1, v1

    .line 9
    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-virtual {p0, v1, p2}, Ld6/l1;->w(IZ)Ls5/b;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-static {v0, v2}, Ls5/b;->a(Ls5/b;Ls5/b;)Ls5/b;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :goto_1
    shl-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    return-object v0
.end method

.method private x()Ls5/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->f:Ld6/w1;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 6
    .line 7
    invoke-virtual {p0}, Ld6/s1;->j()Ls5/b;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Ls5/b;->e:Ls5/b;

    .line 13
    .line 14
    return-object p0
.end method

.method private y(Landroid/view/View;)Ls5/b;
    .locals 4

    .line 1
    const-string p0, "WindowInsetsCompat"

    .line 2
    .line 3
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 4
    .line 5
    const/16 v1, 0x1e

    .line 6
    .line 7
    if-ge v0, v1, :cond_4

    .line 8
    .line 9
    sget-boolean v0, Ld6/l1;->i:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Ld6/l1;->A()V

    .line 14
    .line 15
    .line 16
    :cond_0
    sget-object v0, Ld6/l1;->j:Ljava/lang/reflect/Method;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v0, :cond_3

    .line 20
    .line 21
    sget-object v2, Ld6/l1;->k:Ljava/lang/Class;

    .line 22
    .line 23
    if-eqz v2, :cond_3

    .line 24
    .line 25
    sget-object v2, Ld6/l1;->l:Ljava/lang/reflect/Field;

    .line 26
    .line 27
    if-nez v2, :cond_1

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    :try_start_0
    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    if-nez p1, :cond_2

    .line 35
    .line 36
    const-string p1, "Failed to get visible insets. getViewRootImpl() returned null from the provided view. This means that the view is either not attached or the method has been overridden"

    .line 37
    .line 38
    new-instance v0, Ljava/lang/NullPointerException;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/lang/NullPointerException;-><init>()V

    .line 41
    .line 42
    .line 43
    invoke-static {p0, p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 44
    .line 45
    .line 46
    return-object v1

    .line 47
    :catch_0
    move-exception p1

    .line 48
    goto :goto_0

    .line 49
    :cond_2
    sget-object v0, Ld6/l1;->m:Ljava/lang/reflect/Field;

    .line 50
    .line 51
    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    sget-object v0, Ld6/l1;->l:Ljava/lang/reflect/Field;

    .line 56
    .line 57
    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    check-cast p1, Landroid/graphics/Rect;

    .line 62
    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    iget v0, p1, Landroid/graphics/Rect;->left:I

    .line 66
    .line 67
    iget v2, p1, Landroid/graphics/Rect;->top:I

    .line 68
    .line 69
    iget v3, p1, Landroid/graphics/Rect;->right:I

    .line 70
    .line 71
    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    .line 72
    .line 73
    invoke-static {v0, v2, v3, p1}, Ls5/b;->b(IIII)Ls5/b;

    .line 74
    .line 75
    .line 76
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/ReflectiveOperationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 77
    return-object p0

    .line 78
    :goto_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    const-string v2, "Failed to get visible insets. (Reflection error). "

    .line 81
    .line 82
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-static {p0, v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 97
    .line 98
    .line 99
    :cond_3
    :goto_1
    return-object v1

    .line 100
    :cond_4
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 101
    .line 102
    const-string p1, "getVisibleInsets() should not be called on API >= 30. Use WindowInsets.isVisible() instead."

    .line 103
    .line 104
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    throw p0
.end method


# virtual methods
.method public d(Landroid/view/View;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ld6/l1;->y(Landroid/view/View;)Ls5/b;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    sget-object p1, Ls5/b;->e:Ls5/b;

    .line 8
    .line 9
    :cond_0
    invoke-virtual {p0, p1}, Ld6/l1;->s(Ls5/b;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public e(Ld6/w1;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ld6/l1;->f:Ld6/w1;

    .line 2
    .line 3
    iget-object v1, p1, Ld6/w1;->a:Ld6/s1;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Ld6/s1;->t(Ld6/w1;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Ld6/l1;->g:Ls5/b;

    .line 9
    .line 10
    iget-object p1, p1, Ld6/w1;->a:Ld6/s1;

    .line 11
    .line 12
    invoke-virtual {p1, v0}, Ld6/s1;->s(Ls5/b;)V

    .line 13
    .line 14
    .line 15
    iget p0, p0, Ld6/l1;->h:I

    .line 16
    .line 17
    invoke-virtual {p1, p0}, Ld6/s1;->u(I)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    invoke-super {p0, p1}, Ld6/s1;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    check-cast p1, Ld6/l1;

    .line 10
    .line 11
    iget-object v0, p0, Ld6/l1;->g:Ls5/b;

    .line 12
    .line 13
    iget-object v2, p1, Ld6/l1;->g:Ls5/b;

    .line 14
    .line 15
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iget p0, p0, Ld6/l1;->h:I

    .line 22
    .line 23
    iget p1, p1, Ld6/l1;->h:I

    .line 24
    .line 25
    invoke-static {p0, p1}, Ld6/l1;->B(II)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    if-eqz p0, :cond_1

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_1
    return v1
.end method

.method public g(I)Ls5/b;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Ld6/l1;->v(IZ)Ls5/b;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public h(I)Ls5/b;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, v0}, Ld6/l1;->v(IZ)Ls5/b;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public final l()Ls5/b;
    .locals 4

    .line 1
    iget-object v0, p0, Ld6/l1;->e:Ls5/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getSystemWindowInsetLeft()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getSystemWindowInsetTop()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getSystemWindowInsetRight()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getSystemWindowInsetBottom()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-static {v1, v2, v3, v0}, Ls5/b;->b(IIII)Ls5/b;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iput-object v0, p0, Ld6/l1;->e:Ls5/b;

    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Ld6/l1;->e:Ls5/b;

    .line 30
    .line 31
    return-object p0
.end method

.method public n(IIII)Ld6/w1;
    .locals 3

    .line 1
    iget-object v0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1, v0}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v2, 0x22

    .line 11
    .line 12
    if-lt v1, v2, :cond_0

    .line 13
    .line 14
    new-instance v1, Ld6/j1;

    .line 15
    .line 16
    invoke-direct {v1, v0}, Ld6/j1;-><init>(Ld6/w1;)V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/16 v2, 0x1f

    .line 21
    .line 22
    if-lt v1, v2, :cond_1

    .line 23
    .line 24
    new-instance v1, Ld6/i1;

    .line 25
    .line 26
    invoke-direct {v1, v0}, Ld6/i1;-><init>(Ld6/w1;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/16 v2, 0x1e

    .line 31
    .line 32
    if-lt v1, v2, :cond_2

    .line 33
    .line 34
    new-instance v1, Ld6/h1;

    .line 35
    .line 36
    invoke-direct {v1, v0}, Ld6/h1;-><init>(Ld6/w1;)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    new-instance v1, Ld6/g1;

    .line 41
    .line 42
    invoke-direct {v1, v0}, Ld6/g1;-><init>(Ld6/w1;)V

    .line 43
    .line 44
    .line 45
    :goto_0
    invoke-virtual {p0}, Ld6/l1;->l()Ls5/b;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {v0, p1, p2, p3, p4}, Ld6/w1;->f(Ls5/b;IIII)Ls5/b;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-virtual {v1, v0}, Ld6/k1;->g(Ls5/b;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Ld6/s1;->j()Ls5/b;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-static {p0, p1, p2, p3, p4}, Ld6/w1;->f(Ls5/b;IIII)Ls5/b;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {v1, p0}, Ld6/k1;->e(Ls5/b;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v1}, Ld6/k1;->b()Ld6/w1;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method

.method public p()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/WindowInsets;->isRound()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public q(I)Z
    .locals 3
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "WrongConstant"
        }
    .end annotation

    .line 1
    const/4 v0, 0x1

    .line 2
    move v1, v0

    .line 3
    :goto_0
    const/16 v2, 0x200

    .line 4
    .line 5
    if-gt v1, v2, :cond_2

    .line 6
    .line 7
    and-int v2, p1, v1

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    invoke-virtual {p0, v1}, Ld6/l1;->z(I)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_1
    shl-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_2
    return v0
.end method

.method public r([Ls5/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ld6/l1;->d:[Ls5/b;

    .line 2
    .line 3
    return-void
.end method

.method public s(Ls5/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ld6/l1;->g:Ls5/b;

    .line 2
    .line 3
    return-void
.end method

.method public t(Ld6/w1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ld6/l1;->f:Ld6/w1;

    .line 2
    .line 3
    return-void
.end method

.method public u(I)V
    .locals 0

    .line 1
    iput p1, p0, Ld6/l1;->h:I

    .line 2
    .line 3
    return-void
.end method

.method public w(IZ)Ls5/b;
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    sget-object v1, Ls5/b;->e:Ls5/b;

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    if-eq p1, v0, :cond_10

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    const/4 v3, 0x2

    .line 9
    if-eq p1, v3, :cond_b

    .line 10
    .line 11
    const/16 p2, 0x8

    .line 12
    .line 13
    if-eq p1, p2, :cond_6

    .line 14
    .line 15
    const/16 p2, 0x10

    .line 16
    .line 17
    if-eq p1, p2, :cond_5

    .line 18
    .line 19
    const/16 p2, 0x20

    .line 20
    .line 21
    if-eq p1, p2, :cond_4

    .line 22
    .line 23
    const/16 p2, 0x40

    .line 24
    .line 25
    if-eq p1, p2, :cond_3

    .line 26
    .line 27
    const/16 p2, 0x80

    .line 28
    .line 29
    if-eq p1, p2, :cond_0

    .line 30
    .line 31
    return-object v1

    .line 32
    :cond_0
    iget-object p1, p0, Ld6/l1;->f:Ld6/w1;

    .line 33
    .line 34
    if-eqz p1, :cond_1

    .line 35
    .line 36
    iget-object p0, p1, Ld6/w1;->a:Ld6/s1;

    .line 37
    .line 38
    invoke-virtual {p0}, Ld6/s1;->f()Ld6/i;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    invoke-virtual {p0}, Ld6/s1;->f()Ld6/i;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    :goto_0
    if-eqz p0, :cond_2

    .line 48
    .line 49
    iget-object p0, p0, Ld6/i;->a:Landroid/view/DisplayCutout;

    .line 50
    .line 51
    invoke-virtual {p0}, Landroid/view/DisplayCutout;->getSafeInsetLeft()I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    invoke-virtual {p0}, Landroid/view/DisplayCutout;->getSafeInsetTop()I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    invoke-virtual {p0}, Landroid/view/DisplayCutout;->getSafeInsetRight()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    invoke-virtual {p0}, Landroid/view/DisplayCutout;->getSafeInsetBottom()I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    invoke-static {p1, p2, v0, p0}, Ls5/b;->b(IIII)Ls5/b;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :cond_2
    return-object v1

    .line 73
    :cond_3
    invoke-virtual {p0}, Ld6/s1;->m()Ls5/b;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :cond_4
    invoke-virtual {p0}, Ld6/s1;->i()Ls5/b;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :cond_5
    invoke-virtual {p0}, Ld6/s1;->k()Ls5/b;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :cond_6
    iget-object p1, p0, Ld6/l1;->d:[Ls5/b;

    .line 89
    .line 90
    if-eqz p1, :cond_7

    .line 91
    .line 92
    invoke-static {p2}, Ljp/qf;->c(I)I

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    aget-object v0, p1, p2

    .line 97
    .line 98
    :cond_7
    if-eqz v0, :cond_8

    .line 99
    .line 100
    return-object v0

    .line 101
    :cond_8
    invoke-virtual {p0}, Ld6/l1;->l()Ls5/b;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-direct {p0}, Ld6/l1;->x()Ls5/b;

    .line 106
    .line 107
    .line 108
    move-result-object p2

    .line 109
    iget p1, p1, Ls5/b;->d:I

    .line 110
    .line 111
    iget v0, p2, Ls5/b;->d:I

    .line 112
    .line 113
    if-le p1, v0, :cond_9

    .line 114
    .line 115
    invoke-static {v2, v2, v2, p1}, Ls5/b;->b(IIII)Ls5/b;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0

    .line 120
    :cond_9
    iget-object p1, p0, Ld6/l1;->g:Ls5/b;

    .line 121
    .line 122
    if-eqz p1, :cond_a

    .line 123
    .line 124
    invoke-virtual {p1, v1}, Ls5/b;->equals(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    if-nez p1, :cond_a

    .line 129
    .line 130
    iget-object p0, p0, Ld6/l1;->g:Ls5/b;

    .line 131
    .line 132
    iget p0, p0, Ls5/b;->d:I

    .line 133
    .line 134
    iget p1, p2, Ls5/b;->d:I

    .line 135
    .line 136
    if-le p0, p1, :cond_a

    .line 137
    .line 138
    invoke-static {v2, v2, v2, p0}, Ls5/b;->b(IIII)Ls5/b;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0

    .line 143
    :cond_a
    return-object v1

    .line 144
    :cond_b
    if-eqz p2, :cond_c

    .line 145
    .line 146
    invoke-direct {p0}, Ld6/l1;->x()Ls5/b;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    invoke-virtual {p0}, Ld6/s1;->j()Ls5/b;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    iget p2, p1, Ls5/b;->a:I

    .line 155
    .line 156
    iget v0, p0, Ls5/b;->a:I

    .line 157
    .line 158
    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    .line 159
    .line 160
    .line 161
    move-result p2

    .line 162
    iget v0, p1, Ls5/b;->c:I

    .line 163
    .line 164
    iget v1, p0, Ls5/b;->c:I

    .line 165
    .line 166
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    iget p1, p1, Ls5/b;->d:I

    .line 171
    .line 172
    iget p0, p0, Ls5/b;->d:I

    .line 173
    .line 174
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 175
    .line 176
    .line 177
    move-result p0

    .line 178
    invoke-static {p2, v2, v0, p0}, Ls5/b;->b(IIII)Ls5/b;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    return-object p0

    .line 183
    :cond_c
    iget p1, p0, Ld6/l1;->h:I

    .line 184
    .line 185
    and-int/2addr p1, v3

    .line 186
    if-eqz p1, :cond_d

    .line 187
    .line 188
    return-object v1

    .line 189
    :cond_d
    invoke-virtual {p0}, Ld6/l1;->l()Ls5/b;

    .line 190
    .line 191
    .line 192
    move-result-object p1

    .line 193
    iget-object p0, p0, Ld6/l1;->f:Ld6/w1;

    .line 194
    .line 195
    if-eqz p0, :cond_e

    .line 196
    .line 197
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 198
    .line 199
    invoke-virtual {p0}, Ld6/s1;->j()Ls5/b;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    :cond_e
    iget p0, p1, Ls5/b;->d:I

    .line 204
    .line 205
    if-eqz v0, :cond_f

    .line 206
    .line 207
    iget p2, v0, Ls5/b;->d:I

    .line 208
    .line 209
    invoke-static {p0, p2}, Ljava/lang/Math;->min(II)I

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    :cond_f
    iget p2, p1, Ls5/b;->a:I

    .line 214
    .line 215
    iget p1, p1, Ls5/b;->c:I

    .line 216
    .line 217
    invoke-static {p2, v2, p1, p0}, Ls5/b;->b(IIII)Ls5/b;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    return-object p0

    .line 222
    :cond_10
    if-eqz p2, :cond_11

    .line 223
    .line 224
    invoke-direct {p0}, Ld6/l1;->x()Ls5/b;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    iget p1, p1, Ls5/b;->b:I

    .line 229
    .line 230
    invoke-virtual {p0}, Ld6/l1;->l()Ls5/b;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    iget p0, p0, Ls5/b;->b:I

    .line 235
    .line 236
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    invoke-static {v2, p0, v2, v2}, Ls5/b;->b(IIII)Ls5/b;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    return-object p0

    .line 245
    :cond_11
    iget p1, p0, Ld6/l1;->h:I

    .line 246
    .line 247
    and-int/lit8 p1, p1, 0x4

    .line 248
    .line 249
    if-eqz p1, :cond_12

    .line 250
    .line 251
    return-object v1

    .line 252
    :cond_12
    invoke-virtual {p0}, Ld6/l1;->l()Ls5/b;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    iget p0, p0, Ls5/b;->b:I

    .line 257
    .line 258
    invoke-static {v2, p0, v2, v2}, Ls5/b;->b(IIII)Ls5/b;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    return-object p0
.end method

.method public z(I)Z
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-eq p1, v1, :cond_1

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    if-eq p1, v2, :cond_1

    .line 7
    .line 8
    const/4 v2, 0x4

    .line 9
    if-eq p1, v2, :cond_0

    .line 10
    .line 11
    const/16 v2, 0x8

    .line 12
    .line 13
    if-eq p1, v2, :cond_1

    .line 14
    .line 15
    const/16 v2, 0x80

    .line 16
    .line 17
    if-eq p1, v2, :cond_1

    .line 18
    .line 19
    return v1

    .line 20
    :cond_0
    return v0

    .line 21
    :cond_1
    invoke-virtual {p0, p1, v0}, Ld6/l1;->w(IZ)Ls5/b;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    sget-object p1, Ls5/b;->e:Ls5/b;

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Ls5/b;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    xor-int/2addr p0, v1

    .line 32
    return p0
.end method
