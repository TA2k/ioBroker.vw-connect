.class public final Lh/z;
.super Lh/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll/j;
.implements Landroid/view/LayoutInflater$Factory2;


# static fields
.field public static final t1:Landroidx/collection/a1;

.field public static final u1:[I

.field public static final v1:Z


# instance fields
.field public A:Lh/o;

.field public B:Ld6/w0;

.field public C:Z

.field public D:Landroid/view/ViewGroup;

.field public E:Landroid/widget/TextView;

.field public F:Landroid/view/View;

.field public G:Z

.field public H:Z

.field public I:Z

.field public J:Z

.field public K:Z

.field public L:Z

.field public M:Z

.field public N:Z

.field public O:[Lh/y;

.field public P:Lh/y;

.field public Q:Z

.field public R:Z

.field public S:Z

.field public T:Z

.field public U:Landroid/content/res/Configuration;

.field public final V:I

.field public W:I

.field public X:I

.field public Y:Z

.field public Z:Lh/v;

.field public a0:Lh/v;

.field public b0:Z

.field public c0:I

.field public final d0:Lh/o;

.field public e0:Z

.field public f0:Landroid/graphics/Rect;

.field public g0:Landroid/graphics/Rect;

.field public final m:Ljava/lang/Object;

.field public final n:Landroid/content/Context;

.field public o:Landroid/view/Window;

.field public p:Lh/u;

.field public final q:Ljava/lang/Object;

.field public q1:Lh/c0;

.field public r:Lh/i0;

.field public r1:Landroid/window/OnBackInvokedDispatcher;

.field public s:Lk/h;

.field public s1:Landroid/window/OnBackInvokedCallback;

.field public t:Ljava/lang/CharSequence;

.field public u:Lm/e1;

.field public v:Laq/a;

.field public w:Lh/p;

.field public x:Lk/a;

.field public y:Landroidx/appcompat/widget/ActionBarContextView;

.field public z:Landroid/widget/PopupWindow;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Landroidx/collection/a1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lh/z;->t1:Landroidx/collection/a1;

    .line 8
    .line 9
    const v0, 0x1010054

    .line 10
    .line 11
    .line 12
    filled-new-array {v0}, [I

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lh/z;->u1:[I

    .line 17
    .line 18
    const-string v0, "robolectric"

    .line 19
    .line 20
    sget-object v1, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    xor-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    sput-boolean v0, Lh/z;->v1:Z

    .line 29
    .line 30
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/view/Window;Lh/j;Ljava/lang/Object;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lh/z;->B:Ld6/w0;

    .line 6
    .line 7
    const/16 v1, -0x64

    .line 8
    .line 9
    iput v1, p0, Lh/z;->V:I

    .line 10
    .line 11
    new-instance v2, Lh/o;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v2, p0, v3}, Lh/o;-><init>(Lh/z;I)V

    .line 15
    .line 16
    .line 17
    iput-object v2, p0, Lh/z;->d0:Lh/o;

    .line 18
    .line 19
    iput-object p1, p0, Lh/z;->n:Landroid/content/Context;

    .line 20
    .line 21
    iput-object p3, p0, Lh/z;->q:Ljava/lang/Object;

    .line 22
    .line 23
    iput-object p4, p0, Lh/z;->m:Ljava/lang/Object;

    .line 24
    .line 25
    instance-of p3, p4, Landroid/app/Dialog;

    .line 26
    .line 27
    if-eqz p3, :cond_2

    .line 28
    .line 29
    :goto_0
    if-eqz p1, :cond_1

    .line 30
    .line 31
    instance-of p3, p1, Lh/i;

    .line 32
    .line 33
    if-eqz p3, :cond_0

    .line 34
    .line 35
    move-object v0, p1

    .line 36
    check-cast v0, Lh/i;

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    instance-of p3, p1, Landroid/content/ContextWrapper;

    .line 40
    .line 41
    if-eqz p3, :cond_1

    .line 42
    .line 43
    check-cast p1, Landroid/content/ContextWrapper;

    .line 44
    .line 45
    invoke-virtual {p1}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    goto :goto_0

    .line 50
    :cond_1
    :goto_1
    if-eqz v0, :cond_2

    .line 51
    .line 52
    invoke-virtual {v0}, Lh/i;->i()Lh/n;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    check-cast p1, Lh/z;

    .line 57
    .line 58
    iget p1, p1, Lh/z;->V:I

    .line 59
    .line 60
    iput p1, p0, Lh/z;->V:I

    .line 61
    .line 62
    :cond_2
    iget p1, p0, Lh/z;->V:I

    .line 63
    .line 64
    if-ne p1, v1, :cond_3

    .line 65
    .line 66
    iget-object p1, p0, Lh/z;->m:Ljava/lang/Object;

    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    sget-object p3, Lh/z;->t1:Landroidx/collection/a1;

    .line 77
    .line 78
    invoke-virtual {p3, p1}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Ljava/lang/Integer;

    .line 83
    .line 84
    if-eqz p1, :cond_3

    .line 85
    .line 86
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    iput p1, p0, Lh/z;->V:I

    .line 91
    .line 92
    iget-object p1, p0, Lh/z;->m:Ljava/lang/Object;

    .line 93
    .line 94
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-virtual {p3, p1}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    :cond_3
    if-eqz p2, :cond_4

    .line 106
    .line 107
    invoke-virtual {p0, p2}, Lh/z;->s(Landroid/view/Window;)V

    .line 108
    .line 109
    .line 110
    :cond_4
    invoke-static {}, Lm/s;->d()V

    .line 111
    .line 112
    .line 113
    return-void
.end method

.method public static t(Landroid/content/Context;)Ly5/c;
    .locals 5

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x21

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget-object v0, Lh/n;->f:Ly5/c;

    .line 9
    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    :goto_0
    const/4 p0, 0x0

    .line 13
    return-object p0

    .line 14
    :cond_1
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Lh/s;->b(Landroid/content/res/Configuration;)Ly5/c;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    iget-object v1, v0, Ly5/c;->a:Ly5/d;

    .line 31
    .line 32
    iget-object v1, v1, Ly5/d;->a:Landroid/os/LocaleList;

    .line 33
    .line 34
    invoke-virtual {v1}, Landroid/os/LocaleList;->isEmpty()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    sget-object v0, Ly5/c;->b:Ly5/c;

    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_2
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 44
    .line 45
    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 46
    .line 47
    .line 48
    const/4 v2, 0x0

    .line 49
    :goto_1
    invoke-virtual {v0}, Ly5/c;->c()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    invoke-virtual {p0}, Ly5/c;->c()I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    add-int/2addr v4, v3

    .line 58
    if-ge v2, v4, :cond_5

    .line 59
    .line 60
    invoke-virtual {v0}, Ly5/c;->c()I

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    if-ge v2, v3, :cond_3

    .line 65
    .line 66
    invoke-virtual {v0, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    goto :goto_2

    .line 71
    :cond_3
    invoke-virtual {v0}, Ly5/c;->c()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    sub-int v3, v2, v3

    .line 76
    .line 77
    invoke-virtual {p0, v3}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    :goto_2
    if-eqz v3, :cond_4

    .line 82
    .line 83
    invoke-interface {v1, v3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_5
    invoke-interface {v1}, Ljava/util/Set;->size()I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    new-array v0, v0, [Ljava/util/Locale;

    .line 94
    .line 95
    invoke-interface {v1, v0}, Ljava/util/Set;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    check-cast v0, [Ljava/util/Locale;

    .line 100
    .line 101
    new-instance v1, Landroid/os/LocaleList;

    .line 102
    .line 103
    invoke-direct {v1, v0}, Landroid/os/LocaleList;-><init>([Ljava/util/Locale;)V

    .line 104
    .line 105
    .line 106
    new-instance v0, Ly5/c;

    .line 107
    .line 108
    new-instance v2, Ly5/d;

    .line 109
    .line 110
    invoke-direct {v2, v1}, Ly5/d;-><init>(Landroid/os/LocaleList;)V

    .line 111
    .line 112
    .line 113
    invoke-direct {v0, v2}, Ly5/c;-><init>(Ly5/d;)V

    .line 114
    .line 115
    .line 116
    :goto_3
    iget-object v1, v0, Ly5/c;->a:Ly5/d;

    .line 117
    .line 118
    iget-object v1, v1, Ly5/d;->a:Landroid/os/LocaleList;

    .line 119
    .line 120
    invoke-virtual {v1}, Landroid/os/LocaleList;->isEmpty()Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-eqz v1, :cond_6

    .line 125
    .line 126
    return-object p0

    .line 127
    :cond_6
    return-object v0
.end method

.method public static x(Landroid/content/Context;ILy5/c;Landroid/content/res/Configuration;Z)Landroid/content/res/Configuration;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p1, v0, :cond_2

    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p1, v0, :cond_1

    .line 6
    .line 7
    if-eqz p4, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget p0, p0, Landroid/content/res/Configuration;->uiMode:I

    .line 24
    .line 25
    and-int/lit8 p0, p0, 0x30

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const/16 p0, 0x20

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_2
    const/16 p0, 0x10

    .line 32
    .line 33
    :goto_0
    new-instance p1, Landroid/content/res/Configuration;

    .line 34
    .line 35
    invoke-direct {p1}, Landroid/content/res/Configuration;-><init>()V

    .line 36
    .line 37
    .line 38
    const/4 p4, 0x0

    .line 39
    iput p4, p1, Landroid/content/res/Configuration;->fontScale:F

    .line 40
    .line 41
    if-eqz p3, :cond_3

    .line 42
    .line 43
    invoke-virtual {p1, p3}, Landroid/content/res/Configuration;->setTo(Landroid/content/res/Configuration;)V

    .line 44
    .line 45
    .line 46
    :cond_3
    iget p3, p1, Landroid/content/res/Configuration;->uiMode:I

    .line 47
    .line 48
    and-int/lit8 p3, p3, -0x31

    .line 49
    .line 50
    or-int/2addr p0, p3

    .line 51
    iput p0, p1, Landroid/content/res/Configuration;->uiMode:I

    .line 52
    .line 53
    if-eqz p2, :cond_4

    .line 54
    .line 55
    invoke-static {p1, p2}, Lh/s;->d(Landroid/content/res/Configuration;Ly5/c;)V

    .line 56
    .line 57
    .line 58
    :cond_4
    return-object p1
.end method


# virtual methods
.method public final A()V
    .locals 11

    .line 1
    iget-boolean v0, p0, Lh/z;->C:Z

    .line 2
    .line 3
    if-nez v0, :cond_1b

    .line 4
    .line 5
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 6
    .line 7
    sget-object v1, Lg/a;->j:[I

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const/16 v3, 0x75

    .line 14
    .line 15
    invoke-virtual {v2, v3}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    if-eqz v4, :cond_1a

    .line 20
    .line 21
    const/16 v4, 0x7e

    .line 22
    .line 23
    const/4 v5, 0x0

    .line 24
    invoke-virtual {v2, v4, v5}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    const/16 v6, 0x6c

    .line 29
    .line 30
    const/4 v7, 0x1

    .line 31
    if-eqz v4, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0, v7}, Lh/z;->j(I)Z

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v2, v3, v5}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_1

    .line 42
    .line 43
    invoke-virtual {p0, v6}, Lh/z;->j(I)Z

    .line 44
    .line 45
    .line 46
    :cond_1
    :goto_0
    const/16 v3, 0x76

    .line 47
    .line 48
    invoke-virtual {v2, v3, v5}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    const/16 v4, 0x6d

    .line 53
    .line 54
    if-eqz v3, :cond_2

    .line 55
    .line 56
    invoke-virtual {p0, v4}, Lh/z;->j(I)Z

    .line 57
    .line 58
    .line 59
    :cond_2
    const/16 v3, 0x77

    .line 60
    .line 61
    invoke-virtual {v2, v3, v5}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-eqz v3, :cond_3

    .line 66
    .line 67
    const/16 v3, 0xa

    .line 68
    .line 69
    invoke-virtual {p0, v3}, Lh/z;->j(I)Z

    .line 70
    .line 71
    .line 72
    :cond_3
    invoke-virtual {v2, v5, v5}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    iput-boolean v3, p0, Lh/z;->L:Z

    .line 77
    .line 78
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0}, Lh/z;->B()V

    .line 82
    .line 83
    .line 84
    iget-object v2, p0, Lh/z;->o:Landroid/view/Window;

    .line 85
    .line 86
    invoke-virtual {v2}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 87
    .line 88
    .line 89
    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    iget-boolean v3, p0, Lh/z;->M:Z

    .line 94
    .line 95
    const/4 v8, 0x0

    .line 96
    if-nez v3, :cond_9

    .line 97
    .line 98
    iget-boolean v3, p0, Lh/z;->L:Z

    .line 99
    .line 100
    if-eqz v3, :cond_4

    .line 101
    .line 102
    const v3, 0x7f0d000c

    .line 103
    .line 104
    .line 105
    invoke-virtual {v2, v3, v8}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    check-cast v2, Landroid/view/ViewGroup;

    .line 110
    .line 111
    iput-boolean v5, p0, Lh/z;->J:Z

    .line 112
    .line 113
    iput-boolean v5, p0, Lh/z;->I:Z

    .line 114
    .line 115
    goto/16 :goto_2

    .line 116
    .line 117
    :cond_4
    iget-boolean v2, p0, Lh/z;->I:Z

    .line 118
    .line 119
    if-eqz v2, :cond_8

    .line 120
    .line 121
    new-instance v2, Landroid/util/TypedValue;

    .line 122
    .line 123
    invoke-direct {v2}, Landroid/util/TypedValue;-><init>()V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    const v9, 0x7f04000c

    .line 131
    .line 132
    .line 133
    invoke-virtual {v3, v9, v2, v7}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 134
    .line 135
    .line 136
    iget v3, v2, Landroid/util/TypedValue;->resourceId:I

    .line 137
    .line 138
    if-eqz v3, :cond_5

    .line 139
    .line 140
    new-instance v3, Lk/c;

    .line 141
    .line 142
    iget v2, v2, Landroid/util/TypedValue;->resourceId:I

    .line 143
    .line 144
    invoke-direct {v3, v0, v2}, Lk/c;-><init>(Landroid/content/Context;I)V

    .line 145
    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_5
    move-object v3, v0

    .line 149
    :goto_1
    invoke-static {v3}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    const v3, 0x7f0d0017

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2, v3, v8}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    check-cast v2, Landroid/view/ViewGroup;

    .line 161
    .line 162
    const v3, 0x7f0a00ff

    .line 163
    .line 164
    .line 165
    invoke-virtual {v2, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    check-cast v3, Lm/e1;

    .line 170
    .line 171
    iput-object v3, p0, Lh/z;->u:Lm/e1;

    .line 172
    .line 173
    iget-object v9, p0, Lh/z;->o:Landroid/view/Window;

    .line 174
    .line 175
    invoke-virtual {v9}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 176
    .line 177
    .line 178
    move-result-object v9

    .line 179
    invoke-interface {v3, v9}, Lm/e1;->setWindowCallback(Landroid/view/Window$Callback;)V

    .line 180
    .line 181
    .line 182
    iget-boolean v3, p0, Lh/z;->J:Z

    .line 183
    .line 184
    if-eqz v3, :cond_6

    .line 185
    .line 186
    iget-object v3, p0, Lh/z;->u:Lm/e1;

    .line 187
    .line 188
    check-cast v3, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 189
    .line 190
    invoke-virtual {v3, v4}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->j(I)V

    .line 191
    .line 192
    .line 193
    :cond_6
    iget-boolean v3, p0, Lh/z;->G:Z

    .line 194
    .line 195
    if-eqz v3, :cond_7

    .line 196
    .line 197
    iget-object v3, p0, Lh/z;->u:Lm/e1;

    .line 198
    .line 199
    const/4 v4, 0x2

    .line 200
    check-cast v3, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 201
    .line 202
    invoke-virtual {v3, v4}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->j(I)V

    .line 203
    .line 204
    .line 205
    :cond_7
    iget-boolean v3, p0, Lh/z;->H:Z

    .line 206
    .line 207
    if-eqz v3, :cond_b

    .line 208
    .line 209
    iget-object v3, p0, Lh/z;->u:Lm/e1;

    .line 210
    .line 211
    const/4 v4, 0x5

    .line 212
    check-cast v3, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 213
    .line 214
    invoke-virtual {v3, v4}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->j(I)V

    .line 215
    .line 216
    .line 217
    goto :goto_2

    .line 218
    :cond_8
    move-object v2, v8

    .line 219
    goto :goto_2

    .line 220
    :cond_9
    iget-boolean v3, p0, Lh/z;->K:Z

    .line 221
    .line 222
    if-eqz v3, :cond_a

    .line 223
    .line 224
    const v3, 0x7f0d0016

    .line 225
    .line 226
    .line 227
    invoke-virtual {v2, v3, v8}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    check-cast v2, Landroid/view/ViewGroup;

    .line 232
    .line 233
    goto :goto_2

    .line 234
    :cond_a
    const v3, 0x7f0d0015

    .line 235
    .line 236
    .line 237
    invoke-virtual {v2, v3, v8}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    check-cast v2, Landroid/view/ViewGroup;

    .line 242
    .line 243
    :cond_b
    :goto_2
    if-eqz v2, :cond_19

    .line 244
    .line 245
    new-instance v3, Lh/p;

    .line 246
    .line 247
    invoke-direct {v3, p0}, Lh/p;-><init>(Lh/z;)V

    .line 248
    .line 249
    .line 250
    sget-object v4, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 251
    .line 252
    invoke-static {v2, v3}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 253
    .line 254
    .line 255
    iget-object v3, p0, Lh/z;->u:Lm/e1;

    .line 256
    .line 257
    if-nez v3, :cond_c

    .line 258
    .line 259
    const v3, 0x7f0a02e5

    .line 260
    .line 261
    .line 262
    invoke-virtual {v2, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    check-cast v3, Landroid/widget/TextView;

    .line 267
    .line 268
    iput-object v3, p0, Lh/z;->E:Landroid/widget/TextView;

    .line 269
    .line 270
    :cond_c
    const-string v3, "Could not invoke makeOptionalFitsSystemWindows"

    .line 271
    .line 272
    const-string v4, "ViewUtils"

    .line 273
    .line 274
    :try_start_0
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 275
    .line 276
    .line 277
    move-result-object v9

    .line 278
    const-string v10, "makeOptionalFitsSystemWindows"

    .line 279
    .line 280
    invoke-virtual {v9, v10, v8}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 281
    .line 282
    .line 283
    move-result-object v9

    .line 284
    invoke-virtual {v9}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 285
    .line 286
    .line 287
    move-result v10

    .line 288
    if-nez v10, :cond_d

    .line 289
    .line 290
    invoke-virtual {v9, v7}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 291
    .line 292
    .line 293
    goto :goto_3

    .line 294
    :catch_0
    move-exception v9

    .line 295
    goto :goto_4

    .line 296
    :catch_1
    move-exception v9

    .line 297
    goto :goto_5

    .line 298
    :cond_d
    :goto_3
    invoke-virtual {v9, v2, v8}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    .line 299
    .line 300
    .line 301
    goto :goto_6

    .line 302
    :goto_4
    invoke-static {v4, v3, v9}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 303
    .line 304
    .line 305
    goto :goto_6

    .line 306
    :goto_5
    invoke-static {v4, v3, v9}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 307
    .line 308
    .line 309
    goto :goto_6

    .line 310
    :catch_2
    const-string v3, "Could not find method makeOptionalFitsSystemWindows. Oh well..."

    .line 311
    .line 312
    invoke-static {v4, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 313
    .line 314
    .line 315
    :goto_6
    const v3, 0x7f0a0034

    .line 316
    .line 317
    .line 318
    invoke-virtual {v2, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 319
    .line 320
    .line 321
    move-result-object v3

    .line 322
    check-cast v3, Landroidx/appcompat/widget/ContentFrameLayout;

    .line 323
    .line 324
    iget-object v4, p0, Lh/z;->o:Landroid/view/Window;

    .line 325
    .line 326
    const v9, 0x1020002

    .line 327
    .line 328
    .line 329
    invoke-virtual {v4, v9}, Landroid/view/Window;->findViewById(I)Landroid/view/View;

    .line 330
    .line 331
    .line 332
    move-result-object v4

    .line 333
    check-cast v4, Landroid/view/ViewGroup;

    .line 334
    .line 335
    if-eqz v4, :cond_f

    .line 336
    .line 337
    :goto_7
    invoke-virtual {v4}, Landroid/view/ViewGroup;->getChildCount()I

    .line 338
    .line 339
    .line 340
    move-result v10

    .line 341
    if-lez v10, :cond_e

    .line 342
    .line 343
    invoke-virtual {v4, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 344
    .line 345
    .line 346
    move-result-object v10

    .line 347
    invoke-virtual {v4, v5}, Landroid/view/ViewGroup;->removeViewAt(I)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v3, v10}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 351
    .line 352
    .line 353
    goto :goto_7

    .line 354
    :cond_e
    const/4 v10, -0x1

    .line 355
    invoke-virtual {v4, v10}, Landroid/view/View;->setId(I)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v3, v9}, Landroid/view/View;->setId(I)V

    .line 359
    .line 360
    .line 361
    instance-of v10, v4, Landroid/widget/FrameLayout;

    .line 362
    .line 363
    if-eqz v10, :cond_f

    .line 364
    .line 365
    check-cast v4, Landroid/widget/FrameLayout;

    .line 366
    .line 367
    invoke-virtual {v4, v8}, Landroid/view/View;->setForeground(Landroid/graphics/drawable/Drawable;)V

    .line 368
    .line 369
    .line 370
    :cond_f
    iget-object v4, p0, Lh/z;->o:Landroid/view/Window;

    .line 371
    .line 372
    invoke-virtual {v4, v2}, Landroid/view/Window;->setContentView(Landroid/view/View;)V

    .line 373
    .line 374
    .line 375
    new-instance v4, Lbu/c;

    .line 376
    .line 377
    const/16 v8, 0x1a

    .line 378
    .line 379
    invoke-direct {v4, p0, v8}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v3, v4}, Landroidx/appcompat/widget/ContentFrameLayout;->setAttachListener(Lm/d1;)V

    .line 383
    .line 384
    .line 385
    iput-object v2, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 386
    .line 387
    iget-object v2, p0, Lh/z;->m:Ljava/lang/Object;

    .line 388
    .line 389
    instance-of v3, v2, Landroid/app/Activity;

    .line 390
    .line 391
    if-eqz v3, :cond_10

    .line 392
    .line 393
    check-cast v2, Landroid/app/Activity;

    .line 394
    .line 395
    invoke-virtual {v2}, Landroid/app/Activity;->getTitle()Ljava/lang/CharSequence;

    .line 396
    .line 397
    .line 398
    move-result-object v2

    .line 399
    goto :goto_8

    .line 400
    :cond_10
    iget-object v2, p0, Lh/z;->t:Ljava/lang/CharSequence;

    .line 401
    .line 402
    :goto_8
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 403
    .line 404
    .line 405
    move-result v3

    .line 406
    if-nez v3, :cond_13

    .line 407
    .line 408
    iget-object v3, p0, Lh/z;->u:Lm/e1;

    .line 409
    .line 410
    if-eqz v3, :cond_11

    .line 411
    .line 412
    invoke-interface {v3, v2}, Lm/e1;->setWindowTitle(Ljava/lang/CharSequence;)V

    .line 413
    .line 414
    .line 415
    goto :goto_9

    .line 416
    :cond_11
    iget-object v3, p0, Lh/z;->r:Lh/i0;

    .line 417
    .line 418
    if-eqz v3, :cond_12

    .line 419
    .line 420
    iget-object v3, v3, Lh/i0;->e:Lm/f1;

    .line 421
    .line 422
    check-cast v3, Lm/w2;

    .line 423
    .line 424
    iget-boolean v4, v3, Lm/w2;->g:Z

    .line 425
    .line 426
    if-nez v4, :cond_13

    .line 427
    .line 428
    iget-object v4, v3, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 429
    .line 430
    iput-object v2, v3, Lm/w2;->h:Ljava/lang/CharSequence;

    .line 431
    .line 432
    iget v8, v3, Lm/w2;->b:I

    .line 433
    .line 434
    and-int/lit8 v8, v8, 0x8

    .line 435
    .line 436
    if-eqz v8, :cond_13

    .line 437
    .line 438
    invoke-virtual {v4, v2}, Landroidx/appcompat/widget/Toolbar;->setTitle(Ljava/lang/CharSequence;)V

    .line 439
    .line 440
    .line 441
    iget-boolean v3, v3, Lm/w2;->g:Z

    .line 442
    .line 443
    if-eqz v3, :cond_13

    .line 444
    .line 445
    invoke-virtual {v4}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 446
    .line 447
    .line 448
    move-result-object v3

    .line 449
    invoke-static {v3, v2}, Ld6/r0;->j(Landroid/view/View;Ljava/lang/CharSequence;)V

    .line 450
    .line 451
    .line 452
    goto :goto_9

    .line 453
    :cond_12
    iget-object v3, p0, Lh/z;->E:Landroid/widget/TextView;

    .line 454
    .line 455
    if-eqz v3, :cond_13

    .line 456
    .line 457
    invoke-virtual {v3, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 458
    .line 459
    .line 460
    :cond_13
    :goto_9
    iget-object v2, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 461
    .line 462
    invoke-virtual {v2, v9}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 463
    .line 464
    .line 465
    move-result-object v2

    .line 466
    check-cast v2, Landroidx/appcompat/widget/ContentFrameLayout;

    .line 467
    .line 468
    iget-object v3, p0, Lh/z;->o:Landroid/view/Window;

    .line 469
    .line 470
    invoke-virtual {v3}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 471
    .line 472
    .line 473
    move-result-object v3

    .line 474
    invoke-virtual {v3}, Landroid/view/View;->getPaddingLeft()I

    .line 475
    .line 476
    .line 477
    move-result v4

    .line 478
    invoke-virtual {v3}, Landroid/view/View;->getPaddingTop()I

    .line 479
    .line 480
    .line 481
    move-result v8

    .line 482
    invoke-virtual {v3}, Landroid/view/View;->getPaddingRight()I

    .line 483
    .line 484
    .line 485
    move-result v9

    .line 486
    invoke-virtual {v3}, Landroid/view/View;->getPaddingBottom()I

    .line 487
    .line 488
    .line 489
    move-result v3

    .line 490
    iget-object v10, v2, Landroidx/appcompat/widget/ContentFrameLayout;->j:Landroid/graphics/Rect;

    .line 491
    .line 492
    invoke-virtual {v10, v4, v8, v9, v3}, Landroid/graphics/Rect;->set(IIII)V

    .line 493
    .line 494
    .line 495
    invoke-virtual {v2}, Landroid/view/View;->isLaidOut()Z

    .line 496
    .line 497
    .line 498
    move-result v3

    .line 499
    if-eqz v3, :cond_14

    .line 500
    .line 501
    invoke-virtual {v2}, Landroid/view/View;->requestLayout()V

    .line 502
    .line 503
    .line 504
    :cond_14
    invoke-virtual {v0, v1}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    const/16 v1, 0x7c

    .line 509
    .line 510
    invoke-virtual {v2}, Landroidx/appcompat/widget/ContentFrameLayout;->getMinWidthMajor()Landroid/util/TypedValue;

    .line 511
    .line 512
    .line 513
    move-result-object v3

    .line 514
    invoke-virtual {v0, v1, v3}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 515
    .line 516
    .line 517
    const/16 v1, 0x7d

    .line 518
    .line 519
    invoke-virtual {v2}, Landroidx/appcompat/widget/ContentFrameLayout;->getMinWidthMinor()Landroid/util/TypedValue;

    .line 520
    .line 521
    .line 522
    move-result-object v3

    .line 523
    invoke-virtual {v0, v1, v3}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 524
    .line 525
    .line 526
    const/16 v1, 0x7a

    .line 527
    .line 528
    invoke-virtual {v0, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 529
    .line 530
    .line 531
    move-result v3

    .line 532
    if-eqz v3, :cond_15

    .line 533
    .line 534
    invoke-virtual {v2}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedWidthMajor()Landroid/util/TypedValue;

    .line 535
    .line 536
    .line 537
    move-result-object v3

    .line 538
    invoke-virtual {v0, v1, v3}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 539
    .line 540
    .line 541
    :cond_15
    const/16 v1, 0x7b

    .line 542
    .line 543
    invoke-virtual {v0, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 544
    .line 545
    .line 546
    move-result v3

    .line 547
    if-eqz v3, :cond_16

    .line 548
    .line 549
    invoke-virtual {v2}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedWidthMinor()Landroid/util/TypedValue;

    .line 550
    .line 551
    .line 552
    move-result-object v3

    .line 553
    invoke-virtual {v0, v1, v3}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 554
    .line 555
    .line 556
    :cond_16
    const/16 v1, 0x78

    .line 557
    .line 558
    invoke-virtual {v0, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 559
    .line 560
    .line 561
    move-result v3

    .line 562
    if-eqz v3, :cond_17

    .line 563
    .line 564
    invoke-virtual {v2}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedHeightMajor()Landroid/util/TypedValue;

    .line 565
    .line 566
    .line 567
    move-result-object v3

    .line 568
    invoke-virtual {v0, v1, v3}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 569
    .line 570
    .line 571
    :cond_17
    const/16 v1, 0x79

    .line 572
    .line 573
    invoke-virtual {v0, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 574
    .line 575
    .line 576
    move-result v3

    .line 577
    if-eqz v3, :cond_18

    .line 578
    .line 579
    invoke-virtual {v2}, Landroidx/appcompat/widget/ContentFrameLayout;->getFixedHeightMinor()Landroid/util/TypedValue;

    .line 580
    .line 581
    .line 582
    move-result-object v3

    .line 583
    invoke-virtual {v0, v1, v3}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 584
    .line 585
    .line 586
    :cond_18
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v2}, Landroid/view/View;->requestLayout()V

    .line 590
    .line 591
    .line 592
    iput-boolean v7, p0, Lh/z;->C:Z

    .line 593
    .line 594
    invoke-virtual {p0, v5}, Lh/z;->D(I)Lh/y;

    .line 595
    .line 596
    .line 597
    move-result-object v0

    .line 598
    iget-boolean v1, p0, Lh/z;->T:Z

    .line 599
    .line 600
    if-nez v1, :cond_1b

    .line 601
    .line 602
    iget-object v0, v0, Lh/y;->h:Ll/l;

    .line 603
    .line 604
    if-nez v0, :cond_1b

    .line 605
    .line 606
    invoke-virtual {p0, v6}, Lh/z;->F(I)V

    .line 607
    .line 608
    .line 609
    goto :goto_a

    .line 610
    :cond_19
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 611
    .line 612
    new-instance v1, Ljava/lang/StringBuilder;

    .line 613
    .line 614
    const-string v2, "AppCompat does not support the current theme features: { windowActionBar: "

    .line 615
    .line 616
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    iget-boolean v2, p0, Lh/z;->I:Z

    .line 620
    .line 621
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 622
    .line 623
    .line 624
    const-string v2, ", windowActionBarOverlay: "

    .line 625
    .line 626
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 627
    .line 628
    .line 629
    iget-boolean v2, p0, Lh/z;->J:Z

    .line 630
    .line 631
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 632
    .line 633
    .line 634
    const-string v2, ", android:windowIsFloating: "

    .line 635
    .line 636
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 637
    .line 638
    .line 639
    iget-boolean v2, p0, Lh/z;->L:Z

    .line 640
    .line 641
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 642
    .line 643
    .line 644
    const-string v2, ", windowActionModeOverlay: "

    .line 645
    .line 646
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 647
    .line 648
    .line 649
    iget-boolean v2, p0, Lh/z;->K:Z

    .line 650
    .line 651
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 652
    .line 653
    .line 654
    const-string v2, ", windowNoTitle: "

    .line 655
    .line 656
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 657
    .line 658
    .line 659
    iget-boolean p0, p0, Lh/z;->M:Z

    .line 660
    .line 661
    const-string v2, " }"

    .line 662
    .line 663
    invoke-static {v1, p0, v2}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 664
    .line 665
    .line 666
    move-result-object p0

    .line 667
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 668
    .line 669
    .line 670
    throw v0

    .line 671
    :cond_1a
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 672
    .line 673
    .line 674
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 675
    .line 676
    const-string v0, "You need to use a Theme.AppCompat theme (or descendant) with this activity."

    .line 677
    .line 678
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 679
    .line 680
    .line 681
    throw p0

    .line 682
    :cond_1b
    :goto_a
    return-void
.end method

.method public final B()V
    .locals 2

    .line 1
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lh/z;->m:Ljava/lang/Object;

    .line 6
    .line 7
    instance-of v1, v0, Landroid/app/Activity;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    check-cast v0, Landroid/app/Activity;

    .line 12
    .line 13
    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p0, v0}, Lh/z;->s(Landroid/view/Window;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string v0, "We have not been given a Window"

    .line 28
    .line 29
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method

.method public final C(Landroid/content/Context;)Lh/w;
    .locals 3

    .line 1
    iget-object v0, p0, Lh/z;->Z:Lh/v;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    new-instance v0, Lh/v;

    .line 6
    .line 7
    sget-object v1, Lgw0/c;->h:Lgw0/c;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    new-instance v1, Lgw0/c;

    .line 16
    .line 17
    const-string v2, "location"

    .line 18
    .line 19
    invoke-virtual {p1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Landroid/location/LocationManager;

    .line 24
    .line 25
    invoke-direct {v1, p1, v2}, Lgw0/c;-><init>(Landroid/content/Context;Landroid/location/LocationManager;)V

    .line 26
    .line 27
    .line 28
    sput-object v1, Lgw0/c;->h:Lgw0/c;

    .line 29
    .line 30
    :cond_0
    sget-object p1, Lgw0/c;->h:Lgw0/c;

    .line 31
    .line 32
    invoke-direct {v0, p0, p1}, Lh/v;-><init>(Lh/z;Lgw0/c;)V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lh/z;->Z:Lh/v;

    .line 36
    .line 37
    :cond_1
    iget-object p0, p0, Lh/z;->Z:Lh/v;

    .line 38
    .line 39
    return-object p0
.end method

.method public final D(I)Lh/y;
    .locals 4

    .line 1
    iget-object v0, p0, Lh/z;->O:[Lh/y;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    array-length v2, v0

    .line 7
    if-gt v2, p1, :cond_2

    .line 8
    .line 9
    :cond_0
    add-int/lit8 v2, p1, 0x1

    .line 10
    .line 11
    new-array v2, v2, [Lh/y;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    array-length v3, v0

    .line 16
    invoke-static {v0, v1, v2, v1, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 17
    .line 18
    .line 19
    :cond_1
    iput-object v2, p0, Lh/z;->O:[Lh/y;

    .line 20
    .line 21
    move-object v0, v2

    .line 22
    :cond_2
    aget-object p0, v0, p1

    .line 23
    .line 24
    if-nez p0, :cond_3

    .line 25
    .line 26
    new-instance p0, Lh/y;

    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput p1, p0, Lh/y;->a:I

    .line 32
    .line 33
    iput-boolean v1, p0, Lh/y;->n:Z

    .line 34
    .line 35
    aput-object p0, v0, p1

    .line 36
    .line 37
    :cond_3
    return-object p0
.end method

.method public final E()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lh/z;->A()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Lh/z;->I:Z

    .line 5
    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    iget-object v0, p0, Lh/z;->r:Lh/i0;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    iget-object v0, p0, Lh/z;->m:Ljava/lang/Object;

    .line 14
    .line 15
    instance-of v1, v0, Landroid/app/Activity;

    .line 16
    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    new-instance v1, Lh/i0;

    .line 20
    .line 21
    check-cast v0, Landroid/app/Activity;

    .line 22
    .line 23
    iget-boolean v2, p0, Lh/z;->J:Z

    .line 24
    .line 25
    invoke-direct {v1, v0, v2}, Lh/i0;-><init>(Landroid/app/Activity;Z)V

    .line 26
    .line 27
    .line 28
    iput-object v1, p0, Lh/z;->r:Lh/i0;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    instance-of v1, v0, Landroid/app/Dialog;

    .line 32
    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    new-instance v1, Lh/i0;

    .line 36
    .line 37
    check-cast v0, Landroid/app/Dialog;

    .line 38
    .line 39
    invoke-direct {v1, v0}, Lh/i0;-><init>(Landroid/app/Dialog;)V

    .line 40
    .line 41
    .line 42
    iput-object v1, p0, Lh/z;->r:Lh/i0;

    .line 43
    .line 44
    :cond_2
    :goto_0
    iget-object v0, p0, Lh/z;->r:Lh/i0;

    .line 45
    .line 46
    if-eqz v0, :cond_3

    .line 47
    .line 48
    iget-boolean p0, p0, Lh/z;->e0:Z

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Lh/i0;->f(Z)V

    .line 51
    .line 52
    .line 53
    :cond_3
    :goto_1
    return-void
.end method

.method public final F(I)V
    .locals 2

    .line 1
    iget v0, p0, Lh/z;->c0:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    shl-int p1, v1, p1

    .line 5
    .line 6
    or-int/2addr p1, v0

    .line 7
    iput p1, p0, Lh/z;->c0:I

    .line 8
    .line 9
    iget-boolean p1, p0, Lh/z;->b0:Z

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    iget-object p1, p0, Lh/z;->o:Landroid/view/Window;

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 20
    .line 21
    iget-object v0, p0, Lh/z;->d0:Lh/o;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 24
    .line 25
    .line 26
    iput-boolean v1, p0, Lh/z;->b0:Z

    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public final G(Landroid/content/Context;I)I
    .locals 2

    .line 1
    const/16 v0, -0x64

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-eq p2, v0, :cond_5

    .line 5
    .line 6
    if-eq p2, v1, :cond_4

    .line 7
    .line 8
    if-eqz p2, :cond_2

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    if-eq p2, v0, :cond_4

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    if-eq p2, v0, :cond_4

    .line 15
    .line 16
    const/4 v0, 0x3

    .line 17
    if-ne p2, v0, :cond_1

    .line 18
    .line 19
    iget-object p2, p0, Lh/z;->a0:Lh/v;

    .line 20
    .line 21
    if-nez p2, :cond_0

    .line 22
    .line 23
    new-instance p2, Lh/v;

    .line 24
    .line 25
    invoke-direct {p2, p0, p1}, Lh/v;-><init>(Lh/z;Landroid/content/Context;)V

    .line 26
    .line 27
    .line 28
    iput-object p2, p0, Lh/z;->a0:Lh/v;

    .line 29
    .line 30
    :cond_0
    iget-object p0, p0, Lh/z;->a0:Lh/v;

    .line 31
    .line 32
    invoke-virtual {p0}, Lh/v;->f()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "Unknown value set for night mode. Please use one of the MODE_NIGHT values from AppCompatDelegate."

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_2
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    const-string v0, "uimode"

    .line 50
    .line 51
    invoke-virtual {p2, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    check-cast p2, Landroid/app/UiModeManager;

    .line 56
    .line 57
    invoke-virtual {p2}, Landroid/app/UiModeManager;->getNightMode()I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    if-nez p2, :cond_3

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_3
    invoke-virtual {p0, p1}, Lh/z;->C(Landroid/content/Context;)Lh/w;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-virtual {p0}, Lh/w;->f()I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    return p0

    .line 73
    :cond_4
    return p2

    .line 74
    :cond_5
    :goto_0
    return v1
.end method

.method public final H()Z
    .locals 5

    .line 1
    iget-boolean v0, p0, Lh/z;->Q:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-boolean v1, p0, Lh/z;->Q:Z

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    iget-boolean v3, v2, Lh/y;->m:Z

    .line 11
    .line 12
    const/4 v4, 0x1

    .line 13
    if-eqz v3, :cond_0

    .line 14
    .line 15
    if-nez v0, :cond_3

    .line 16
    .line 17
    invoke-virtual {p0, v2, v4}, Lh/z;->w(Lh/y;Z)V

    .line 18
    .line 19
    .line 20
    return v4

    .line 21
    :cond_0
    iget-object v0, p0, Lh/z;->x:Lk/a;

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v0}, Lk/a;->a()V

    .line 26
    .line 27
    .line 28
    return v4

    .line 29
    :cond_1
    invoke-virtual {p0}, Lh/z;->E()V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lh/z;->r:Lh/i0;

    .line 33
    .line 34
    if-eqz p0, :cond_4

    .line 35
    .line 36
    iget-object p0, p0, Lh/i0;->e:Lm/f1;

    .line 37
    .line 38
    if-eqz p0, :cond_4

    .line 39
    .line 40
    move-object v0, p0

    .line 41
    check-cast v0, Lm/w2;

    .line 42
    .line 43
    iget-object v0, v0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 44
    .line 45
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->O:Lm/r2;

    .line 46
    .line 47
    if-eqz v0, :cond_4

    .line 48
    .line 49
    iget-object v0, v0, Lm/r2;->e:Ll/n;

    .line 50
    .line 51
    if-eqz v0, :cond_4

    .line 52
    .line 53
    check-cast p0, Lm/w2;

    .line 54
    .line 55
    iget-object p0, p0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 56
    .line 57
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->O:Lm/r2;

    .line 58
    .line 59
    if-nez p0, :cond_2

    .line 60
    .line 61
    const/4 p0, 0x0

    .line 62
    goto :goto_0

    .line 63
    :cond_2
    iget-object p0, p0, Lm/r2;->e:Ll/n;

    .line 64
    .line 65
    :goto_0
    if-eqz p0, :cond_3

    .line 66
    .line 67
    invoke-virtual {p0}, Ll/n;->collapseActionView()Z

    .line 68
    .line 69
    .line 70
    :cond_3
    return v4

    .line 71
    :cond_4
    return v1
.end method

.method public final I(Lh/y;Landroid/view/KeyEvent;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-boolean v2, v1, Lh/y;->m:Z

    .line 6
    .line 7
    iget v3, v1, Lh/y;->a:I

    .line 8
    .line 9
    if-nez v2, :cond_1a

    .line 10
    .line 11
    iget-boolean v2, v0, Lh/z;->T:Z

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    goto/16 :goto_9

    .line 16
    .line 17
    :cond_0
    iget-object v2, v0, Lh/z;->n:Landroid/content/Context;

    .line 18
    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    invoke-virtual {v4}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    iget v4, v4, Landroid/content/res/Configuration;->screenLayout:I

    .line 30
    .line 31
    and-int/lit8 v4, v4, 0xf

    .line 32
    .line 33
    const/4 v5, 0x4

    .line 34
    if-ne v4, v5, :cond_1

    .line 35
    .line 36
    goto/16 :goto_9

    .line 37
    .line 38
    :cond_1
    iget-object v4, v0, Lh/z;->o:Landroid/view/Window;

    .line 39
    .line 40
    invoke-virtual {v4}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    const/4 v5, 0x1

    .line 45
    if-eqz v4, :cond_2

    .line 46
    .line 47
    iget-object v6, v1, Lh/y;->h:Ll/l;

    .line 48
    .line 49
    invoke-interface {v4, v3, v6}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    if-nez v4, :cond_2

    .line 54
    .line 55
    invoke-virtual {v0, v1, v5}, Lh/z;->w(Lh/y;Z)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    const-string v4, "window"

    .line 60
    .line 61
    invoke-virtual {v2, v4}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    check-cast v4, Landroid/view/WindowManager;

    .line 66
    .line 67
    if-nez v4, :cond_3

    .line 68
    .line 69
    goto/16 :goto_9

    .line 70
    .line 71
    :cond_3
    invoke-virtual/range {p0 .. p2}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 72
    .line 73
    .line 74
    move-result v6

    .line 75
    if-nez v6, :cond_4

    .line 76
    .line 77
    goto/16 :goto_9

    .line 78
    .line 79
    :cond_4
    iget-object v6, v1, Lh/y;->e:Lh/x;

    .line 80
    .line 81
    const/4 v7, 0x0

    .line 82
    const/4 v8, -0x2

    .line 83
    if-eqz v6, :cond_6

    .line 84
    .line 85
    iget-boolean v9, v1, Lh/y;->n:Z

    .line 86
    .line 87
    if-eqz v9, :cond_5

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_5
    iget-object v2, v1, Lh/y;->g:Landroid/view/View;

    .line 91
    .line 92
    if-eqz v2, :cond_18

    .line 93
    .line 94
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    if-eqz v2, :cond_18

    .line 99
    .line 100
    iget v2, v2, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 101
    .line 102
    const/4 v6, -0x1

    .line 103
    if-ne v2, v6, :cond_18

    .line 104
    .line 105
    move v10, v6

    .line 106
    goto/16 :goto_7

    .line 107
    .line 108
    :cond_6
    :goto_0
    if-nez v6, :cond_b

    .line 109
    .line 110
    invoke-virtual {v0}, Lh/z;->E()V

    .line 111
    .line 112
    .line 113
    iget-object v6, v0, Lh/z;->r:Lh/i0;

    .line 114
    .line 115
    if-eqz v6, :cond_7

    .line 116
    .line 117
    invoke-virtual {v6}, Lh/i0;->d()Landroid/content/Context;

    .line 118
    .line 119
    .line 120
    move-result-object v6

    .line 121
    goto :goto_1

    .line 122
    :cond_7
    const/4 v6, 0x0

    .line 123
    :goto_1
    if-nez v6, :cond_8

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_8
    move-object v2, v6

    .line 127
    :goto_2
    new-instance v6, Landroid/util/TypedValue;

    .line 128
    .line 129
    invoke-direct {v6}, Landroid/util/TypedValue;-><init>()V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 133
    .line 134
    .line 135
    move-result-object v9

    .line 136
    invoke-virtual {v9}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    .line 137
    .line 138
    .line 139
    move-result-object v9

    .line 140
    invoke-virtual {v2}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 141
    .line 142
    .line 143
    move-result-object v10

    .line 144
    invoke-virtual {v9, v10}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    .line 145
    .line 146
    .line 147
    const v10, 0x7f040005

    .line 148
    .line 149
    .line 150
    invoke-virtual {v9, v10, v6, v5}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 151
    .line 152
    .line 153
    iget v10, v6, Landroid/util/TypedValue;->resourceId:I

    .line 154
    .line 155
    if-eqz v10, :cond_9

    .line 156
    .line 157
    invoke-virtual {v9, v10, v5}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 158
    .line 159
    .line 160
    :cond_9
    const v10, 0x7f040433

    .line 161
    .line 162
    .line 163
    invoke-virtual {v9, v10, v6, v5}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 164
    .line 165
    .line 166
    iget v6, v6, Landroid/util/TypedValue;->resourceId:I

    .line 167
    .line 168
    if-eqz v6, :cond_a

    .line 169
    .line 170
    invoke-virtual {v9, v6, v5}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 171
    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_a
    const v6, 0x7f1302ee

    .line 175
    .line 176
    .line 177
    invoke-virtual {v9, v6, v5}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 178
    .line 179
    .line 180
    :goto_3
    new-instance v6, Lk/c;

    .line 181
    .line 182
    invoke-direct {v6, v2, v7}, Lk/c;-><init>(Landroid/content/Context;I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v6}, Lk/c;->getTheme()Landroid/content/res/Resources$Theme;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    invoke-virtual {v2, v9}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    .line 190
    .line 191
    .line 192
    iput-object v6, v1, Lh/y;->j:Lk/c;

    .line 193
    .line 194
    sget-object v2, Lg/a;->j:[I

    .line 195
    .line 196
    invoke-virtual {v6, v2}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    const/16 v6, 0x56

    .line 201
    .line 202
    invoke-virtual {v2, v6, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 203
    .line 204
    .line 205
    move-result v6

    .line 206
    iput v6, v1, Lh/y;->b:I

    .line 207
    .line 208
    invoke-virtual {v2, v5, v7}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 209
    .line 210
    .line 211
    move-result v6

    .line 212
    iput v6, v1, Lh/y;->d:I

    .line 213
    .line 214
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 215
    .line 216
    .line 217
    new-instance v2, Lh/x;

    .line 218
    .line 219
    iget-object v6, v1, Lh/y;->j:Lk/c;

    .line 220
    .line 221
    invoke-direct {v2, v0, v6}, Lh/x;-><init>(Lh/z;Lk/c;)V

    .line 222
    .line 223
    .line 224
    iput-object v2, v1, Lh/y;->e:Lh/x;

    .line 225
    .line 226
    const/16 v2, 0x51

    .line 227
    .line 228
    iput v2, v1, Lh/y;->c:I

    .line 229
    .line 230
    goto :goto_4

    .line 231
    :cond_b
    iget-boolean v2, v1, Lh/y;->n:Z

    .line 232
    .line 233
    if-eqz v2, :cond_c

    .line 234
    .line 235
    invoke-virtual {v6}, Landroid/view/ViewGroup;->getChildCount()I

    .line 236
    .line 237
    .line 238
    move-result v2

    .line 239
    if-lez v2, :cond_c

    .line 240
    .line 241
    iget-object v2, v1, Lh/y;->e:Lh/x;

    .line 242
    .line 243
    invoke-virtual {v2}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 244
    .line 245
    .line 246
    :cond_c
    :goto_4
    iget-object v2, v1, Lh/y;->g:Landroid/view/View;

    .line 247
    .line 248
    if-eqz v2, :cond_d

    .line 249
    .line 250
    iput-object v2, v1, Lh/y;->f:Landroid/view/View;

    .line 251
    .line 252
    goto :goto_5

    .line 253
    :cond_d
    iget-object v2, v1, Lh/y;->h:Ll/l;

    .line 254
    .line 255
    if-nez v2, :cond_e

    .line 256
    .line 257
    goto/16 :goto_8

    .line 258
    .line 259
    :cond_e
    iget-object v2, v0, Lh/z;->w:Lh/p;

    .line 260
    .line 261
    if-nez v2, :cond_f

    .line 262
    .line 263
    new-instance v2, Lh/p;

    .line 264
    .line 265
    invoke-direct {v2, v0}, Lh/p;-><init>(Lh/z;)V

    .line 266
    .line 267
    .line 268
    iput-object v2, v0, Lh/z;->w:Lh/p;

    .line 269
    .line 270
    :cond_f
    iget-object v2, v0, Lh/z;->w:Lh/p;

    .line 271
    .line 272
    iget-object v6, v1, Lh/y;->i:Ll/h;

    .line 273
    .line 274
    if-nez v6, :cond_10

    .line 275
    .line 276
    new-instance v6, Ll/h;

    .line 277
    .line 278
    iget-object v9, v1, Lh/y;->j:Lk/c;

    .line 279
    .line 280
    invoke-direct {v6, v9}, Ll/h;-><init>(Landroid/content/Context;)V

    .line 281
    .line 282
    .line 283
    iput-object v6, v1, Lh/y;->i:Ll/h;

    .line 284
    .line 285
    iput-object v2, v6, Ll/h;->h:Ll/w;

    .line 286
    .line 287
    iget-object v2, v1, Lh/y;->h:Ll/l;

    .line 288
    .line 289
    iget-object v9, v2, Ll/l;->a:Landroid/content/Context;

    .line 290
    .line 291
    invoke-virtual {v2, v6, v9}, Ll/l;->b(Ll/x;Landroid/content/Context;)V

    .line 292
    .line 293
    .line 294
    :cond_10
    iget-object v2, v1, Lh/y;->i:Ll/h;

    .line 295
    .line 296
    iget-object v6, v1, Lh/y;->e:Lh/x;

    .line 297
    .line 298
    iget-object v9, v2, Ll/h;->g:Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 299
    .line 300
    if-nez v9, :cond_12

    .line 301
    .line 302
    iget-object v9, v2, Ll/h;->e:Landroid/view/LayoutInflater;

    .line 303
    .line 304
    const v10, 0x7f0d000d

    .line 305
    .line 306
    .line 307
    invoke-virtual {v9, v10, v6, v7}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 308
    .line 309
    .line 310
    move-result-object v6

    .line 311
    check-cast v6, Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 312
    .line 313
    iput-object v6, v2, Ll/h;->g:Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 314
    .line 315
    iget-object v6, v2, Ll/h;->i:Ll/g;

    .line 316
    .line 317
    if-nez v6, :cond_11

    .line 318
    .line 319
    new-instance v6, Ll/g;

    .line 320
    .line 321
    invoke-direct {v6, v2}, Ll/g;-><init>(Ll/h;)V

    .line 322
    .line 323
    .line 324
    iput-object v6, v2, Ll/h;->i:Ll/g;

    .line 325
    .line 326
    :cond_11
    iget-object v6, v2, Ll/h;->g:Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 327
    .line 328
    iget-object v9, v2, Ll/h;->i:Ll/g;

    .line 329
    .line 330
    invoke-virtual {v6, v9}, Landroid/widget/AbsListView;->setAdapter(Landroid/widget/ListAdapter;)V

    .line 331
    .line 332
    .line 333
    iget-object v6, v2, Ll/h;->g:Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 334
    .line 335
    invoke-virtual {v6, v2}, Landroid/widget/AdapterView;->setOnItemClickListener(Landroid/widget/AdapterView$OnItemClickListener;)V

    .line 336
    .line 337
    .line 338
    :cond_12
    iget-object v2, v2, Ll/h;->g:Landroidx/appcompat/view/menu/ExpandedMenuView;

    .line 339
    .line 340
    iput-object v2, v1, Lh/y;->f:Landroid/view/View;

    .line 341
    .line 342
    if-eqz v2, :cond_19

    .line 343
    .line 344
    :goto_5
    iget-object v2, v1, Lh/y;->f:Landroid/view/View;

    .line 345
    .line 346
    if-nez v2, :cond_13

    .line 347
    .line 348
    goto/16 :goto_8

    .line 349
    .line 350
    :cond_13
    iget-object v2, v1, Lh/y;->g:Landroid/view/View;

    .line 351
    .line 352
    if-eqz v2, :cond_14

    .line 353
    .line 354
    goto :goto_6

    .line 355
    :cond_14
    iget-object v2, v1, Lh/y;->i:Ll/h;

    .line 356
    .line 357
    iget-object v6, v2, Ll/h;->i:Ll/g;

    .line 358
    .line 359
    if-nez v6, :cond_15

    .line 360
    .line 361
    new-instance v6, Ll/g;

    .line 362
    .line 363
    invoke-direct {v6, v2}, Ll/g;-><init>(Ll/h;)V

    .line 364
    .line 365
    .line 366
    iput-object v6, v2, Ll/h;->i:Ll/g;

    .line 367
    .line 368
    :cond_15
    iget-object v2, v2, Ll/h;->i:Ll/g;

    .line 369
    .line 370
    invoke-virtual {v2}, Ll/g;->getCount()I

    .line 371
    .line 372
    .line 373
    move-result v2

    .line 374
    if-lez v2, :cond_19

    .line 375
    .line 376
    :goto_6
    iget-object v2, v1, Lh/y;->f:Landroid/view/View;

    .line 377
    .line 378
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 379
    .line 380
    .line 381
    move-result-object v2

    .line 382
    if-nez v2, :cond_16

    .line 383
    .line 384
    new-instance v2, Landroid/view/ViewGroup$LayoutParams;

    .line 385
    .line 386
    invoke-direct {v2, v8, v8}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 387
    .line 388
    .line 389
    :cond_16
    iget v6, v1, Lh/y;->b:I

    .line 390
    .line 391
    iget-object v9, v1, Lh/y;->e:Lh/x;

    .line 392
    .line 393
    invoke-virtual {v9, v6}, Lh/x;->setBackgroundResource(I)V

    .line 394
    .line 395
    .line 396
    iget-object v6, v1, Lh/y;->f:Landroid/view/View;

    .line 397
    .line 398
    invoke-virtual {v6}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 399
    .line 400
    .line 401
    move-result-object v6

    .line 402
    instance-of v9, v6, Landroid/view/ViewGroup;

    .line 403
    .line 404
    if-eqz v9, :cond_17

    .line 405
    .line 406
    check-cast v6, Landroid/view/ViewGroup;

    .line 407
    .line 408
    iget-object v9, v1, Lh/y;->f:Landroid/view/View;

    .line 409
    .line 410
    invoke-virtual {v6, v9}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 411
    .line 412
    .line 413
    :cond_17
    iget-object v6, v1, Lh/y;->e:Lh/x;

    .line 414
    .line 415
    iget-object v9, v1, Lh/y;->f:Landroid/view/View;

    .line 416
    .line 417
    invoke-virtual {v6, v9, v2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 418
    .line 419
    .line 420
    iget-object v2, v1, Lh/y;->f:Landroid/view/View;

    .line 421
    .line 422
    invoke-virtual {v2}, Landroid/view/View;->hasFocus()Z

    .line 423
    .line 424
    .line 425
    move-result v2

    .line 426
    if-nez v2, :cond_18

    .line 427
    .line 428
    iget-object v2, v1, Lh/y;->f:Landroid/view/View;

    .line 429
    .line 430
    invoke-virtual {v2}, Landroid/view/View;->requestFocus()Z

    .line 431
    .line 432
    .line 433
    :cond_18
    move v10, v8

    .line 434
    :goto_7
    iput-boolean v7, v1, Lh/y;->l:Z

    .line 435
    .line 436
    new-instance v9, Landroid/view/WindowManager$LayoutParams;

    .line 437
    .line 438
    const/high16 v15, 0x820000

    .line 439
    .line 440
    const/16 v16, -0x3

    .line 441
    .line 442
    const/4 v11, -0x2

    .line 443
    const/4 v12, 0x0

    .line 444
    const/4 v13, 0x0

    .line 445
    const/16 v14, 0x3ea

    .line 446
    .line 447
    invoke-direct/range {v9 .. v16}, Landroid/view/WindowManager$LayoutParams;-><init>(IIIIIII)V

    .line 448
    .line 449
    .line 450
    iget v2, v1, Lh/y;->c:I

    .line 451
    .line 452
    iput v2, v9, Landroid/view/WindowManager$LayoutParams;->gravity:I

    .line 453
    .line 454
    iget v2, v1, Lh/y;->d:I

    .line 455
    .line 456
    iput v2, v9, Landroid/view/WindowManager$LayoutParams;->windowAnimations:I

    .line 457
    .line 458
    iget-object v2, v1, Lh/y;->e:Lh/x;

    .line 459
    .line 460
    invoke-interface {v4, v2, v9}, Landroid/view/ViewManager;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 461
    .line 462
    .line 463
    iput-boolean v5, v1, Lh/y;->m:Z

    .line 464
    .line 465
    if-nez v3, :cond_1a

    .line 466
    .line 467
    invoke-virtual {v0}, Lh/z;->M()V

    .line 468
    .line 469
    .line 470
    return-void

    .line 471
    :cond_19
    :goto_8
    iput-boolean v5, v1, Lh/y;->n:Z

    .line 472
    .line 473
    :cond_1a
    :goto_9
    return-void
.end method

.method public final J(Lh/y;ILandroid/view/KeyEvent;)Z
    .locals 2

    .line 1
    invoke-virtual {p3}, Landroid/view/KeyEvent;->isSystem()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    iget-boolean v0, p1, Lh/y;->k:Z

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0, p1, p3}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_2

    .line 18
    .line 19
    :cond_1
    iget-object p0, p1, Lh/y;->h:Ll/l;

    .line 20
    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    const/4 p1, 0x1

    .line 24
    invoke-virtual {p0, p2, p3, p1}, Ll/l;->performShortcut(ILandroid/view/KeyEvent;I)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    :cond_2
    return v1
.end method

.method public final K(Lh/y;Landroid/view/KeyEvent;)Z
    .locals 12

    .line 1
    iget-boolean v0, p0, Lh/z;->T:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    goto/16 :goto_5

    .line 7
    .line 8
    :cond_0
    iget-boolean v0, p1, Lh/y;->k:Z

    .line 9
    .line 10
    iget v2, p1, Lh/y;->a:I

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    return v3

    .line 16
    :cond_1
    iget-object v0, p0, Lh/z;->P:Lh/y;

    .line 17
    .line 18
    if-eqz v0, :cond_2

    .line 19
    .line 20
    if-eq v0, p1, :cond_2

    .line 21
    .line 22
    invoke-virtual {p0, v0, v1}, Lh/z;->w(Lh/y;Z)V

    .line 23
    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    invoke-interface {v0, v2}, Landroid/view/Window$Callback;->onCreatePanelView(I)Landroid/view/View;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iput-object v4, p1, Lh/y;->g:Landroid/view/View;

    .line 38
    .line 39
    :cond_3
    const/16 v4, 0x6c

    .line 40
    .line 41
    if-eqz v2, :cond_5

    .line 42
    .line 43
    if-ne v2, v4, :cond_4

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    move v5, v1

    .line 47
    goto :goto_1

    .line 48
    :cond_5
    :goto_0
    move v5, v3

    .line 49
    :goto_1
    if-eqz v5, :cond_6

    .line 50
    .line 51
    iget-object v6, p0, Lh/z;->u:Lm/e1;

    .line 52
    .line 53
    if-eqz v6, :cond_6

    .line 54
    .line 55
    check-cast v6, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 56
    .line 57
    invoke-virtual {v6}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 58
    .line 59
    .line 60
    iget-object v6, v6, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 61
    .line 62
    check-cast v6, Lm/w2;

    .line 63
    .line 64
    iput-boolean v3, v6, Lm/w2;->l:Z

    .line 65
    .line 66
    :cond_6
    iget-object v6, p1, Lh/y;->g:Landroid/view/View;

    .line 67
    .line 68
    if-nez v6, :cond_1d

    .line 69
    .line 70
    iget-object v6, p1, Lh/y;->h:Ll/l;

    .line 71
    .line 72
    const/4 v7, 0x0

    .line 73
    if-eqz v6, :cond_7

    .line 74
    .line 75
    iget-boolean v8, p1, Lh/y;->o:Z

    .line 76
    .line 77
    if-eqz v8, :cond_17

    .line 78
    .line 79
    :cond_7
    if-nez v6, :cond_10

    .line 80
    .line 81
    iget-object v6, p0, Lh/z;->n:Landroid/content/Context;

    .line 82
    .line 83
    if-eqz v2, :cond_8

    .line 84
    .line 85
    if-ne v2, v4, :cond_c

    .line 86
    .line 87
    :cond_8
    iget-object v4, p0, Lh/z;->u:Lm/e1;

    .line 88
    .line 89
    if-eqz v4, :cond_c

    .line 90
    .line 91
    new-instance v4, Landroid/util/TypedValue;

    .line 92
    .line 93
    invoke-direct {v4}, Landroid/util/TypedValue;-><init>()V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v6}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    const v9, 0x7f04000c

    .line 101
    .line 102
    .line 103
    invoke-virtual {v8, v9, v4, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 104
    .line 105
    .line 106
    iget v9, v4, Landroid/util/TypedValue;->resourceId:I

    .line 107
    .line 108
    const v10, 0x7f04000d

    .line 109
    .line 110
    .line 111
    if-eqz v9, :cond_9

    .line 112
    .line 113
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 114
    .line 115
    .line 116
    move-result-object v9

    .line 117
    invoke-virtual {v9}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    .line 118
    .line 119
    .line 120
    move-result-object v9

    .line 121
    invoke-virtual {v9, v8}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    .line 122
    .line 123
    .line 124
    iget v11, v4, Landroid/util/TypedValue;->resourceId:I

    .line 125
    .line 126
    invoke-virtual {v9, v11, v3}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, v10, v4, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 130
    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_9
    invoke-virtual {v8, v10, v4, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 134
    .line 135
    .line 136
    move-object v9, v7

    .line 137
    :goto_2
    iget v10, v4, Landroid/util/TypedValue;->resourceId:I

    .line 138
    .line 139
    if-eqz v10, :cond_b

    .line 140
    .line 141
    if-nez v9, :cond_a

    .line 142
    .line 143
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 144
    .line 145
    .line 146
    move-result-object v9

    .line 147
    invoke-virtual {v9}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    .line 148
    .line 149
    .line 150
    move-result-object v9

    .line 151
    invoke-virtual {v9, v8}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    .line 152
    .line 153
    .line 154
    :cond_a
    iget v4, v4, Landroid/util/TypedValue;->resourceId:I

    .line 155
    .line 156
    invoke-virtual {v9, v4, v3}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 157
    .line 158
    .line 159
    :cond_b
    if-eqz v9, :cond_c

    .line 160
    .line 161
    new-instance v4, Lk/c;

    .line 162
    .line 163
    invoke-direct {v4, v6, v1}, Lk/c;-><init>(Landroid/content/Context;I)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v4}, Lk/c;->getTheme()Landroid/content/res/Resources$Theme;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    invoke-virtual {v6, v9}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    .line 171
    .line 172
    .line 173
    move-object v6, v4

    .line 174
    :cond_c
    new-instance v4, Ll/l;

    .line 175
    .line 176
    invoke-direct {v4, v6}, Ll/l;-><init>(Landroid/content/Context;)V

    .line 177
    .line 178
    .line 179
    iput-object p0, v4, Ll/l;->e:Ll/j;

    .line 180
    .line 181
    iget-object v6, p1, Lh/y;->h:Ll/l;

    .line 182
    .line 183
    if-ne v4, v6, :cond_d

    .line 184
    .line 185
    goto :goto_3

    .line 186
    :cond_d
    if-eqz v6, :cond_e

    .line 187
    .line 188
    iget-object v8, p1, Lh/y;->i:Ll/h;

    .line 189
    .line 190
    invoke-virtual {v6, v8}, Ll/l;->r(Ll/x;)V

    .line 191
    .line 192
    .line 193
    :cond_e
    iput-object v4, p1, Lh/y;->h:Ll/l;

    .line 194
    .line 195
    iget-object v6, p1, Lh/y;->i:Ll/h;

    .line 196
    .line 197
    if-eqz v6, :cond_f

    .line 198
    .line 199
    iget-object v8, v4, Ll/l;->a:Landroid/content/Context;

    .line 200
    .line 201
    invoke-virtual {v4, v6, v8}, Ll/l;->b(Ll/x;Landroid/content/Context;)V

    .line 202
    .line 203
    .line 204
    :cond_f
    :goto_3
    iget-object v4, p1, Lh/y;->h:Ll/l;

    .line 205
    .line 206
    if-nez v4, :cond_10

    .line 207
    .line 208
    goto :goto_5

    .line 209
    :cond_10
    if-eqz v5, :cond_12

    .line 210
    .line 211
    iget-object v4, p0, Lh/z;->u:Lm/e1;

    .line 212
    .line 213
    if-eqz v4, :cond_12

    .line 214
    .line 215
    iget-object v6, p0, Lh/z;->v:Laq/a;

    .line 216
    .line 217
    if-nez v6, :cond_11

    .line 218
    .line 219
    new-instance v6, Laq/a;

    .line 220
    .line 221
    const/16 v8, 0x1b

    .line 222
    .line 223
    invoke-direct {v6, p0, v8}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 224
    .line 225
    .line 226
    iput-object v6, p0, Lh/z;->v:Laq/a;

    .line 227
    .line 228
    :cond_11
    iget-object v6, p1, Lh/y;->h:Ll/l;

    .line 229
    .line 230
    iget-object v8, p0, Lh/z;->v:Laq/a;

    .line 231
    .line 232
    check-cast v4, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 233
    .line 234
    invoke-virtual {v4, v6, v8}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->l(Landroid/view/Menu;Ll/w;)V

    .line 235
    .line 236
    .line 237
    :cond_12
    iget-object v4, p1, Lh/y;->h:Ll/l;

    .line 238
    .line 239
    invoke-virtual {v4}, Ll/l;->w()V

    .line 240
    .line 241
    .line 242
    iget-object v4, p1, Lh/y;->h:Ll/l;

    .line 243
    .line 244
    invoke-interface {v0, v2, v4}, Landroid/view/Window$Callback;->onCreatePanelMenu(ILandroid/view/Menu;)Z

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    if-nez v2, :cond_16

    .line 249
    .line 250
    iget-object p2, p1, Lh/y;->h:Ll/l;

    .line 251
    .line 252
    if-nez p2, :cond_13

    .line 253
    .line 254
    goto :goto_4

    .line 255
    :cond_13
    if-eqz p2, :cond_14

    .line 256
    .line 257
    iget-object v0, p1, Lh/y;->i:Ll/h;

    .line 258
    .line 259
    invoke-virtual {p2, v0}, Ll/l;->r(Ll/x;)V

    .line 260
    .line 261
    .line 262
    :cond_14
    iput-object v7, p1, Lh/y;->h:Ll/l;

    .line 263
    .line 264
    :goto_4
    if-eqz v5, :cond_15

    .line 265
    .line 266
    iget-object p1, p0, Lh/z;->u:Lm/e1;

    .line 267
    .line 268
    if-eqz p1, :cond_15

    .line 269
    .line 270
    iget-object p0, p0, Lh/z;->v:Laq/a;

    .line 271
    .line 272
    check-cast p1, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 273
    .line 274
    invoke-virtual {p1, v7, p0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->l(Landroid/view/Menu;Ll/w;)V

    .line 275
    .line 276
    .line 277
    :cond_15
    :goto_5
    return v1

    .line 278
    :cond_16
    iput-boolean v1, p1, Lh/y;->o:Z

    .line 279
    .line 280
    :cond_17
    iget-object v2, p1, Lh/y;->h:Ll/l;

    .line 281
    .line 282
    invoke-virtual {v2}, Ll/l;->w()V

    .line 283
    .line 284
    .line 285
    iget-object v2, p1, Lh/y;->p:Landroid/os/Bundle;

    .line 286
    .line 287
    if-eqz v2, :cond_18

    .line 288
    .line 289
    iget-object v4, p1, Lh/y;->h:Ll/l;

    .line 290
    .line 291
    invoke-virtual {v4, v2}, Ll/l;->s(Landroid/os/Bundle;)V

    .line 292
    .line 293
    .line 294
    iput-object v7, p1, Lh/y;->p:Landroid/os/Bundle;

    .line 295
    .line 296
    :cond_18
    iget-object v2, p1, Lh/y;->g:Landroid/view/View;

    .line 297
    .line 298
    iget-object v4, p1, Lh/y;->h:Ll/l;

    .line 299
    .line 300
    invoke-interface {v0, v1, v2, v4}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    .line 301
    .line 302
    .line 303
    move-result v0

    .line 304
    if-nez v0, :cond_1a

    .line 305
    .line 306
    if-eqz v5, :cond_19

    .line 307
    .line 308
    iget-object p2, p0, Lh/z;->u:Lm/e1;

    .line 309
    .line 310
    if-eqz p2, :cond_19

    .line 311
    .line 312
    iget-object p0, p0, Lh/z;->v:Laq/a;

    .line 313
    .line 314
    check-cast p2, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 315
    .line 316
    invoke-virtual {p2, v7, p0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->l(Landroid/view/Menu;Ll/w;)V

    .line 317
    .line 318
    .line 319
    :cond_19
    iget-object p0, p1, Lh/y;->h:Ll/l;

    .line 320
    .line 321
    invoke-virtual {p0}, Ll/l;->v()V

    .line 322
    .line 323
    .line 324
    return v1

    .line 325
    :cond_1a
    if-eqz p2, :cond_1b

    .line 326
    .line 327
    invoke-virtual {p2}, Landroid/view/KeyEvent;->getDeviceId()I

    .line 328
    .line 329
    .line 330
    move-result p2

    .line 331
    goto :goto_6

    .line 332
    :cond_1b
    const/4 p2, -0x1

    .line 333
    :goto_6
    invoke-static {p2}, Landroid/view/KeyCharacterMap;->load(I)Landroid/view/KeyCharacterMap;

    .line 334
    .line 335
    .line 336
    move-result-object p2

    .line 337
    invoke-virtual {p2}, Landroid/view/KeyCharacterMap;->getKeyboardType()I

    .line 338
    .line 339
    .line 340
    move-result p2

    .line 341
    if-eq p2, v3, :cond_1c

    .line 342
    .line 343
    move p2, v3

    .line 344
    goto :goto_7

    .line 345
    :cond_1c
    move p2, v1

    .line 346
    :goto_7
    iget-object v0, p1, Lh/y;->h:Ll/l;

    .line 347
    .line 348
    invoke-virtual {v0, p2}, Ll/l;->setQwertyMode(Z)V

    .line 349
    .line 350
    .line 351
    iget-object p2, p1, Lh/y;->h:Ll/l;

    .line 352
    .line 353
    invoke-virtual {p2}, Ll/l;->v()V

    .line 354
    .line 355
    .line 356
    :cond_1d
    iput-boolean v3, p1, Lh/y;->k:Z

    .line 357
    .line 358
    iput-boolean v1, p1, Lh/y;->l:Z

    .line 359
    .line 360
    iput-object p1, p0, Lh/z;->P:Lh/y;

    .line 361
    .line 362
    return v3
.end method

.method public final L()V
    .locals 1

    .line 1
    iget-boolean p0, p0, Lh/z;->C:Z

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Landroid/util/AndroidRuntimeException;

    .line 7
    .line 8
    const-string v0, "Window feature must be requested before adding content"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Landroid/util/AndroidRuntimeException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final M()V
    .locals 3

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x21

    .line 4
    .line 5
    if-lt v0, v1, :cond_4

    .line 6
    .line 7
    iget-object v0, p0, Lh/z;->r1:Landroid/window/OnBackInvokedDispatcher;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-boolean v0, v0, Lh/y;->m:Z

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    :goto_0
    move v1, v2

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    iget-object v0, p0, Lh/z;->x:Lk/a;

    .line 25
    .line 26
    if-eqz v0, :cond_2

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_2
    :goto_1
    if-eqz v1, :cond_3

    .line 30
    .line 31
    iget-object v0, p0, Lh/z;->s1:Landroid/window/OnBackInvokedCallback;

    .line 32
    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    iget-object v0, p0, Lh/z;->r1:Landroid/window/OnBackInvokedDispatcher;

    .line 36
    .line 37
    invoke-static {v0, p0}, Lh/t;->b(Ljava/lang/Object;Lh/z;)Landroid/window/OnBackInvokedCallback;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iput-object v0, p0, Lh/z;->s1:Landroid/window/OnBackInvokedCallback;

    .line 42
    .line 43
    return-void

    .line 44
    :cond_3
    if-nez v1, :cond_4

    .line 45
    .line 46
    iget-object v0, p0, Lh/z;->s1:Landroid/window/OnBackInvokedCallback;

    .line 47
    .line 48
    if-eqz v0, :cond_4

    .line 49
    .line 50
    iget-object v1, p0, Lh/z;->r1:Landroid/window/OnBackInvokedDispatcher;

    .line 51
    .line 52
    invoke-static {v1, v0}, Lh/t;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    const/4 v0, 0x0

    .line 56
    iput-object v0, p0, Lh/z;->s1:Landroid/window/OnBackInvokedCallback;

    .line 57
    .line 58
    :cond_4
    return-void
.end method

.method public final d()V
    .locals 2

    .line 1
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Landroid/view/LayoutInflater;->getFactory()Landroid/view/LayoutInflater$Factory;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Landroid/view/LayoutInflater;->setFactory2(Landroid/view/LayoutInflater$Factory2;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {v0}, Landroid/view/LayoutInflater;->getFactory2()Landroid/view/LayoutInflater$Factory2;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    instance-of p0, p0, Lh/z;

    .line 22
    .line 23
    if-nez p0, :cond_1

    .line 24
    .line 25
    const-string p0, "AppCompatDelegate"

    .line 26
    .line 27
    const-string v0, "The Activity\'s LayoutInflater already has a Factory installed so we can not install AppCompat\'s"

    .line 28
    .line 29
    invoke-static {p0, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 30
    .line 31
    .line 32
    :cond_1
    return-void
.end method

.method public final e()V
    .locals 1

    .line 1
    iget-object v0, p0, Lh/z;->r:Lh/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lh/z;->E()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lh/z;->r:Lh/i0;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-virtual {p0, v0}, Lh/z;->F(I)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final g()V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lh/z;->R:Z

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    invoke-virtual {p0, v1, v0}, Lh/z;->r(ZZ)Z

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lh/z;->B()V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lh/z;->m:Ljava/lang/Object;

    .line 12
    .line 13
    instance-of v2, v1, Landroid/app/Activity;

    .line 14
    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    :try_start_0
    check-cast v1, Landroid/app/Activity;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1

    .line 18
    .line 19
    :try_start_1
    invoke-virtual {v1}, Landroid/app/Activity;->getComponentName()Landroid/content/ComponentName;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-static {v1, v2}, Landroidx/core/app/c;->c(Landroid/content/Context;Landroid/content/ComponentName;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 27
    goto :goto_0

    .line 28
    :catch_0
    move-exception v1

    .line 29
    :try_start_2
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    invoke-direct {v2, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 32
    .line 33
    .line 34
    throw v2
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_1

    .line 35
    :catch_1
    const/4 v1, 0x0

    .line 36
    :goto_0
    if-eqz v1, :cond_1

    .line 37
    .line 38
    iget-object v1, p0, Lh/z;->r:Lh/i0;

    .line 39
    .line 40
    if-nez v1, :cond_0

    .line 41
    .line 42
    iput-boolean v0, p0, Lh/z;->e0:Z

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_0
    invoke-virtual {v1, v0}, Lh/i0;->f(Z)V

    .line 46
    .line 47
    .line 48
    :cond_1
    :goto_1
    sget-object v1, Lh/n;->k:Ljava/lang/Object;

    .line 49
    .line 50
    monitor-enter v1

    .line 51
    :try_start_3
    invoke-static {p0}, Lh/n;->i(Lh/z;)V

    .line 52
    .line 53
    .line 54
    sget-object v2, Lh/n;->j:Landroidx/collection/g;

    .line 55
    .line 56
    new-instance v3, Ljava/lang/ref/WeakReference;

    .line 57
    .line 58
    invoke-direct {v3, p0}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v2, v3}, Landroidx/collection/g;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    monitor-exit v1

    .line 65
    goto :goto_2

    .line 66
    :catchall_0
    move-exception p0

    .line 67
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 68
    throw p0

    .line 69
    :cond_2
    :goto_2
    new-instance v1, Landroid/content/res/Configuration;

    .line 70
    .line 71
    iget-object v2, p0, Lh/z;->n:Landroid/content/Context;

    .line 72
    .line 73
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-virtual {v2}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-direct {v1, v2}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    .line 82
    .line 83
    .line 84
    iput-object v1, p0, Lh/z;->U:Landroid/content/res/Configuration;

    .line 85
    .line 86
    iput-boolean v0, p0, Lh/z;->S:Z

    .line 87
    .line 88
    return-void
.end method

.method public final h()V
    .locals 3

    .line 1
    iget-object v0, p0, Lh/z;->m:Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v0, v0, Landroid/app/Activity;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Lh/n;->k:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    :try_start_0
    invoke-static {p0}, Lh/n;->i(Lh/z;)V

    .line 11
    .line 12
    .line 13
    monitor-exit v0

    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0

    .line 18
    :cond_0
    :goto_0
    iget-boolean v0, p0, Lh/z;->b0:Z

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 23
    .line 24
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget-object v1, p0, Lh/z;->d0:Lh/o;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 31
    .line 32
    .line 33
    :cond_1
    const/4 v0, 0x1

    .line 34
    iput-boolean v0, p0, Lh/z;->T:Z

    .line 35
    .line 36
    iget v0, p0, Lh/z;->V:I

    .line 37
    .line 38
    const/16 v1, -0x64

    .line 39
    .line 40
    if-eq v0, v1, :cond_2

    .line 41
    .line 42
    iget-object v0, p0, Lh/z;->m:Ljava/lang/Object;

    .line 43
    .line 44
    instance-of v1, v0, Landroid/app/Activity;

    .line 45
    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    check-cast v0, Landroid/app/Activity;

    .line 49
    .line 50
    invoke-virtual {v0}, Landroid/app/Activity;->isChangingConfigurations()Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_2

    .line 55
    .line 56
    sget-object v0, Lh/z;->t1:Landroidx/collection/a1;

    .line 57
    .line 58
    iget-object v1, p0, Lh/z;->m:Ljava/lang/Object;

    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    iget v2, p0, Lh/z;->V:I

    .line 69
    .line 70
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    invoke-virtual {v0, v1, v2}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_2
    sget-object v0, Lh/z;->t1:Landroidx/collection/a1;

    .line 79
    .line 80
    iget-object v1, p0, Lh/z;->m:Ljava/lang/Object;

    .line 81
    .line 82
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v0, v1}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    :goto_1
    iget-object v0, p0, Lh/z;->Z:Lh/v;

    .line 94
    .line 95
    if-eqz v0, :cond_3

    .line 96
    .line 97
    invoke-virtual {v0}, Lh/w;->c()V

    .line 98
    .line 99
    .line 100
    :cond_3
    iget-object p0, p0, Lh/z;->a0:Lh/v;

    .line 101
    .line 102
    if-eqz p0, :cond_4

    .line 103
    .line 104
    invoke-virtual {p0}, Lh/w;->c()V

    .line 105
    .line 106
    .line 107
    :cond_4
    return-void
.end method

.method public final j(I)Z
    .locals 5

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    const/16 v1, 0x6d

    .line 4
    .line 5
    const/16 v2, 0x6c

    .line 6
    .line 7
    const-string v3, "AppCompatDelegate"

    .line 8
    .line 9
    if-ne p1, v0, :cond_0

    .line 10
    .line 11
    const-string p1, "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR id when requesting this feature."

    .line 12
    .line 13
    invoke-static {v3, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 14
    .line 15
    .line 16
    move p1, v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/16 v0, 0x9

    .line 19
    .line 20
    if-ne p1, v0, :cond_1

    .line 21
    .line 22
    const-string p1, "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR_OVERLAY id when requesting this feature."

    .line 23
    .line 24
    invoke-static {v3, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move p1, v1

    .line 28
    :cond_1
    :goto_0
    iget-boolean v0, p0, Lh/z;->M:Z

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    if-ne p1, v2, :cond_2

    .line 34
    .line 35
    return v3

    .line 36
    :cond_2
    iget-boolean v0, p0, Lh/z;->I:Z

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    if-ne p1, v4, :cond_3

    .line 42
    .line 43
    iput-boolean v3, p0, Lh/z;->I:Z

    .line 44
    .line 45
    :cond_3
    if-eq p1, v4, :cond_9

    .line 46
    .line 47
    const/4 v0, 0x2

    .line 48
    if-eq p1, v0, :cond_8

    .line 49
    .line 50
    const/4 v0, 0x5

    .line 51
    if-eq p1, v0, :cond_7

    .line 52
    .line 53
    const/16 v0, 0xa

    .line 54
    .line 55
    if-eq p1, v0, :cond_6

    .line 56
    .line 57
    if-eq p1, v2, :cond_5

    .line 58
    .line 59
    if-eq p1, v1, :cond_4

    .line 60
    .line 61
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 62
    .line 63
    invoke-virtual {p0, p1}, Landroid/view/Window;->requestFeature(I)Z

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    return p0

    .line 68
    :cond_4
    invoke-virtual {p0}, Lh/z;->L()V

    .line 69
    .line 70
    .line 71
    iput-boolean v4, p0, Lh/z;->J:Z

    .line 72
    .line 73
    return v4

    .line 74
    :cond_5
    invoke-virtual {p0}, Lh/z;->L()V

    .line 75
    .line 76
    .line 77
    iput-boolean v4, p0, Lh/z;->I:Z

    .line 78
    .line 79
    return v4

    .line 80
    :cond_6
    invoke-virtual {p0}, Lh/z;->L()V

    .line 81
    .line 82
    .line 83
    iput-boolean v4, p0, Lh/z;->K:Z

    .line 84
    .line 85
    return v4

    .line 86
    :cond_7
    invoke-virtual {p0}, Lh/z;->L()V

    .line 87
    .line 88
    .line 89
    iput-boolean v4, p0, Lh/z;->H:Z

    .line 90
    .line 91
    return v4

    .line 92
    :cond_8
    invoke-virtual {p0}, Lh/z;->L()V

    .line 93
    .line 94
    .line 95
    iput-boolean v4, p0, Lh/z;->G:Z

    .line 96
    .line 97
    return v4

    .line 98
    :cond_9
    invoke-virtual {p0}, Lh/z;->L()V

    .line 99
    .line 100
    .line 101
    iput-boolean v4, p0, Lh/z;->M:Z

    .line 102
    .line 103
    return v4
.end method

.method public final k(I)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh/z;->A()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 5
    .line 6
    const v1, 0x1020002

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Landroid/view/ViewGroup;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lh/z;->n:Landroid/content/Context;

    .line 19
    .line 20
    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1, p1, v0}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lh/z;->p:Lh/u;

    .line 28
    .line 29
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p1, p0}, Lh/u;->a(Landroid/view/Window$Callback;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final l(Ll/l;)V
    .locals 5

    .line 1
    iget-object p1, p0, Lh/z;->u:Lm/e1;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz p1, :cond_5

    .line 6
    .line 7
    check-cast p1, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 8
    .line 9
    invoke-virtual {p1}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 10
    .line 11
    .line 12
    iget-object p1, p1, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 13
    .line 14
    check-cast p1, Lm/w2;

    .line 15
    .line 16
    iget-object p1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/view/View;->getVisibility()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-nez v2, :cond_5

    .line 23
    .line 24
    iget-object p1, p1, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 25
    .line 26
    if-eqz p1, :cond_5

    .line 27
    .line 28
    iget-boolean p1, p1, Landroidx/appcompat/widget/ActionMenuView;->v:Z

    .line 29
    .line 30
    if-eqz p1, :cond_5

    .line 31
    .line 32
    iget-object p1, p0, Lh/z;->n:Landroid/content/Context;

    .line 33
    .line 34
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p1}, Landroid/view/ViewConfiguration;->hasPermanentMenuKey()Z

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    if-eqz p1, :cond_0

    .line 43
    .line 44
    iget-object p1, p0, Lh/z;->u:Lm/e1;

    .line 45
    .line 46
    check-cast p1, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 47
    .line 48
    invoke-virtual {p1}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 49
    .line 50
    .line 51
    iget-object p1, p1, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 52
    .line 53
    check-cast p1, Lm/w2;

    .line 54
    .line 55
    iget-object p1, p1, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 56
    .line 57
    iget-object p1, p1, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 58
    .line 59
    if-eqz p1, :cond_5

    .line 60
    .line 61
    iget-object p1, p1, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 62
    .line 63
    if-eqz p1, :cond_5

    .line 64
    .line 65
    iget-object v2, p1, Lm/j;->x:Lm/h;

    .line 66
    .line 67
    if-nez v2, :cond_0

    .line 68
    .line 69
    invoke-virtual {p1}, Lm/j;->k()Z

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-eqz p1, :cond_5

    .line 74
    .line 75
    :cond_0
    iget-object p1, p0, Lh/z;->o:Landroid/view/Window;

    .line 76
    .line 77
    invoke-virtual {p1}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    iget-object v2, p0, Lh/z;->u:Lm/e1;

    .line 82
    .line 83
    check-cast v2, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 84
    .line 85
    invoke-virtual {v2}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 86
    .line 87
    .line 88
    iget-object v2, v2, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 89
    .line 90
    check-cast v2, Lm/w2;

    .line 91
    .line 92
    iget-object v2, v2, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 93
    .line 94
    iget-object v2, v2, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 95
    .line 96
    const/16 v3, 0x6c

    .line 97
    .line 98
    if-eqz v2, :cond_2

    .line 99
    .line 100
    iget-object v2, v2, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 101
    .line 102
    if-eqz v2, :cond_2

    .line 103
    .line 104
    invoke-virtual {v2}, Lm/j;->k()Z

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    if-eqz v2, :cond_2

    .line 109
    .line 110
    iget-object v0, p0, Lh/z;->u:Lm/e1;

    .line 111
    .line 112
    check-cast v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 113
    .line 114
    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 115
    .line 116
    .line 117
    iget-object v0, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 118
    .line 119
    check-cast v0, Lm/w2;

    .line 120
    .line 121
    iget-object v0, v0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 122
    .line 123
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 124
    .line 125
    if-eqz v0, :cond_1

    .line 126
    .line 127
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 128
    .line 129
    if-eqz v0, :cond_1

    .line 130
    .line 131
    invoke-virtual {v0}, Lm/j;->b()Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    :cond_1
    iget-boolean v0, p0, Lh/z;->T:Z

    .line 136
    .line 137
    if-nez v0, :cond_4

    .line 138
    .line 139
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    iget-object p0, p0, Lh/y;->h:Ll/l;

    .line 144
    .line 145
    invoke-interface {p1, v3, p0}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_2
    if-eqz p1, :cond_4

    .line 150
    .line 151
    iget-boolean v2, p0, Lh/z;->T:Z

    .line 152
    .line 153
    if-nez v2, :cond_4

    .line 154
    .line 155
    iget-boolean v2, p0, Lh/z;->b0:Z

    .line 156
    .line 157
    if-eqz v2, :cond_3

    .line 158
    .line 159
    iget v2, p0, Lh/z;->c0:I

    .line 160
    .line 161
    and-int/2addr v0, v2

    .line 162
    if-eqz v0, :cond_3

    .line 163
    .line 164
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 165
    .line 166
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    iget-object v2, p0, Lh/z;->d0:Lh/o;

    .line 171
    .line 172
    invoke-virtual {v0, v2}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 173
    .line 174
    .line 175
    invoke-virtual {v2}, Lh/o;->run()V

    .line 176
    .line 177
    .line 178
    :cond_3
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    iget-object v2, v0, Lh/y;->h:Ll/l;

    .line 183
    .line 184
    if-eqz v2, :cond_4

    .line 185
    .line 186
    iget-boolean v4, v0, Lh/y;->o:Z

    .line 187
    .line 188
    if-nez v4, :cond_4

    .line 189
    .line 190
    iget-object v4, v0, Lh/y;->g:Landroid/view/View;

    .line 191
    .line 192
    invoke-interface {p1, v1, v4, v2}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    .line 193
    .line 194
    .line 195
    move-result v1

    .line 196
    if-eqz v1, :cond_4

    .line 197
    .line 198
    iget-object v0, v0, Lh/y;->h:Ll/l;

    .line 199
    .line 200
    invoke-interface {p1, v3, v0}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    .line 201
    .line 202
    .line 203
    iget-object p0, p0, Lh/z;->u:Lm/e1;

    .line 204
    .line 205
    check-cast p0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 206
    .line 207
    invoke-virtual {p0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 208
    .line 209
    .line 210
    iget-object p0, p0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 211
    .line 212
    check-cast p0, Lm/w2;

    .line 213
    .line 214
    iget-object p0, p0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 215
    .line 216
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 217
    .line 218
    if-eqz p0, :cond_4

    .line 219
    .line 220
    iget-object p0, p0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 221
    .line 222
    if-eqz p0, :cond_4

    .line 223
    .line 224
    invoke-virtual {p0}, Lm/j;->l()Z

    .line 225
    .line 226
    .line 227
    :cond_4
    return-void

    .line 228
    :cond_5
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 229
    .line 230
    .line 231
    move-result-object p1

    .line 232
    iput-boolean v0, p1, Lh/y;->n:Z

    .line 233
    .line 234
    invoke-virtual {p0, p1, v1}, Lh/z;->w(Lh/y;Z)V

    .line 235
    .line 236
    .line 237
    const/4 v0, 0x0

    .line 238
    invoke-virtual {p0, p1, v0}, Lh/z;->I(Lh/y;Landroid/view/KeyEvent;)V

    .line 239
    .line 240
    .line 241
    return-void
.end method

.method public final m(Ll/l;Landroid/view/MenuItem;)Z
    .locals 6

    .line 1
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    iget-boolean v2, p0, Lh/z;->T:Z

    .line 11
    .line 12
    if-nez v2, :cond_3

    .line 13
    .line 14
    invoke-virtual {p1}, Ll/l;->k()Ll/l;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget-object p0, p0, Lh/z;->O:[Lh/y;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    array-length v2, p0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v2, v1

    .line 25
    :goto_0
    move v3, v1

    .line 26
    :goto_1
    if-ge v3, v2, :cond_2

    .line 27
    .line 28
    aget-object v4, p0, v3

    .line 29
    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    iget-object v5, v4, Lh/y;->h:Ll/l;

    .line 33
    .line 34
    if-ne v5, p1, :cond_1

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    const/4 v4, 0x0

    .line 41
    :goto_2
    if-eqz v4, :cond_3

    .line 42
    .line 43
    iget p0, v4, Lh/y;->a:I

    .line 44
    .line 45
    invoke-interface {v0, p0, p2}, Landroid/view/Window$Callback;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0

    .line 50
    :cond_3
    return v1
.end method

.method public final n(Landroid/view/View;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh/z;->A()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 5
    .line 6
    const v1, 0x1020002

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Landroid/view/ViewGroup;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lh/z;->p:Lh/u;

    .line 22
    .line 23
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p1, p0}, Lh/u;->a(Landroid/view/Window$Callback;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final o(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh/z;->A()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 5
    .line 6
    const v1, 0x1020002

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Landroid/view/ViewGroup;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lh/z;->p:Lh/u;

    .line 22
    .line 23
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p1, p0}, Lh/u;->a(Landroid/view/Window$Callback;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final onCreateView(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;
    .locals 7

    .line 1
    iget-object p1, p0, Lh/z;->q1:Lh/c0;

    const/4 v0, 0x0

    if-nez p1, :cond_1

    .line 2
    sget-object p1, Lg/a;->j:[I

    iget-object v1, p0, Lh/z;->n:Landroid/content/Context;

    invoke-virtual {v1, p1}, Landroid/content/Context;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    move-result-object p1

    const/16 v2, 0x74

    .line 3
    invoke-virtual {p1, v2}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v2

    .line 4
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    if-nez v2, :cond_0

    .line 5
    new-instance p1, Lh/c0;

    invoke-direct {p1}, Lh/c0;-><init>()V

    iput-object p1, p0, Lh/z;->q1:Lh/c0;

    goto :goto_0

    .line 6
    :cond_0
    :try_start_0
    invoke-virtual {v1}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object p1

    invoke-virtual {p1, v2}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1

    .line 7
    invoke-virtual {p1, v0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object p1

    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lh/c0;

    iput-object p1, p0, Lh/z;->q1:Lh/c0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "Failed to instantiate custom view inflater "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ". Falling back to default."

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "AppCompatDelegate"

    invoke-static {v2, v1, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 10
    new-instance p1, Lh/c0;

    invoke-direct {p1}, Lh/c0;-><init>()V

    iput-object p1, p0, Lh/z;->q1:Lh/c0;

    .line 11
    :cond_1
    :goto_0
    iget-object p0, p0, Lh/z;->q1:Lh/c0;

    .line 12
    sget p1, Lm/y2;->b:I

    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    sget-object p1, Lg/a;->x:[I

    const/4 v1, 0x0

    invoke-virtual {p3, p4, p1, v1, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    move-result-object p1

    const/4 v2, 0x4

    .line 15
    invoke-virtual {p1, v2, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v3

    if-eqz v3, :cond_2

    .line 16
    const-string v4, "AppCompatViewInflater"

    const-string v5, "app:theme is now deprecated. Please move to using android:theme instead."

    invoke-static {v4, v5}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 17
    :cond_2
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    if-eqz v3, :cond_4

    .line 18
    instance-of p1, p3, Lk/c;

    if-eqz p1, :cond_3

    move-object p1, p3

    check-cast p1, Lk/c;

    .line 19
    iget p1, p1, Lk/c;->a:I

    if-eq p1, v3, :cond_4

    .line 20
    :cond_3
    new-instance p1, Lk/c;

    invoke-direct {p1, p3, v3}, Lk/c;-><init>(Landroid/content/Context;I)V

    goto :goto_1

    :cond_4
    move-object p1, p3

    .line 21
    :goto_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/String;->hashCode()I

    move-result v3

    const/4 v4, 0x3

    const/4 v5, 0x1

    const/4 v6, -0x1

    sparse-switch v3, :sswitch_data_0

    :goto_2
    move v2, v6

    goto/16 :goto_3

    :sswitch_0
    const-string v2, "Button"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_5

    goto :goto_2

    :cond_5
    const/16 v2, 0xd

    goto/16 :goto_3

    :sswitch_1
    const-string v2, "EditText"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_6

    goto :goto_2

    :cond_6
    const/16 v2, 0xc

    goto/16 :goto_3

    :sswitch_2
    const-string v2, "CheckBox"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_7

    goto :goto_2

    :cond_7
    const/16 v2, 0xb

    goto/16 :goto_3

    :sswitch_3
    const-string v2, "AutoCompleteTextView"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_8

    goto :goto_2

    :cond_8
    const/16 v2, 0xa

    goto/16 :goto_3

    :sswitch_4
    const-string v2, "ImageView"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_9

    goto :goto_2

    :cond_9
    const/16 v2, 0x9

    goto/16 :goto_3

    :sswitch_5
    const-string v2, "ToggleButton"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_a

    goto :goto_2

    :cond_a
    const/16 v2, 0x8

    goto/16 :goto_3

    :sswitch_6
    const-string v2, "RadioButton"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_b

    goto :goto_2

    :cond_b
    const/4 v2, 0x7

    goto :goto_3

    :sswitch_7
    const-string v2, "Spinner"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_c

    goto :goto_2

    :cond_c
    const/4 v2, 0x6

    goto :goto_3

    :sswitch_8
    const-string v2, "SeekBar"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_d

    goto :goto_2

    :cond_d
    const/4 v2, 0x5

    goto :goto_3

    :sswitch_9
    const-string v3, "ImageButton"

    invoke-virtual {p2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_12

    goto :goto_2

    :sswitch_a
    const-string v2, "TextView"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_e

    goto/16 :goto_2

    :cond_e
    move v2, v4

    goto :goto_3

    :sswitch_b
    const-string v2, "MultiAutoCompleteTextView"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_f

    goto/16 :goto_2

    :cond_f
    const/4 v2, 0x2

    goto :goto_3

    :sswitch_c
    const-string v2, "CheckedTextView"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_10

    goto/16 :goto_2

    :cond_10
    move v2, v5

    goto :goto_3

    :sswitch_d
    const-string v2, "RatingBar"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11

    goto/16 :goto_2

    :cond_11
    move v2, v1

    :cond_12
    :goto_3
    packed-switch v2, :pswitch_data_0

    move-object v2, v0

    goto :goto_4

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p4}, Lh/c0;->b(Landroid/content/Context;Landroid/util/AttributeSet;)Lm/o;

    move-result-object v2

    goto :goto_4

    .line 23
    :pswitch_1
    new-instance v2, Lm/u;

    .line 24
    invoke-direct {v2, p1, p4}, Lm/u;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_4

    .line 25
    :pswitch_2
    invoke-virtual {p0, p1, p4}, Lh/c0;->c(Landroid/content/Context;Landroid/util/AttributeSet;)Lm/p;

    move-result-object v2

    goto :goto_4

    .line 26
    :pswitch_3
    invoke-virtual {p0, p1, p4}, Lh/c0;->a(Landroid/content/Context;Landroid/util/AttributeSet;)Lm/n;

    move-result-object v2

    goto :goto_4

    .line 27
    :pswitch_4
    new-instance v2, Lm/x;

    .line 28
    invoke-direct {v2, p1, p4, v1}, Lm/x;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    goto :goto_4

    .line 29
    :pswitch_5
    new-instance v2, Lm/c1;

    invoke-direct {v2, p1, p4}, Lm/c1;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_4

    .line 30
    :pswitch_6
    invoke-virtual {p0, p1, p4}, Lh/c0;->d(Landroid/content/Context;Landroid/util/AttributeSet;)Lm/b0;

    move-result-object v2

    goto :goto_4

    .line 31
    :pswitch_7
    new-instance v2, Lm/p0;

    invoke-direct {v2, p1, p4}, Lm/p0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_4

    .line 32
    :pswitch_8
    new-instance v2, Lm/e0;

    invoke-direct {v2, p1, p4}, Lm/e0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_4

    .line 33
    :pswitch_9
    new-instance v2, Lm/w;

    const v3, 0x7f040299

    .line 34
    invoke-direct {v2, p1, p4, v3}, Lm/w;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    goto :goto_4

    .line 35
    :pswitch_a
    invoke-virtual {p0, p1, p4}, Lh/c0;->e(Landroid/content/Context;Landroid/util/AttributeSet;)Lm/x0;

    move-result-object v2

    goto :goto_4

    .line 36
    :pswitch_b
    new-instance v2, Lm/y;

    invoke-direct {v2, p1, p4}, Lm/y;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_4

    .line 37
    :pswitch_c
    new-instance v2, Lm/q;

    invoke-direct {v2, p1, p4}, Lm/q;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    goto :goto_4

    .line 38
    :pswitch_d
    new-instance v2, Lm/c0;

    invoke-direct {v2, p1, p4}, Lm/c0;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    :goto_4
    if-nez v2, :cond_17

    if-eq p3, p1, :cond_17

    .line 39
    iget-object p3, p0, Lh/c0;->a:[Ljava/lang/Object;

    const-string v2, "view"

    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_13

    .line 40
    const-string p2, "class"

    invoke-interface {p4, v0, p2}, Landroid/util/AttributeSet;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 41
    :cond_13
    :try_start_1
    aput-object p1, p3, v1

    .line 42
    aput-object p4, p3, v5

    const/16 v2, 0x2e

    .line 43
    invoke-virtual {p2, v2}, Ljava/lang/String;->indexOf(I)I

    move-result v2

    if-ne v6, v2, :cond_16

    move v2, v1

    .line 44
    :goto_5
    sget-object v3, Lh/c0;->d:[Ljava/lang/String;

    if-ge v2, v4, :cond_15

    .line 45
    aget-object v3, v3, v2

    invoke-virtual {p0, p1, p2, v3}, Lh/c0;->f(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/view/View;

    move-result-object v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v3, :cond_14

    .line 46
    aput-object v0, p3, v1

    .line 47
    aput-object v0, p3, v5

    move-object v0, v3

    goto :goto_7

    :cond_14
    add-int/lit8 v2, v2, 0x1

    goto :goto_5

    :catchall_1
    move-exception p0

    goto :goto_6

    .line 48
    :cond_15
    aput-object v0, p3, v1

    .line 49
    aput-object v0, p3, v5

    goto :goto_7

    .line 50
    :cond_16
    :try_start_2
    invoke-virtual {p0, p1, p2, v0}, Lh/c0;->f(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/view/View;

    move-result-object p0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 51
    aput-object v0, p3, v1

    .line 52
    aput-object v0, p3, v5

    move-object v0, p0

    goto :goto_7

    .line 53
    :goto_6
    aput-object v0, p3, v1

    .line 54
    aput-object v0, p3, v5

    .line 55
    throw p0

    .line 56
    :catch_0
    aput-object v0, p3, v1

    .line 57
    aput-object v0, p3, v5

    :goto_7
    move-object v2, v0

    :cond_17
    if-eqz v2, :cond_1a

    .line 58
    invoke-virtual {v2}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p0

    .line 59
    instance-of p1, p0, Landroid/content/ContextWrapper;

    if-eqz p1, :cond_1a

    invoke-virtual {v2}, Landroid/view/View;->hasOnClickListeners()Z

    move-result p1

    if-nez p1, :cond_18

    goto :goto_8

    .line 60
    :cond_18
    sget-object p1, Lh/c0;->c:[I

    invoke-virtual {p0, p4, p1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p0

    .line 61
    invoke-virtual {p0, v1}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_19

    .line 62
    new-instance p2, Lh/b0;

    invoke-direct {p2, v2, p1}, Lh/b0;-><init>(Landroid/view/View;Ljava/lang/String;)V

    invoke-virtual {v2, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 63
    :cond_19
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    :cond_1a
    :goto_8
    return-object v2

    nop

    :sswitch_data_0
    .sparse-switch
        -0x7404ceea -> :sswitch_d
        -0x56c015e7 -> :sswitch_c
        -0x503aa7ad -> :sswitch_b
        -0x37f7066e -> :sswitch_a
        -0x37e04bb3 -> :sswitch_9
        -0x274065a5 -> :sswitch_8
        -0x1440b607 -> :sswitch_7
        0x2e46a6ed -> :sswitch_6
        0x2fa453c6 -> :sswitch_5
        0x431b5280 -> :sswitch_4
        0x5445f9ba -> :sswitch_3
        0x5f7507c3 -> :sswitch_2
        0x63577677 -> :sswitch_1
        0x77471352 -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
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
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final onCreateView(Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;
    .locals 1

    const/4 v0, 0x0

    .line 64
    invoke-virtual {p0, v0, p1, p2, p3}, Lh/z;->onCreateView(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;

    move-result-object p0

    return-object p0
.end method

.method public final p(Ljava/lang/CharSequence;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lh/z;->t:Ljava/lang/CharSequence;

    .line 2
    .line 3
    iget-object v0, p0, Lh/z;->u:Lm/e1;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1}, Lm/e1;->setWindowTitle(Ljava/lang/CharSequence;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object v0, p0, Lh/z;->r:Lh/i0;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget-object p0, v0, Lh/i0;->e:Lm/f1;

    .line 16
    .line 17
    check-cast p0, Lm/w2;

    .line 18
    .line 19
    iget-boolean v0, p0, Lm/w2;->g:Z

    .line 20
    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    iget-object v0, p0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 24
    .line 25
    iput-object p1, p0, Lm/w2;->h:Ljava/lang/CharSequence;

    .line 26
    .line 27
    iget v1, p0, Lm/w2;->b:I

    .line 28
    .line 29
    and-int/lit8 v1, v1, 0x8

    .line 30
    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/Toolbar;->setTitle(Ljava/lang/CharSequence;)V

    .line 34
    .line 35
    .line 36
    iget-boolean p0, p0, Lm/w2;->g:Z

    .line 37
    .line 38
    if-eqz p0, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-static {p0, p1}, Ld6/r0;->j(Landroid/view/View;Ljava/lang/CharSequence;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    iget-object p0, p0, Lh/z;->E:Landroid/widget/TextView;

    .line 49
    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 53
    .line 54
    .line 55
    :cond_2
    return-void
.end method

.method public final r(ZZ)Z
    .locals 12

    .line 1
    iget-boolean v0, p0, Lh/z;->T:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    const/16 v0, -0x64

    .line 8
    .line 9
    iget v2, p0, Lh/z;->V:I

    .line 10
    .line 11
    if-eq v2, v0, :cond_1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    sget v2, Lh/n;->e:I

    .line 15
    .line 16
    :goto_0
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 17
    .line 18
    invoke-virtual {p0, v0, v2}, Lh/z;->G(Landroid/content/Context;I)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 23
    .line 24
    const/16 v5, 0x21

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    if-ge v4, v5, :cond_2

    .line 28
    .line 29
    invoke-static {v0}, Lh/z;->t(Landroid/content/Context;)Ly5/c;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    goto :goto_1

    .line 34
    :cond_2
    move-object v4, v6

    .line 35
    :goto_1
    if-nez p2, :cond_3

    .line 36
    .line 37
    if-eqz v4, :cond_3

    .line 38
    .line 39
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p2}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    invoke-static {p2}, Lh/s;->b(Landroid/content/res/Configuration;)Ly5/c;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    :cond_3
    invoke-static {v0, v3, v4, v6, v1}, Lh/z;->x(Landroid/content/Context;ILy5/c;Landroid/content/res/Configuration;Z)Landroid/content/res/Configuration;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    iget-boolean v3, p0, Lh/z;->Y:Z

    .line 56
    .line 57
    const/4 v5, 0x1

    .line 58
    iget-object v7, p0, Lh/z;->m:Ljava/lang/Object;

    .line 59
    .line 60
    if-nez v3, :cond_5

    .line 61
    .line 62
    instance-of v3, v7, Landroid/app/Activity;

    .line 63
    .line 64
    if-eqz v3, :cond_5

    .line 65
    .line 66
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    if-nez v3, :cond_4

    .line 71
    .line 72
    move v3, v1

    .line 73
    goto :goto_3

    .line 74
    :cond_4
    :try_start_0
    new-instance v8, Landroid/content/ComponentName;

    .line 75
    .line 76
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    invoke-direct {v8, v0, v9}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 81
    .line 82
    .line 83
    const/high16 v9, 0x100c0000

    .line 84
    .line 85
    invoke-virtual {v3, v8, v9}, Landroid/content/pm/PackageManager;->getActivityInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ActivityInfo;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    if-eqz v3, :cond_5

    .line 90
    .line 91
    iget v3, v3, Landroid/content/pm/ActivityInfo;->configChanges:I

    .line 92
    .line 93
    iput v3, p0, Lh/z;->X:I
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :catch_0
    move-exception v3

    .line 97
    const-string v8, "AppCompatDelegate"

    .line 98
    .line 99
    const-string v9, "Exception while getting ActivityInfo"

    .line 100
    .line 101
    invoke-static {v8, v9, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 102
    .line 103
    .line 104
    iput v1, p0, Lh/z;->X:I

    .line 105
    .line 106
    :cond_5
    :goto_2
    iput-boolean v5, p0, Lh/z;->Y:Z

    .line 107
    .line 108
    iget v3, p0, Lh/z;->X:I

    .line 109
    .line 110
    :goto_3
    iget-object v8, p0, Lh/z;->U:Landroid/content/res/Configuration;

    .line 111
    .line 112
    if-nez v8, :cond_6

    .line 113
    .line 114
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    invoke-virtual {v8}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 119
    .line 120
    .line 121
    move-result-object v8

    .line 122
    :cond_6
    iget v9, v8, Landroid/content/res/Configuration;->uiMode:I

    .line 123
    .line 124
    and-int/lit8 v9, v9, 0x30

    .line 125
    .line 126
    iget v10, p2, Landroid/content/res/Configuration;->uiMode:I

    .line 127
    .line 128
    and-int/lit8 v10, v10, 0x30

    .line 129
    .line 130
    invoke-static {v8}, Lh/s;->b(Landroid/content/res/Configuration;)Ly5/c;

    .line 131
    .line 132
    .line 133
    move-result-object v8

    .line 134
    if-nez v4, :cond_7

    .line 135
    .line 136
    move-object v4, v6

    .line 137
    goto :goto_4

    .line 138
    :cond_7
    invoke-static {p2}, Lh/s;->b(Landroid/content/res/Configuration;)Ly5/c;

    .line 139
    .line 140
    .line 141
    move-result-object v4

    .line 142
    :goto_4
    if-eq v9, v10, :cond_8

    .line 143
    .line 144
    const/16 v9, 0x200

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_8
    move v9, v1

    .line 148
    :goto_5
    if-eqz v4, :cond_9

    .line 149
    .line 150
    invoke-virtual {v8, v4}, Ly5/c;->equals(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v8

    .line 154
    if-nez v8, :cond_9

    .line 155
    .line 156
    or-int/lit16 v9, v9, 0x2004

    .line 157
    .line 158
    :cond_9
    not-int v8, v3

    .line 159
    and-int/2addr v8, v9

    .line 160
    if-eqz v8, :cond_c

    .line 161
    .line 162
    if-eqz p1, :cond_c

    .line 163
    .line 164
    iget-boolean p1, p0, Lh/z;->R:Z

    .line 165
    .line 166
    if-eqz p1, :cond_c

    .line 167
    .line 168
    sget-boolean p1, Lh/z;->v1:Z

    .line 169
    .line 170
    if-nez p1, :cond_a

    .line 171
    .line 172
    iget-boolean p1, p0, Lh/z;->S:Z

    .line 173
    .line 174
    if-eqz p1, :cond_c

    .line 175
    .line 176
    :cond_a
    instance-of p1, v7, Landroid/app/Activity;

    .line 177
    .line 178
    if-eqz p1, :cond_c

    .line 179
    .line 180
    move-object p1, v7

    .line 181
    check-cast p1, Landroid/app/Activity;

    .line 182
    .line 183
    invoke-virtual {p1}, Landroid/app/Activity;->isChild()Z

    .line 184
    .line 185
    .line 186
    move-result v8

    .line 187
    if-nez v8, :cond_c

    .line 188
    .line 189
    sget v8, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 190
    .line 191
    const/16 v11, 0x1f

    .line 192
    .line 193
    if-lt v8, v11, :cond_b

    .line 194
    .line 195
    and-int/lit16 v8, v9, 0x2000

    .line 196
    .line 197
    if-eqz v8, :cond_b

    .line 198
    .line 199
    invoke-virtual {p1}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 200
    .line 201
    .line 202
    move-result-object v8

    .line 203
    invoke-virtual {v8}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    invoke-virtual {p2}, Landroid/content/res/Configuration;->getLayoutDirection()I

    .line 208
    .line 209
    .line 210
    move-result p2

    .line 211
    invoke-virtual {v8, p2}, Landroid/view/View;->setLayoutDirection(I)V

    .line 212
    .line 213
    .line 214
    :cond_b
    invoke-virtual {p1}, Landroid/app/Activity;->recreate()V

    .line 215
    .line 216
    .line 217
    move p1, v5

    .line 218
    goto :goto_6

    .line 219
    :cond_c
    move p1, v1

    .line 220
    :goto_6
    if-nez p1, :cond_11

    .line 221
    .line 222
    if-eqz v9, :cond_11

    .line 223
    .line 224
    and-int p1, v9, v3

    .line 225
    .line 226
    if-ne p1, v9, :cond_d

    .line 227
    .line 228
    move v1, v5

    .line 229
    :cond_d
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    new-instance p2, Landroid/content/res/Configuration;

    .line 234
    .line 235
    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    invoke-direct {p2, v3}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 243
    .line 244
    .line 245
    move-result-object v3

    .line 246
    iget v3, v3, Landroid/content/res/Configuration;->uiMode:I

    .line 247
    .line 248
    and-int/lit8 v3, v3, -0x31

    .line 249
    .line 250
    or-int/2addr v3, v10

    .line 251
    iput v3, p2, Landroid/content/res/Configuration;->uiMode:I

    .line 252
    .line 253
    if-eqz v4, :cond_e

    .line 254
    .line 255
    invoke-static {p2, v4}, Lh/s;->d(Landroid/content/res/Configuration;Ly5/c;)V

    .line 256
    .line 257
    .line 258
    :cond_e
    invoke-virtual {p1, p2, v6}, Landroid/content/res/Resources;->updateConfiguration(Landroid/content/res/Configuration;Landroid/util/DisplayMetrics;)V

    .line 259
    .line 260
    .line 261
    iget p1, p0, Lh/z;->W:I

    .line 262
    .line 263
    if-eqz p1, :cond_f

    .line 264
    .line 265
    invoke-virtual {v0, p1}, Landroid/content/Context;->setTheme(I)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    iget v3, p0, Lh/z;->W:I

    .line 273
    .line 274
    invoke-virtual {p1, v3, v5}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 275
    .line 276
    .line 277
    :cond_f
    if-eqz v1, :cond_12

    .line 278
    .line 279
    instance-of p1, v7, Landroid/app/Activity;

    .line 280
    .line 281
    if-eqz p1, :cond_12

    .line 282
    .line 283
    check-cast v7, Landroid/app/Activity;

    .line 284
    .line 285
    instance-of p1, v7, Landroidx/lifecycle/x;

    .line 286
    .line 287
    if-eqz p1, :cond_10

    .line 288
    .line 289
    move-object p1, v7

    .line 290
    check-cast p1, Landroidx/lifecycle/x;

    .line 291
    .line 292
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 293
    .line 294
    .line 295
    move-result-object p1

    .line 296
    invoke-virtual {p1}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 297
    .line 298
    .line 299
    move-result-object p1

    .line 300
    sget-object v1, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 301
    .line 302
    invoke-virtual {p1, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 303
    .line 304
    .line 305
    move-result p1

    .line 306
    if-ltz p1, :cond_12

    .line 307
    .line 308
    invoke-virtual {v7, p2}, Landroid/app/Activity;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    .line 309
    .line 310
    .line 311
    goto :goto_7

    .line 312
    :cond_10
    iget-boolean p1, p0, Lh/z;->S:Z

    .line 313
    .line 314
    if-eqz p1, :cond_12

    .line 315
    .line 316
    iget-boolean p1, p0, Lh/z;->T:Z

    .line 317
    .line 318
    if-nez p1, :cond_12

    .line 319
    .line 320
    invoke-virtual {v7, p2}, Landroid/app/Activity;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    .line 321
    .line 322
    .line 323
    goto :goto_7

    .line 324
    :cond_11
    move v5, p1

    .line 325
    :cond_12
    :goto_7
    if-eqz v4, :cond_13

    .line 326
    .line 327
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 328
    .line 329
    .line 330
    move-result-object p1

    .line 331
    invoke-virtual {p1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 332
    .line 333
    .line 334
    move-result-object p1

    .line 335
    invoke-static {p1}, Lh/s;->b(Landroid/content/res/Configuration;)Ly5/c;

    .line 336
    .line 337
    .line 338
    move-result-object p1

    .line 339
    invoke-static {p1}, Lh/s;->c(Ly5/c;)V

    .line 340
    .line 341
    .line 342
    :cond_13
    if-nez v2, :cond_14

    .line 343
    .line 344
    invoke-virtual {p0, v0}, Lh/z;->C(Landroid/content/Context;)Lh/w;

    .line 345
    .line 346
    .line 347
    move-result-object p1

    .line 348
    invoke-virtual {p1}, Lh/w;->p()V

    .line 349
    .line 350
    .line 351
    goto :goto_8

    .line 352
    :cond_14
    iget-object p1, p0, Lh/z;->Z:Lh/v;

    .line 353
    .line 354
    if-eqz p1, :cond_15

    .line 355
    .line 356
    invoke-virtual {p1}, Lh/w;->c()V

    .line 357
    .line 358
    .line 359
    :cond_15
    :goto_8
    const/4 p1, 0x3

    .line 360
    if-ne v2, p1, :cond_17

    .line 361
    .line 362
    iget-object p1, p0, Lh/z;->a0:Lh/v;

    .line 363
    .line 364
    if-nez p1, :cond_16

    .line 365
    .line 366
    new-instance p1, Lh/v;

    .line 367
    .line 368
    invoke-direct {p1, p0, v0}, Lh/v;-><init>(Lh/z;Landroid/content/Context;)V

    .line 369
    .line 370
    .line 371
    iput-object p1, p0, Lh/z;->a0:Lh/v;

    .line 372
    .line 373
    :cond_16
    iget-object p0, p0, Lh/z;->a0:Lh/v;

    .line 374
    .line 375
    invoke-virtual {p0}, Lh/w;->p()V

    .line 376
    .line 377
    .line 378
    goto :goto_9

    .line 379
    :cond_17
    iget-object p0, p0, Lh/z;->a0:Lh/v;

    .line 380
    .line 381
    if-eqz p0, :cond_18

    .line 382
    .line 383
    invoke-virtual {p0}, Lh/w;->c()V

    .line 384
    .line 385
    .line 386
    :cond_18
    :goto_9
    return v5
.end method

.method public final s(Landroid/view/Window;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 2
    .line 3
    const-string v1, "AppCompat has already installed itself into the Window"

    .line 4
    .line 5
    if-nez v0, :cond_5

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    instance-of v2, v0, Lh/u;

    .line 12
    .line 13
    if-nez v2, :cond_4

    .line 14
    .line 15
    new-instance v1, Lh/u;

    .line 16
    .line 17
    invoke-direct {v1, p0, v0}, Lh/u;-><init>(Lh/z;Landroid/view/Window$Callback;)V

    .line 18
    .line 19
    .line 20
    iput-object v1, p0, Lh/z;->p:Lh/u;

    .line 21
    .line 22
    invoke-virtual {p1, v1}, Landroid/view/Window;->setCallback(Landroid/view/Window$Callback;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 26
    .line 27
    sget-object v1, Lh/z;->u1:[I

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-static {v0, v2, v1}, Lil/g;->Q(Landroid/content/Context;Landroid/util/AttributeSet;[I)Lil/g;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-virtual {v0, v1}, Lil/g;->C(I)Landroid/graphics/drawable/Drawable;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    if-eqz v1, :cond_0

    .line 40
    .line 41
    invoke-virtual {p1, v1}, Landroid/view/Window;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 42
    .line 43
    .line 44
    :cond_0
    invoke-virtual {v0}, Lil/g;->U()V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lh/z;->o:Landroid/view/Window;

    .line 48
    .line 49
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 50
    .line 51
    const/16 v0, 0x21

    .line 52
    .line 53
    if-lt p1, v0, :cond_3

    .line 54
    .line 55
    iget-object p1, p0, Lh/z;->r1:Landroid/window/OnBackInvokedDispatcher;

    .line 56
    .line 57
    if-nez p1, :cond_3

    .line 58
    .line 59
    if-eqz p1, :cond_1

    .line 60
    .line 61
    iget-object v0, p0, Lh/z;->s1:Landroid/window/OnBackInvokedCallback;

    .line 62
    .line 63
    if-eqz v0, :cond_1

    .line 64
    .line 65
    invoke-static {p1, v0}, Lh/t;->c(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iput-object v2, p0, Lh/z;->s1:Landroid/window/OnBackInvokedCallback;

    .line 69
    .line 70
    :cond_1
    iget-object p1, p0, Lh/z;->m:Ljava/lang/Object;

    .line 71
    .line 72
    instance-of v0, p1, Landroid/app/Activity;

    .line 73
    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    check-cast p1, Landroid/app/Activity;

    .line 77
    .line 78
    invoke-virtual {p1}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    if-eqz v0, :cond_2

    .line 83
    .line 84
    invoke-static {p1}, Lh/t;->a(Landroid/app/Activity;)Landroid/window/OnBackInvokedDispatcher;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    iput-object p1, p0, Lh/z;->r1:Landroid/window/OnBackInvokedDispatcher;

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_2
    iput-object v2, p0, Lh/z;->r1:Landroid/window/OnBackInvokedDispatcher;

    .line 92
    .line 93
    :goto_0
    invoke-virtual {p0}, Lh/z;->M()V

    .line 94
    .line 95
    .line 96
    :cond_3
    return-void

    .line 97
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 104
    .line 105
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0
.end method

.method public final u(ILh/y;Ll/l;)V
    .locals 2

    .line 1
    if-nez p3, :cond_1

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lh/z;->O:[Lh/y;

    .line 8
    .line 9
    array-length v1, v0

    .line 10
    if-ge p1, v1, :cond_0

    .line 11
    .line 12
    aget-object p2, v0, p1

    .line 13
    .line 14
    :cond_0
    if-eqz p2, :cond_1

    .line 15
    .line 16
    iget-object p3, p2, Lh/y;->h:Ll/l;

    .line 17
    .line 18
    :cond_1
    if-eqz p2, :cond_2

    .line 19
    .line 20
    iget-boolean p2, p2, Lh/y;->m:Z

    .line 21
    .line 22
    if-nez p2, :cond_2

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_2
    iget-boolean p2, p0, Lh/z;->T:Z

    .line 26
    .line 27
    if-nez p2, :cond_3

    .line 28
    .line 29
    iget-object p2, p0, Lh/z;->p:Lh/u;

    .line 30
    .line 31
    iget-object p0, p0, Lh/z;->o:Landroid/view/Window;

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x1

    .line 41
    const/4 v1, 0x0

    .line 42
    :try_start_0
    iput-boolean v0, p2, Lh/u;->g:Z

    .line 43
    .line 44
    invoke-interface {p0, p1, p3}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    iput-boolean v1, p2, Lh/u;->g:Z

    .line 48
    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    iput-boolean v1, p2, Lh/u;->g:Z

    .line 52
    .line 53
    throw p0

    .line 54
    :cond_3
    :goto_0
    return-void
.end method

.method public final v(Ll/l;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lh/z;->N:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lh/z;->N:Z

    .line 8
    .line 9
    iget-object v0, p0, Lh/z;->u:Lm/e1;

    .line 10
    .line 11
    check-cast v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 12
    .line 13
    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 14
    .line 15
    .line 16
    iget-object v0, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 17
    .line 18
    check-cast v0, Lm/w2;

    .line 19
    .line 20
    iget-object v0, v0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 21
    .line 22
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 27
    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Lm/j;->b()Z

    .line 31
    .line 32
    .line 33
    iget-object v0, v0, Lm/j;->w:Lm/f;

    .line 34
    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    invoke-virtual {v0}, Ll/v;->b()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    iget-object v0, v0, Ll/v;->i:Ll/t;

    .line 44
    .line 45
    invoke-interface {v0}, Ll/b0;->dismiss()V

    .line 46
    .line 47
    .line 48
    :cond_1
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 49
    .line 50
    invoke-virtual {v0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-eqz v0, :cond_2

    .line 55
    .line 56
    iget-boolean v1, p0, Lh/z;->T:Z

    .line 57
    .line 58
    if-nez v1, :cond_2

    .line 59
    .line 60
    const/16 v1, 0x6c

    .line 61
    .line 62
    invoke-interface {v0, v1, p1}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    const/4 p1, 0x0

    .line 66
    iput-boolean p1, p0, Lh/z;->N:Z

    .line 67
    .line 68
    return-void
.end method

.method public final w(Lh/y;Z)V
    .locals 3

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    iget v0, p1, Lh/y;->a:I

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lh/z;->u:Lm/e1;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 12
    .line 13
    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 14
    .line 15
    .line 16
    iget-object v0, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 17
    .line 18
    check-cast v0, Lm/w2;

    .line 19
    .line 20
    iget-object v0, v0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 21
    .line 22
    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    invoke-virtual {v0}, Lm/j;->k()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    iget-object p1, p1, Lh/y;->h:Ll/l;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lh/z;->v(Ll/l;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    .line 43
    .line 44
    const-string v1, "window"

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Landroid/view/WindowManager;

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    if-eqz v0, :cond_1

    .line 54
    .line 55
    iget-boolean v2, p1, Lh/y;->m:Z

    .line 56
    .line 57
    if-eqz v2, :cond_1

    .line 58
    .line 59
    iget-object v2, p1, Lh/y;->e:Lh/x;

    .line 60
    .line 61
    if-eqz v2, :cond_1

    .line 62
    .line 63
    invoke-interface {v0, v2}, Landroid/view/ViewManager;->removeView(Landroid/view/View;)V

    .line 64
    .line 65
    .line 66
    if-eqz p2, :cond_1

    .line 67
    .line 68
    iget p2, p1, Lh/y;->a:I

    .line 69
    .line 70
    invoke-virtual {p0, p2, p1, v1}, Lh/z;->u(ILh/y;Ll/l;)V

    .line 71
    .line 72
    .line 73
    :cond_1
    const/4 p2, 0x0

    .line 74
    iput-boolean p2, p1, Lh/y;->k:Z

    .line 75
    .line 76
    iput-boolean p2, p1, Lh/y;->l:Z

    .line 77
    .line 78
    iput-boolean p2, p1, Lh/y;->m:Z

    .line 79
    .line 80
    iput-object v1, p1, Lh/y;->f:Landroid/view/View;

    .line 81
    .line 82
    const/4 p2, 0x1

    .line 83
    iput-boolean p2, p1, Lh/y;->n:Z

    .line 84
    .line 85
    iget-object p2, p0, Lh/z;->P:Lh/y;

    .line 86
    .line 87
    if-ne p2, p1, :cond_2

    .line 88
    .line 89
    iput-object v1, p0, Lh/z;->P:Lh/y;

    .line 90
    .line 91
    :cond_2
    iget p1, p1, Lh/y;->a:I

    .line 92
    .line 93
    if-nez p1, :cond_3

    .line 94
    .line 95
    invoke-virtual {p0}, Lh/z;->M()V

    .line 96
    .line 97
    .line 98
    :cond_3
    return-void
.end method

.method public final y(Landroid/view/KeyEvent;)Z
    .locals 6

    .line 1
    iget-object v0, p0, Lh/z;->m:Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v1, v0, Ld6/j;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    instance-of v0, v0, Lh/f;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 12
    .line 13
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 20
    .line 21
    :cond_1
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v1, 0x0

    .line 26
    const/16 v2, 0x52

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    if-ne v0, v2, :cond_2

    .line 30
    .line 31
    iget-object v0, p0, Lh/z;->p:Lh/u;

    .line 32
    .line 33
    iget-object v4, p0, Lh/z;->o:Landroid/view/Window;

    .line 34
    .line 35
    invoke-virtual {v4}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    :try_start_0
    iput-boolean v3, v0, Lh/u;->f:Z

    .line 43
    .line 44
    invoke-interface {v4, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 45
    .line 46
    .line 47
    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    iput-boolean v1, v0, Lh/u;->f:Z

    .line 49
    .line 50
    if-eqz v4, :cond_2

    .line 51
    .line 52
    goto/16 :goto_6

    .line 53
    .line 54
    :catchall_0
    move-exception p0

    .line 55
    iput-boolean v1, v0, Lh/u;->f:Z

    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getAction()I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    const/4 v5, 0x4

    .line 67
    if-nez v4, :cond_6

    .line 68
    .line 69
    if-eq v0, v5, :cond_4

    .line 70
    .line 71
    if-eq v0, v2, :cond_3

    .line 72
    .line 73
    goto/16 :goto_7

    .line 74
    .line 75
    :cond_3
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getRepeatCount()I

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    if-nez v0, :cond_11

    .line 80
    .line 81
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    iget-boolean v1, v0, Lh/y;->m:Z

    .line 86
    .line 87
    if-nez v1, :cond_11

    .line 88
    .line 89
    invoke-virtual {p0, v0, p1}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 90
    .line 91
    .line 92
    return v3

    .line 93
    :cond_4
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getFlags()I

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    and-int/lit16 p1, p1, 0x80

    .line 98
    .line 99
    if-eqz p1, :cond_5

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_5
    move v3, v1

    .line 103
    :goto_0
    iput-boolean v3, p0, Lh/z;->Q:Z

    .line 104
    .line 105
    return v1

    .line 106
    :cond_6
    if-eq v0, v5, :cond_10

    .line 107
    .line 108
    if-eq v0, v2, :cond_7

    .line 109
    .line 110
    goto/16 :goto_7

    .line 111
    .line 112
    :cond_7
    iget-object v0, p0, Lh/z;->x:Lk/a;

    .line 113
    .line 114
    if-eqz v0, :cond_8

    .line 115
    .line 116
    goto/16 :goto_6

    .line 117
    .line 118
    :cond_8
    invoke-virtual {p0, v1}, Lh/z;->D(I)Lh/y;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    iget-object v2, p0, Lh/z;->u:Lm/e1;

    .line 123
    .line 124
    iget-object v4, p0, Lh/z;->n:Landroid/content/Context;

    .line 125
    .line 126
    if-eqz v2, :cond_a

    .line 127
    .line 128
    check-cast v2, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 129
    .line 130
    invoke-virtual {v2}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 131
    .line 132
    .line 133
    iget-object v2, v2, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 134
    .line 135
    check-cast v2, Lm/w2;

    .line 136
    .line 137
    iget-object v2, v2, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 138
    .line 139
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    .line 140
    .line 141
    .line 142
    move-result v5

    .line 143
    if-nez v5, :cond_a

    .line 144
    .line 145
    iget-object v2, v2, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 146
    .line 147
    if-eqz v2, :cond_a

    .line 148
    .line 149
    iget-boolean v2, v2, Landroidx/appcompat/widget/ActionMenuView;->v:Z

    .line 150
    .line 151
    if-eqz v2, :cond_a

    .line 152
    .line 153
    invoke-static {v4}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-virtual {v2}, Landroid/view/ViewConfiguration;->hasPermanentMenuKey()Z

    .line 158
    .line 159
    .line 160
    move-result v2

    .line 161
    if-nez v2, :cond_a

    .line 162
    .line 163
    iget-object v2, p0, Lh/z;->u:Lm/e1;

    .line 164
    .line 165
    check-cast v2, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 166
    .line 167
    invoke-virtual {v2}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 168
    .line 169
    .line 170
    iget-object v2, v2, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 171
    .line 172
    check-cast v2, Lm/w2;

    .line 173
    .line 174
    iget-object v2, v2, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 175
    .line 176
    iget-object v2, v2, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 177
    .line 178
    if-eqz v2, :cond_9

    .line 179
    .line 180
    iget-object v2, v2, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 181
    .line 182
    if-eqz v2, :cond_9

    .line 183
    .line 184
    invoke-virtual {v2}, Lm/j;->k()Z

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    if-eqz v2, :cond_9

    .line 189
    .line 190
    iget-object p0, p0, Lh/z;->u:Lm/e1;

    .line 191
    .line 192
    check-cast p0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 193
    .line 194
    invoke-virtual {p0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 195
    .line 196
    .line 197
    iget-object p0, p0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 198
    .line 199
    check-cast p0, Lm/w2;

    .line 200
    .line 201
    iget-object p0, p0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 202
    .line 203
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 204
    .line 205
    if-eqz p0, :cond_d

    .line 206
    .line 207
    iget-object p0, p0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 208
    .line 209
    if-eqz p0, :cond_d

    .line 210
    .line 211
    invoke-virtual {p0}, Lm/j;->b()Z

    .line 212
    .line 213
    .line 214
    move-result p0

    .line 215
    if-eqz p0, :cond_d

    .line 216
    .line 217
    :goto_1
    goto :goto_3

    .line 218
    :cond_9
    iget-boolean v2, p0, Lh/z;->T:Z

    .line 219
    .line 220
    if-nez v2, :cond_d

    .line 221
    .line 222
    invoke-virtual {p0, v0, p1}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 223
    .line 224
    .line 225
    move-result p1

    .line 226
    if-eqz p1, :cond_d

    .line 227
    .line 228
    iget-object p0, p0, Lh/z;->u:Lm/e1;

    .line 229
    .line 230
    check-cast p0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    .line 231
    .line 232
    invoke-virtual {p0}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->k()V

    .line 233
    .line 234
    .line 235
    iget-object p0, p0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->h:Lm/f1;

    .line 236
    .line 237
    check-cast p0, Lm/w2;

    .line 238
    .line 239
    iget-object p0, p0, Lm/w2;->a:Landroidx/appcompat/widget/Toolbar;

    .line 240
    .line 241
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->d:Landroidx/appcompat/widget/ActionMenuView;

    .line 242
    .line 243
    if-eqz p0, :cond_d

    .line 244
    .line 245
    iget-object p0, p0, Landroidx/appcompat/widget/ActionMenuView;->w:Lm/j;

    .line 246
    .line 247
    if-eqz p0, :cond_d

    .line 248
    .line 249
    invoke-virtual {p0}, Lm/j;->l()Z

    .line 250
    .line 251
    .line 252
    move-result p0

    .line 253
    if-eqz p0, :cond_d

    .line 254
    .line 255
    goto :goto_1

    .line 256
    :cond_a
    iget-boolean v2, v0, Lh/y;->m:Z

    .line 257
    .line 258
    if-nez v2, :cond_e

    .line 259
    .line 260
    iget-boolean v5, v0, Lh/y;->l:Z

    .line 261
    .line 262
    if-eqz v5, :cond_b

    .line 263
    .line 264
    goto :goto_4

    .line 265
    :cond_b
    iget-boolean v2, v0, Lh/y;->k:Z

    .line 266
    .line 267
    if-eqz v2, :cond_d

    .line 268
    .line 269
    iget-boolean v2, v0, Lh/y;->o:Z

    .line 270
    .line 271
    if-eqz v2, :cond_c

    .line 272
    .line 273
    iput-boolean v1, v0, Lh/y;->k:Z

    .line 274
    .line 275
    invoke-virtual {p0, v0, p1}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 276
    .line 277
    .line 278
    move-result v2

    .line 279
    goto :goto_2

    .line 280
    :cond_c
    move v2, v3

    .line 281
    :goto_2
    if-eqz v2, :cond_d

    .line 282
    .line 283
    invoke-virtual {p0, v0, p1}, Lh/z;->I(Lh/y;Landroid/view/KeyEvent;)V

    .line 284
    .line 285
    .line 286
    :goto_3
    move p0, v3

    .line 287
    goto :goto_5

    .line 288
    :cond_d
    move p0, v1

    .line 289
    goto :goto_5

    .line 290
    :cond_e
    :goto_4
    invoke-virtual {p0, v0, v3}, Lh/z;->w(Lh/y;Z)V

    .line 291
    .line 292
    .line 293
    move p0, v2

    .line 294
    :goto_5
    if-eqz p0, :cond_11

    .line 295
    .line 296
    invoke-virtual {v4}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    const-string p1, "audio"

    .line 301
    .line 302
    invoke-virtual {p0, p1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    check-cast p0, Landroid/media/AudioManager;

    .line 307
    .line 308
    if-eqz p0, :cond_f

    .line 309
    .line 310
    invoke-virtual {p0, v1}, Landroid/media/AudioManager;->playSoundEffect(I)V

    .line 311
    .line 312
    .line 313
    return v3

    .line 314
    :cond_f
    const-string p0, "AppCompatDelegate"

    .line 315
    .line 316
    const-string p1, "Couldn\'t get audio manager"

    .line 317
    .line 318
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 319
    .line 320
    .line 321
    return v3

    .line 322
    :cond_10
    invoke-virtual {p0}, Lh/z;->H()Z

    .line 323
    .line 324
    .line 325
    move-result p0

    .line 326
    if-eqz p0, :cond_12

    .line 327
    .line 328
    :cond_11
    :goto_6
    return v3

    .line 329
    :cond_12
    :goto_7
    return v1
.end method

.method public final z(I)V
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Lh/z;->D(I)Lh/y;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, v0, Lh/y;->h:Ll/l;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    new-instance v1, Landroid/os/Bundle;

    .line 10
    .line 11
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v2, v0, Lh/y;->h:Ll/l;

    .line 15
    .line 16
    invoke-virtual {v2, v1}, Ll/l;->t(Landroid/os/Bundle;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1}, Landroid/os/BaseBundle;->size()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-lez v2, :cond_0

    .line 24
    .line 25
    iput-object v1, v0, Lh/y;->p:Landroid/os/Bundle;

    .line 26
    .line 27
    :cond_0
    iget-object v1, v0, Lh/y;->h:Ll/l;

    .line 28
    .line 29
    invoke-virtual {v1}, Ll/l;->w()V

    .line 30
    .line 31
    .line 32
    iget-object v1, v0, Lh/y;->h:Ll/l;

    .line 33
    .line 34
    invoke-virtual {v1}, Ll/l;->clear()V

    .line 35
    .line 36
    .line 37
    :cond_1
    const/4 v1, 0x1

    .line 38
    iput-boolean v1, v0, Lh/y;->o:Z

    .line 39
    .line 40
    iput-boolean v1, v0, Lh/y;->n:Z

    .line 41
    .line 42
    const/16 v0, 0x6c

    .line 43
    .line 44
    if-eq p1, v0, :cond_2

    .line 45
    .line 46
    if-nez p1, :cond_3

    .line 47
    .line 48
    :cond_2
    iget-object p1, p0, Lh/z;->u:Lm/e1;

    .line 49
    .line 50
    if-eqz p1, :cond_3

    .line 51
    .line 52
    const/4 p1, 0x0

    .line 53
    invoke-virtual {p0, p1}, Lh/z;->D(I)Lh/y;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    iput-boolean p1, v0, Lh/y;->k:Z

    .line 58
    .line 59
    const/4 p1, 0x0

    .line 60
    invoke-virtual {p0, v0, p1}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 61
    .line 62
    .line 63
    :cond_3
    return-void
.end method
