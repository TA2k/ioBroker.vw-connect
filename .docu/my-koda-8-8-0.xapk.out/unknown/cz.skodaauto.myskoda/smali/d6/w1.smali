.class public final Ld6/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Ld6/w1;


# instance fields
.field public final a:Ld6/s1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x22

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    sget-object v0, Ld6/r1;->s:Ld6/w1;

    .line 8
    .line 9
    sput-object v0, Ld6/w1;->b:Ld6/w1;

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    const/16 v1, 0x1e

    .line 13
    .line 14
    if-lt v0, v1, :cond_1

    .line 15
    .line 16
    sget-object v0, Ld6/p1;->r:Ld6/w1;

    .line 17
    .line 18
    sput-object v0, Ld6/w1;->b:Ld6/w1;

    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    sget-object v0, Ld6/s1;->b:Ld6/w1;

    .line 22
    .line 23
    sput-object v0, Ld6/w1;->b:Ld6/w1;

    .line 24
    .line 25
    return-void
.end method

.method public constructor <init>(Landroid/view/WindowInsets;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    .line 3
    new-instance v0, Ld6/r1;

    invoke-direct {v0, p0, p1}, Ld6/r1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    return-void

    :cond_0
    const/16 v1, 0x1f

    if-lt v0, v1, :cond_1

    .line 4
    new-instance v0, Ld6/q1;

    invoke-direct {v0, p0, p1}, Ld6/q1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    return-void

    :cond_1
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_2

    .line 5
    new-instance v0, Ld6/p1;

    invoke-direct {v0, p0, p1}, Ld6/p1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    return-void

    .line 6
    :cond_2
    new-instance v0, Ld6/o1;

    invoke-direct {v0, p0, p1}, Ld6/o1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    return-void
.end method

.method public constructor <init>(Ld6/w1;)V
    .locals 2

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_7

    .line 8
    iget-object p1, p1, Ld6/w1;->a:Ld6/s1;

    .line 9
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    instance-of v1, p1, Ld6/r1;

    if-eqz v1, :cond_0

    .line 10
    new-instance v0, Ld6/r1;

    move-object v1, p1

    check-cast v1, Ld6/r1;

    invoke-direct {v0, p0, v1}, Ld6/r1;-><init>(Ld6/w1;Ld6/r1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto/16 :goto_0

    :cond_0
    const/16 v1, 0x1f

    if-lt v0, v1, :cond_1

    .line 11
    instance-of v1, p1, Ld6/q1;

    if-eqz v1, :cond_1

    .line 12
    new-instance v0, Ld6/q1;

    move-object v1, p1

    check-cast v1, Ld6/q1;

    invoke-direct {v0, p0, v1}, Ld6/q1;-><init>(Ld6/w1;Ld6/q1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto :goto_0

    :cond_1
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_2

    .line 13
    instance-of v0, p1, Ld6/p1;

    if-eqz v0, :cond_2

    .line 14
    new-instance v0, Ld6/p1;

    move-object v1, p1

    check-cast v1, Ld6/p1;

    invoke-direct {v0, p0, v1}, Ld6/p1;-><init>(Ld6/w1;Ld6/p1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto :goto_0

    .line 15
    :cond_2
    instance-of v0, p1, Ld6/o1;

    if-eqz v0, :cond_3

    .line 16
    new-instance v0, Ld6/o1;

    move-object v1, p1

    check-cast v1, Ld6/o1;

    invoke-direct {v0, p0, v1}, Ld6/o1;-><init>(Ld6/w1;Ld6/o1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto :goto_0

    .line 17
    :cond_3
    instance-of v0, p1, Ld6/n1;

    if-eqz v0, :cond_4

    .line 18
    new-instance v0, Ld6/n1;

    move-object v1, p1

    check-cast v1, Ld6/n1;

    invoke-direct {v0, p0, v1}, Ld6/n1;-><init>(Ld6/w1;Ld6/n1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto :goto_0

    .line 19
    :cond_4
    instance-of v0, p1, Ld6/m1;

    if-eqz v0, :cond_5

    .line 20
    new-instance v0, Ld6/m1;

    move-object v1, p1

    check-cast v1, Ld6/m1;

    invoke-direct {v0, p0, v1}, Ld6/m1;-><init>(Ld6/w1;Ld6/m1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto :goto_0

    .line 21
    :cond_5
    instance-of v0, p1, Ld6/l1;

    if-eqz v0, :cond_6

    .line 22
    new-instance v0, Ld6/l1;

    move-object v1, p1

    check-cast v1, Ld6/l1;

    invoke-direct {v0, p0, v1}, Ld6/l1;-><init>(Ld6/w1;Ld6/l1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    goto :goto_0

    .line 23
    :cond_6
    new-instance v0, Ld6/s1;

    invoke-direct {v0, p0}, Ld6/s1;-><init>(Ld6/w1;)V

    iput-object v0, p0, Ld6/w1;->a:Ld6/s1;

    .line 24
    :goto_0
    invoke-virtual {p1, p0}, Ld6/s1;->e(Ld6/w1;)V

    return-void

    .line 25
    :cond_7
    new-instance p1, Ld6/s1;

    invoke-direct {p1, p0}, Ld6/s1;-><init>(Ld6/w1;)V

    iput-object p1, p0, Ld6/w1;->a:Ld6/s1;

    return-void
.end method

.method public static f(Ls5/b;IIII)Ls5/b;
    .locals 5

    .line 1
    iget v0, p0, Ls5/b;->a:I

    .line 2
    .line 3
    sub-int/2addr v0, p1

    .line 4
    const/4 v1, 0x0

    .line 5
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget v2, p0, Ls5/b;->b:I

    .line 10
    .line 11
    sub-int/2addr v2, p2

    .line 12
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    iget v3, p0, Ls5/b;->c:I

    .line 17
    .line 18
    sub-int/2addr v3, p3

    .line 19
    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    iget v4, p0, Ls5/b;->d:I

    .line 24
    .line 25
    sub-int/2addr v4, p4

    .line 26
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-ne v0, p1, :cond_0

    .line 31
    .line 32
    if-ne v2, p2, :cond_0

    .line 33
    .line 34
    if-ne v3, p3, :cond_0

    .line 35
    .line 36
    if-ne v1, p4, :cond_0

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_0
    invoke-static {v0, v2, v3, v1}, Ls5/b;->b(IIII)Ls5/b;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public static h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;
    .locals 2

    .line 1
    new-instance v0, Ld6/w1;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-direct {v0, p1}, Ld6/w1;-><init>(Landroid/view/WindowInsets;)V

    .line 7
    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    sget-object p1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 18
    .line 19
    invoke-static {p0}, Ld6/l0;->a(Landroid/view/View;)Ld6/w1;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iget-object v1, v0, Ld6/w1;->a:Ld6/s1;

    .line 24
    .line 25
    invoke-virtual {v1, p1}, Ld6/s1;->t(Ld6/w1;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {v1, p1}, Ld6/s1;->d(Landroid/view/View;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Landroid/view/View;->getWindowSystemUiVisibility()I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-virtual {v1, p0}, Ld6/s1;->u(I)V

    .line 40
    .line 41
    .line 42
    :cond_0
    return-object v0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld6/s1;->l()Ls5/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p0, p0, Ls5/b;->d:I

    .line 8
    .line 9
    return p0
.end method

.method public final b()I
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld6/s1;->l()Ls5/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p0, p0, Ls5/b;->a:I

    .line 8
    .line 9
    return p0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld6/s1;->l()Ls5/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p0, p0, Ls5/b;->c:I

    .line 8
    .line 9
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld6/s1;->l()Ls5/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget p0, p0, Ls5/b;->b:I

    .line 8
    .line 9
    return p0
.end method

.method public final e()Z
    .locals 2

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    invoke-virtual {p0, v0}, Ld6/s1;->g(I)Ls5/b;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    sget-object v1, Ls5/b;->e:Ls5/b;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ls5/b;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    const/16 v0, -0x9

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ld6/s1;->h(I)Ls5/b;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0, v1}, Ls5/b;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Ld6/s1;->f()Ld6/i;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    return p0

    .line 37
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 38
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Ld6/w1;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Ld6/w1;

    .line 12
    .line 13
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 14
    .line 15
    iget-object p1, p1, Ld6/w1;->a:Ld6/s1;

    .line 16
    .line 17
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final g()Landroid/view/WindowInsets;
    .locals 1

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    instance-of v0, p0, Ld6/l1;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Ld6/l1;

    .line 8
    .line 9
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ld6/s1;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method
