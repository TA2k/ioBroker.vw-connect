.class public Lil/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;
.implements Ly4/i;
.implements Lat/a;
.implements Lks/b;
.implements Lks/a;
.implements Lju/b;
.implements Lkw/b;
.implements Ll2/c;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 2

    iput p1, p0, Lil/g;->d:I

    const/16 v0, 0xa

    sparse-switch p1, :sswitch_data_0

    .line 65
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 66
    new-instance p1, Landroidx/collection/w;

    const/16 v1, 0x10

    invoke-direct {p1, v1}, Landroidx/collection/w;-><init>(I)V

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 67
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 68
    new-instance p1, Landroidx/collection/q0;

    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 69
    iput-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 70
    new-instance p1, Lnm0/b;

    .line 71
    invoke-direct {p1, v0}, Lnm0/b;-><init>(I)V

    .line 72
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void

    .line 73
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 74
    new-instance p1, Ljava/util/WeakHashMap;

    invoke-direct {p1}, Ljava/util/WeakHashMap;-><init>()V

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 75
    new-instance p1, Ljava/util/WeakHashMap;

    invoke-direct {p1}, Ljava/util/WeakHashMap;-><init>()V

    iput-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 76
    new-instance p1, Ljava/util/WeakHashMap;

    invoke-direct {p1}, Ljava/util/WeakHashMap;-><init>()V

    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void

    .line 77
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 78
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 79
    new-instance p1, Landroidx/collection/q0;

    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 80
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    return-void

    .line 81
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 82
    new-instance p1, Lnm0/b;

    .line 83
    invoke-direct {p1, v0}, Lnm0/b;-><init>(I)V

    .line 84
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void

    .line 85
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    new-instance p1, Ljava/util/HashMap;

    .line 86
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    sget-object p1, Lkp/e;->c:Lkp/e;

    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_3
        0x10 -> :sswitch_2
        0x13 -> :sswitch_1
        0x15 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(ILjava/util/List;Ls71/o;Ljava/util/List;Lv71/e;)V
    .locals 0

    const/16 p1, 0x1b

    iput p1, p0, Lil/g;->d:I

    const-string p1, "centers"

    invoke-static {p4, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "vehicleDimensions"

    invoke-static {p5, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p2, p0, Lil/g;->e:Ljava/lang/Object;

    .line 11
    iput-object p4, p0, Lil/g;->f:Ljava/lang/Object;

    .line 12
    iput-object p5, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lil/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lil/g;->d:I

    .line 46
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 47
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 48
    sget-object p1, Lxl/b;->a:Ltl/b;

    .line 49
    iput-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 50
    new-instance p1, Lxl/d;

    invoke-direct {p1}, Lxl/d;-><init>()V

    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/content/res/TypedArray;)V
    .locals 1

    const/16 v0, 0xe

    iput v0, p0, Lil/g;->d:I

    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 29
    iput-object p2, p0, Lil/g;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/View;)V
    .locals 3

    const/16 v0, 0xd

    iput v0, p0, Lil/g;->d:I

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 25
    sget-object v0, Llx0/j;->f:Llx0/j;

    new-instance v1, La7/j;

    const/16 v2, 0xb

    invoke-direct {v1, p0, v2}, La7/j;-><init>(Ljava/lang/Object;I)V

    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v0

    iput-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 26
    new-instance v0, Laq/a;

    invoke-direct {v0, p1}, Laq/a;-><init>(Landroid/view/View;)V

    iput-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/b0;Lp0/c;)V
    .locals 1

    const/16 v0, 0x18

    iput v0, p0, Lil/g;->d:I

    .line 43
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 44
    iput-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 45
    iput-object p2, p0, Lil/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/z;Landroid/util/Size;)V
    .locals 2

    const/16 v0, 0xb

    iput v0, p0, Lil/g;->d:I

    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 32
    invoke-interface {p1}, Lh0/z;->e()I

    .line 33
    invoke-interface {p1}, Lh0/z;->h()I

    if-eqz p2, :cond_0

    .line 34
    new-instance v0, Landroid/util/Rational;

    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    move-result v1

    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    move-result p2

    invoke-direct {v0, v1, p2}, Landroid/util/Rational;-><init>(II)V

    goto :goto_0

    :cond_0
    const/16 p2, 0x100

    .line 35
    invoke-interface {p1, p2}, Lh0/z;->k(I)Ljava/util/List;

    move-result-object p2

    .line 36
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 p2, 0x0

    move-object v0, p2

    goto :goto_0

    .line 37
    :cond_1
    new-instance v0, Li0/c;

    const/4 v1, 0x0

    .line 38
    invoke-direct {v0, v1}, Li0/c;-><init>(Z)V

    .line 39
    invoke-static {p2, v0}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Landroid/util/Size;

    .line 40
    new-instance v0, Landroid/util/Rational;

    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    move-result v1

    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    move-result p2

    invoke-direct {v0, v1, p2}, Landroid/util/Rational;-><init>(II)V

    .line 41
    :goto_0
    iput-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 42
    new-instance p2, Lg11/b;

    invoke-direct {p2, p1, v0}, Lg11/b;-><init>(Lh0/z;Landroid/util/Rational;)V

    iput-object p2, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh6/e;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lil/g;->d:I

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 18
    new-instance p1, Lg1/i3;

    invoke-direct {p1}, Lg1/i3;-><init>()V

    iput-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 19
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhu/q;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Lil/g;->d:I

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 15
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lj0/b;Landroid/os/Handler;Ljava/util/concurrent/Callable;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lil/g;->d:I

    .line 58
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    iput-object p2, p0, Lil/g;->e:Ljava/lang/Object;

    iput-object p3, p0, Lil/g;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Lil/g;->d:I

    .line 51
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 52
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 53
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 1

    const/16 v0, 0xc

    iput v0, p0, Lil/g;->d:I

    .line 59
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 60
    new-instance v0, Landroidx/collection/a0;

    invoke-direct {v0}, Landroidx/collection/a0;-><init>()V

    .line 61
    iput-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 62
    new-instance v0, Landroidx/collection/l0;

    invoke-direct {v0}, Landroidx/collection/l0;-><init>()V

    .line 63
    iput-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 64
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Lil/g;->d:I

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    iput-object p2, p0, Lil/g;->f:Ljava/lang/Object;

    iput-object p3, p0, Lil/g;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 3

    const/16 v0, 0x17

    iput v0, p0, Lil/g;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Lil/g;

    const/16 v1, 0x16

    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lil/g;-><init>(IZ)V

    .line 7
    iput-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    iput-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 8
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lk4/i0;Lil/g;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Lil/g;->d:I

    .line 54
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 55
    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 56
    iput-object p2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 57
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    move-result-object p1

    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqp/h;Lrp/g;)V
    .locals 1

    const/16 v0, 0x1c

    iput v0, p0, Lil/g;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lt0/c;)V
    .locals 2

    const/16 v0, 0x12

    iput v0, p0, Lil/g;->d:I

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 22
    new-instance v0, Ljava/util/ArrayDeque;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Ljava/util/ArrayDeque;-><init>(I)V

    iput-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 23
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    return-void
.end method

.method public static D(Lin/w0;Ljava/lang/String;)Lin/y0;
    .locals 3

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lin/y0;

    .line 3
    .line 4
    iget-object v1, v0, Lin/y0;->c:Ljava/lang/String;

    .line 5
    .line 6
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    return-object v0

    .line 13
    :cond_0
    invoke-interface {p0}, Lin/w0;->b()Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_4

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lin/a1;

    .line 32
    .line 33
    instance-of v1, v0, Lin/y0;

    .line 34
    .line 35
    if-nez v1, :cond_2

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    move-object v1, v0

    .line 39
    check-cast v1, Lin/y0;

    .line 40
    .line 41
    iget-object v2, v1, Lin/y0;->c:Ljava/lang/String;

    .line 42
    .line 43
    invoke-virtual {p1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_3

    .line 48
    .line 49
    return-object v1

    .line 50
    :cond_3
    instance-of v1, v0, Lin/w0;

    .line 51
    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    check-cast v0, Lin/w0;

    .line 55
    .line 56
    invoke-static {v0, p1}, Lil/g;->D(Lin/w0;Ljava/lang/String;)Lin/y0;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    return-object v0

    .line 63
    :cond_4
    const/4 p0, 0x0

    .line 64
    return-object p0
.end method

.method public static I(Ljava/util/ArrayList;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Li0/b;->a:Landroid/util/Rational;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    sget-object v1, Li0/b;->c:Landroid/util/Rational;

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_3

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Landroid/util/Size;

    .line 31
    .line 32
    new-instance v2, Landroid/util/Rational;

    .line 33
    .line 34
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    invoke-direct {v2, v3, v4}, Landroid/util/Rational;-><init>(II)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    if-nez v3, :cond_0

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    :cond_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_2

    .line 60
    .line 61
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    check-cast v4, Landroid/util/Rational;

    .line 66
    .line 67
    invoke-static {v4, v1}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eqz v4, :cond_1

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_3
    return-object v0
.end method

.method public static K(IZ)Landroid/util/Rational;
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-eq p0, v0, :cond_4

    .line 4
    .line 5
    if-eqz p0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_0

    .line 9
    .line 10
    new-instance p1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v0, "Undefined target aspect ratio: "

    .line 13
    .line 14
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const-string p1, "SupportedOutputSizesCollector"

    .line 25
    .line 26
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-object v1

    .line 30
    :cond_0
    if-eqz p1, :cond_1

    .line 31
    .line 32
    sget-object p0, Li0/b;->c:Landroid/util/Rational;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_1
    sget-object p0, Li0/b;->d:Landroid/util/Rational;

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_2
    if-eqz p1, :cond_3

    .line 39
    .line 40
    sget-object p0, Li0/b;->a:Landroid/util/Rational;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_3
    sget-object p0, Li0/b;->b:Landroid/util/Rational;

    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_4
    return-object v1
.end method

.method public static N(Ljava/util/ArrayList;)Ljava/util/HashMap;
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lil/g;->I(Ljava/util/ArrayList;)Ljava/util/ArrayList;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Landroid/util/Rational;

    .line 25
    .line 26
    new-instance v3, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_3

    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    check-cast v1, Landroid/util/Size;

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    :cond_2
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_1

    .line 64
    .line 65
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    check-cast v3, Landroid/util/Rational;

    .line 70
    .line 71
    invoke-static {v3, v1}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_2

    .line 76
    .line 77
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    check-cast v3, Ljava/util/List;

    .line 82
    .line 83
    invoke-interface {v3, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_3
    return-object v0
.end method

.method public static Q(Landroid/content/Context;Landroid/util/AttributeSet;[I)Lil/g;
    .locals 1

    .line 1
    new-instance v0, Lil/g;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {v0, p0, p1}, Lil/g;-><init>(Landroid/content/Context;Landroid/content/res/TypedArray;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public static R(Landroid/content/Context;Landroid/util/AttributeSet;[II)Lil/g;
    .locals 2

    .line 1
    new-instance v0, Lil/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, p1, p2, p3, v1}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-direct {v0, p0, p1}, Lil/g;-><init>(Landroid/content/Context;Landroid/content/res/TypedArray;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static T(Lil/g;Lk4/l;Lcq/r1;Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lk4/h;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, p1}, Lk4/h;-><init>(Lk4/l;)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Lnm0/b;

    .line 15
    .line 16
    monitor-enter p1

    .line 17
    if-nez p3, :cond_0

    .line 18
    .line 19
    :try_start_0
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Landroidx/collection/q0;

    .line 22
    .line 23
    new-instance p2, Lk4/g;

    .line 24
    .line 25
    const/4 p3, 0x0

    .line 26
    invoke-direct {p2, p3}, Lk4/g;-><init>(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v0, p2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Landroidx/collection/w;

    .line 38
    .line 39
    new-instance p2, Lk4/g;

    .line 40
    .line 41
    invoke-direct {p2, p3}, Lk4/g;-><init>(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, v0, p2}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    :goto_0
    monitor-exit p1

    .line 48
    return-void

    .line 49
    :goto_1
    monitor-exit p1

    .line 50
    throw p0
.end method

.method public static X(Ljava/util/List;Landroid/util/Size;Z)V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    add-int/lit8 v1, v1, -0x1

    .line 11
    .line 12
    :goto_0
    if-ltz v1, :cond_1

    .line 13
    .line 14
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Landroid/util/Size;

    .line 19
    .line 20
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-lt v3, v4, :cond_0

    .line 29
    .line 30
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-ge v3, v4, :cond_1

    .line 39
    .line 40
    :cond_0
    const/4 v3, 0x0

    .line 41
    invoke-virtual {v0, v3, v2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    add-int/lit8 v1, v1, -0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-interface {p0, v0}, Ljava/util/List;->removeAll(Ljava/util/Collection;)Z

    .line 48
    .line 49
    .line 50
    invoke-static {p0}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 51
    .line 52
    .line 53
    if-eqz p2, :cond_2

    .line 54
    .line 55
    invoke-interface {p0, v0}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 56
    .line 57
    .line 58
    :cond_2
    return-void
.end method

.method public static Y(Ljava/util/List;Landroid/util/Size;Z)V
    .locals 6

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    move v2, v1

    .line 8
    :goto_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    if-ge v2, v3, :cond_1

    .line 13
    .line 14
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    check-cast v3, Landroid/util/Size;

    .line 19
    .line 20
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    if-gt v4, v5, :cond_0

    .line 29
    .line 30
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-le v4, v5, :cond_1

    .line 39
    .line 40
    :cond_0
    invoke-virtual {v0, v1, v3}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    add-int/lit8 v2, v2, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    invoke-interface {p0, v0}, Ljava/util/List;->removeAll(Ljava/util/Collection;)Z

    .line 47
    .line 48
    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    invoke-interface {p0, v0}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 52
    .line 53
    .line 54
    :cond_2
    return-void
.end method


# virtual methods
.method public A()Ld3/a;
    .locals 7

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lin/t0;

    .line 4
    .line 5
    iget-object v1, v0, Lin/t0;->r:Lin/e0;

    .line 6
    .line 7
    iget-object v0, v0, Lin/t0;->s:Lin/e0;

    .line 8
    .line 9
    const/high16 v2, -0x40800000    # -1.0f

    .line 10
    .line 11
    if-eqz v1, :cond_5

    .line 12
    .line 13
    invoke-virtual {v1}, Lin/e0;->h()Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-nez v3, :cond_5

    .line 18
    .line 19
    iget v3, v1, Lin/e0;->e:I

    .line 20
    .line 21
    const/16 v4, 0x9

    .line 22
    .line 23
    if-eq v3, v4, :cond_5

    .line 24
    .line 25
    const/4 v5, 0x2

    .line 26
    if-eq v3, v5, :cond_5

    .line 27
    .line 28
    const/4 v6, 0x3

    .line 29
    if-ne v3, v6, :cond_0

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_0
    invoke-virtual {v1}, Lin/e0;->c()F

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    invoke-virtual {v0}, Lin/e0;->h()Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-nez p0, :cond_2

    .line 43
    .line 44
    iget p0, v0, Lin/e0;->e:I

    .line 45
    .line 46
    if-eq p0, v4, :cond_2

    .line 47
    .line 48
    if-eq p0, v5, :cond_2

    .line 49
    .line 50
    if-ne p0, v6, :cond_1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    invoke-virtual {v0}, Lin/e0;->c()F

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    goto :goto_1

    .line 58
    :cond_2
    :goto_0
    new-instance p0, Ld3/a;

    .line 59
    .line 60
    invoke-direct {p0, v2, v2, v2, v2}, Ld3/a;-><init>(FFFF)V

    .line 61
    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_3
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p0, Lin/t0;

    .line 67
    .line 68
    iget-object p0, p0, Lin/e1;->o:Ld3/a;

    .line 69
    .line 70
    if-eqz p0, :cond_4

    .line 71
    .line 72
    iget v0, p0, Ld3/a;->e:F

    .line 73
    .line 74
    mul-float/2addr v0, v1

    .line 75
    iget p0, p0, Ld3/a;->d:F

    .line 76
    .line 77
    div-float p0, v0, p0

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_4
    move p0, v1

    .line 81
    :goto_1
    new-instance v0, Ld3/a;

    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-direct {v0, v2, v2, v1, p0}, Ld3/a;-><init>(FFFF)V

    .line 85
    .line 86
    .line 87
    return-object v0

    .line 88
    :cond_5
    :goto_2
    new-instance p0, Ld3/a;

    .line 89
    .line 90
    invoke-direct {p0, v2, v2, v2, v2}, Ld3/a;-><init>(FFFF)V

    .line 91
    .line 92
    .line 93
    return-object p0
.end method

.method public B(I)Landroid/graphics/drawable/Drawable;
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/res/TypedArray;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-virtual {v0, p1, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/content/Context;

    .line 21
    .line 22
    invoke-static {p0, v1}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    invoke-virtual {v0, p1}, Landroid/content/res/TypedArray;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public C(I)Landroid/graphics/drawable/Drawable;
    .locals 3

    .line 1
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/res/TypedArray;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Landroid/content/res/TypedArray;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-virtual {v0, p1, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    invoke-static {}, Lm/s;->a()Lm/s;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Landroid/content/Context;

    .line 29
    .line 30
    monitor-enter v0

    .line 31
    :try_start_0
    iget-object v1, v0, Lm/s;->a:Lm/h2;

    .line 32
    .line 33
    const/4 v2, 0x1

    .line 34
    invoke-virtual {v1, p0, p1, v2}, Lm/h2;->d(Landroid/content/Context;IZ)Landroid/graphics/drawable/Drawable;

    .line 35
    .line 36
    .line 37
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    monitor-exit v0

    .line 39
    return-object p0

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    throw p0

    .line 43
    :cond_0
    const/4 p0, 0x0

    .line 44
    return-object p0
.end method

.method public E(IILm/q0;)Landroid/graphics/Typeface;
    .locals 9

    .line 1
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/res/TypedArray;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, p1, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 7
    .line 8
    .line 9
    move-result v3

    .line 10
    if-nez v3, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Landroid/util/TypedValue;

    .line 16
    .line 17
    if-nez p1, :cond_1

    .line 18
    .line 19
    new-instance p1, Landroid/util/TypedValue;

    .line 20
    .line 21
    invoke-direct {p1}, Landroid/util/TypedValue;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 25
    .line 26
    :cond_1
    iget-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v2, p1

    .line 29
    check-cast v2, Landroid/content/Context;

    .line 30
    .line 31
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 32
    .line 33
    move-object v4, p0

    .line 34
    check-cast v4, Landroid/util/TypedValue;

    .line 35
    .line 36
    sget-object p0, Lp5/j;->a:Ljava/lang/ThreadLocal;

    .line 37
    .line 38
    invoke-virtual {v2}, Landroid/content/Context;->isRestricted()Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    :goto_0
    const/4 p0, 0x0

    .line 45
    return-object p0

    .line 46
    :cond_2
    const/4 v7, 0x1

    .line 47
    const/4 v8, 0x0

    .line 48
    move v5, p2

    .line 49
    move-object v6, p3

    .line 50
    invoke-static/range {v2 .. v8}, Lp5/j;->b(Landroid/content/Context;ILandroid/util/TypedValue;ILp5/b;ZZ)Landroid/graphics/Typeface;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method

.method public F(Luu/u;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lrp/g;

    .line 4
    .line 5
    new-instance v0, Lqp/j;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lqp/j;-><init>(Luu/u;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 15
    .line 16
    .line 17
    const/16 v0, 0x9

    .line 18
    .line 19
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :catch_0
    move-exception p0

    .line 24
    new-instance p1, La8/r0;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public G(I)I
    .locals 4

    .line 1
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lg1/i3;

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    if-gez p1, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lh6/e;

    .line 12
    .line 13
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    move v2, p1

    .line 22
    :goto_0
    if-ge v2, p0, :cond_3

    .line 23
    .line 24
    invoke-virtual {v0, v2}, Lg1/i3;->s(I)I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    sub-int v3, v2, v3

    .line 29
    .line 30
    sub-int v3, p1, v3

    .line 31
    .line 32
    if-nez v3, :cond_2

    .line 33
    .line 34
    :goto_1
    invoke-virtual {v0, v2}, Lg1/i3;->u(I)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    add-int/lit8 v2, v2, 0x1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    return v2

    .line 44
    :cond_2
    add-int/2addr v2, v3

    .line 45
    goto :goto_0

    .line 46
    :cond_3
    return v1
.end method

.method public H([B)Ljava/util/List;
    .locals 1

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    new-instance v0, Lmr/d;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lmr/d;-><init>([B)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/util/List;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 20
    .line 21
    return-object p0
.end method

.method public J(Lh0/o2;)Ljava/util/ArrayList;
    .locals 12

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lh0/z;

    .line 4
    .line 5
    move-object v1, p1

    .line 6
    check-cast v1, Lh0/a1;

    .line 7
    .line 8
    sget-object v2, Lh0/a1;->O0:Lh0/g;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-interface {v1, v2, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Ljava/util/List;

    .line 16
    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    new-instance v4, Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object v4, v3

    .line 26
    :goto_0
    if-eqz v4, :cond_1

    .line 27
    .line 28
    return-object v4

    .line 29
    :cond_1
    sget-object v2, Lh0/a1;->N0:Lh0/g;

    .line 30
    .line 31
    invoke-interface {v1, v2, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Ls0/b;

    .line 36
    .line 37
    sget-object v4, Lh0/a1;->M0:Lh0/g;

    .line 38
    .line 39
    invoke-interface {v1, v4, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Ljava/util/List;

    .line 44
    .line 45
    invoke-interface {p1}, Lh0/z0;->l()I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-eqz v4, :cond_3

    .line 50
    .line 51
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    :cond_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-eqz v6, :cond_3

    .line 60
    .line 61
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    check-cast v6, Landroid/util/Pair;

    .line 66
    .line 67
    iget-object v7, v6, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v7, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    if-ne v7, v5, :cond_2

    .line 76
    .line 77
    iget-object v4, v6, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v4, [Landroid/util/Size;

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    move-object v4, v3

    .line 83
    :goto_1
    if-nez v4, :cond_4

    .line 84
    .line 85
    move-object v4, v3

    .line 86
    goto :goto_2

    .line 87
    :cond_4
    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    :goto_2
    if-nez v4, :cond_5

    .line 92
    .line 93
    invoke-interface {v0, v5}, Lh0/z;->k(I)Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    :cond_5
    new-instance v0, Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-direct {v0, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 100
    .line 101
    .line 102
    new-instance v4, Li0/c;

    .line 103
    .line 104
    const/4 v6, 0x1

    .line 105
    invoke-direct {v4, v6}, Li0/c;-><init>(Z)V

    .line 106
    .line 107
    .line 108
    invoke-static {v0, v4}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    const-string v7, "SupportedOutputSizesCollector"

    .line 116
    .line 117
    if-eqz v4, :cond_6

    .line 118
    .line 119
    new-instance v4, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    const-string v8, "The retrieved supported resolutions from camera info internal is empty. Format is "

    .line 122
    .line 123
    invoke-direct {v4, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    const-string v5, "."

    .line 130
    .line 131
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    invoke-static {v7, v4}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    :cond_6
    const/4 v4, 0x0

    .line 142
    if-nez v2, :cond_19

    .line 143
    .line 144
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast p0, Lg11/b;

    .line 147
    .line 148
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 152
    .line 153
    .line 154
    move-result v1

    .line 155
    if-eqz v1, :cond_7

    .line 156
    .line 157
    return-object v0

    .line 158
    :cond_7
    new-instance v1, Ljava/util/ArrayList;

    .line 159
    .line 160
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 161
    .line 162
    .line 163
    new-instance v0, Li0/c;

    .line 164
    .line 165
    invoke-direct {v0, v6}, Li0/c;-><init>(Z)V

    .line 166
    .line 167
    .line 168
    invoke-static {v1, v0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 169
    .line 170
    .line 171
    new-instance v0, Ljava/util/ArrayList;

    .line 172
    .line 173
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 174
    .line 175
    .line 176
    check-cast p1, Lh0/a1;

    .line 177
    .line 178
    sget-object v2, Lh0/a1;->L0:Lh0/g;

    .line 179
    .line 180
    invoke-interface {p1, v2, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    check-cast v2, Landroid/util/Size;

    .line 185
    .line 186
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    check-cast v4, Landroid/util/Size;

    .line 191
    .line 192
    if-eqz v2, :cond_8

    .line 193
    .line 194
    invoke-static {v4}, Lo0/a;->a(Landroid/util/Size;)I

    .line 195
    .line 196
    .line 197
    move-result v5

    .line 198
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 199
    .line 200
    .line 201
    move-result v7

    .line 202
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 203
    .line 204
    .line 205
    move-result v8

    .line 206
    mul-int/2addr v8, v7

    .line 207
    if-ge v5, v8, :cond_9

    .line 208
    .line 209
    :cond_8
    move-object v2, v4

    .line 210
    :cond_9
    invoke-virtual {p0, p1}, Lg11/b;->a(Lh0/a1;)Landroid/util/Size;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    sget-object v5, Lo0/a;->b:Landroid/util/Size;

    .line 215
    .line 216
    invoke-static {v5}, Lo0/a;->a(Landroid/util/Size;)I

    .line 217
    .line 218
    .line 219
    move-result v7

    .line 220
    invoke-static {v2}, Lo0/a;->a(Landroid/util/Size;)I

    .line 221
    .line 222
    .line 223
    move-result v8

    .line 224
    if-ge v8, v7, :cond_a

    .line 225
    .line 226
    sget-object v5, Lo0/a;->a:Landroid/util/Size;

    .line 227
    .line 228
    goto :goto_3

    .line 229
    :cond_a
    if-eqz v4, :cond_b

    .line 230
    .line 231
    invoke-virtual {v4}, Landroid/util/Size;->getWidth()I

    .line 232
    .line 233
    .line 234
    move-result v8

    .line 235
    invoke-virtual {v4}, Landroid/util/Size;->getHeight()I

    .line 236
    .line 237
    .line 238
    move-result v9

    .line 239
    mul-int/2addr v9, v8

    .line 240
    if-ge v9, v7, :cond_b

    .line 241
    .line 242
    move-object v5, v4

    .line 243
    :cond_b
    :goto_3
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 244
    .line 245
    .line 246
    move-result-object v7

    .line 247
    :cond_c
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 248
    .line 249
    .line 250
    move-result v8

    .line 251
    if-eqz v8, :cond_d

    .line 252
    .line 253
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v8

    .line 257
    check-cast v8, Landroid/util/Size;

    .line 258
    .line 259
    invoke-static {v8}, Lo0/a;->a(Landroid/util/Size;)I

    .line 260
    .line 261
    .line 262
    move-result v9

    .line 263
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 264
    .line 265
    .line 266
    move-result v10

    .line 267
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 268
    .line 269
    .line 270
    move-result v11

    .line 271
    mul-int/2addr v11, v10

    .line 272
    if-gt v9, v11, :cond_c

    .line 273
    .line 274
    invoke-virtual {v8}, Landroid/util/Size;->getWidth()I

    .line 275
    .line 276
    .line 277
    move-result v9

    .line 278
    invoke-virtual {v8}, Landroid/util/Size;->getHeight()I

    .line 279
    .line 280
    .line 281
    move-result v10

    .line 282
    mul-int/2addr v10, v9

    .line 283
    invoke-static {v5}, Lo0/a;->a(Landroid/util/Size;)I

    .line 284
    .line 285
    .line 286
    move-result v9

    .line 287
    if-lt v10, v9, :cond_c

    .line 288
    .line 289
    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    move-result v9

    .line 293
    if-nez v9, :cond_c

    .line 294
    .line 295
    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    goto :goto_4

    .line 299
    :cond_d
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 300
    .line 301
    .line 302
    move-result v7

    .line 303
    if-nez v7, :cond_18

    .line 304
    .line 305
    sget-object v1, Lh0/a1;->F0:Lh0/g;

    .line 306
    .line 307
    invoke-interface {p1, v1}, Lh0/t1;->j(Lh0/g;)Z

    .line 308
    .line 309
    .line 310
    move-result v2

    .line 311
    if-eqz v2, :cond_e

    .line 312
    .line 313
    invoke-interface {p1, v1}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    check-cast v1, Ljava/lang/Integer;

    .line 318
    .line 319
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 320
    .line 321
    .line 322
    move-result v1

    .line 323
    iget-boolean v2, p0, Lg11/b;->c:Z

    .line 324
    .line 325
    invoke-static {v1, v2}, Lil/g;->K(IZ)Landroid/util/Rational;

    .line 326
    .line 327
    .line 328
    move-result-object v1

    .line 329
    goto :goto_5

    .line 330
    :cond_e
    invoke-virtual {p0, p1}, Lg11/b;->a(Lh0/a1;)Landroid/util/Size;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    if-eqz v1, :cond_11

    .line 335
    .line 336
    invoke-static {v0}, Lil/g;->I(Ljava/util/ArrayList;)Ljava/util/ArrayList;

    .line 337
    .line 338
    .line 339
    move-result-object v2

    .line 340
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 341
    .line 342
    .line 343
    move-result-object v2

    .line 344
    :cond_f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 345
    .line 346
    .line 347
    move-result v5

    .line 348
    if-eqz v5, :cond_10

    .line 349
    .line 350
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v5

    .line 354
    check-cast v5, Landroid/util/Rational;

    .line 355
    .line 356
    invoke-static {v5, v1}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 357
    .line 358
    .line 359
    move-result v7

    .line 360
    if-eqz v7, :cond_f

    .line 361
    .line 362
    move-object v1, v5

    .line 363
    goto :goto_5

    .line 364
    :cond_10
    new-instance v2, Landroid/util/Rational;

    .line 365
    .line 366
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 367
    .line 368
    .line 369
    move-result v5

    .line 370
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 371
    .line 372
    .line 373
    move-result v1

    .line 374
    invoke-direct {v2, v5, v1}, Landroid/util/Rational;-><init>(II)V

    .line 375
    .line 376
    .line 377
    move-object v1, v2

    .line 378
    goto :goto_5

    .line 379
    :cond_11
    move-object v1, v3

    .line 380
    :goto_5
    if-nez v4, :cond_12

    .line 381
    .line 382
    sget-object v2, Lh0/a1;->K0:Lh0/g;

    .line 383
    .line 384
    invoke-interface {p1, v2, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object p1

    .line 388
    move-object v4, p1

    .line 389
    check-cast v4, Landroid/util/Size;

    .line 390
    .line 391
    :cond_12
    new-instance p1, Ljava/util/ArrayList;

    .line 392
    .line 393
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 394
    .line 395
    .line 396
    new-instance v2, Ljava/util/HashMap;

    .line 397
    .line 398
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 399
    .line 400
    .line 401
    if-nez v1, :cond_13

    .line 402
    .line 403
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 404
    .line 405
    .line 406
    if-eqz v4, :cond_17

    .line 407
    .line 408
    invoke-static {p1, v4, v6}, Lil/g;->X(Ljava/util/List;Landroid/util/Size;Z)V

    .line 409
    .line 410
    .line 411
    return-object p1

    .line 412
    :cond_13
    invoke-static {v0}, Lil/g;->N(Ljava/util/ArrayList;)Ljava/util/HashMap;

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    if-eqz v4, :cond_14

    .line 417
    .line 418
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 423
    .line 424
    .line 425
    move-result-object v2

    .line 426
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 427
    .line 428
    .line 429
    move-result v3

    .line 430
    if-eqz v3, :cond_14

    .line 431
    .line 432
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v3

    .line 436
    check-cast v3, Landroid/util/Rational;

    .line 437
    .line 438
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    move-result-object v3

    .line 442
    check-cast v3, Ljava/util/List;

    .line 443
    .line 444
    invoke-static {v3, v4, v6}, Lil/g;->X(Ljava/util/List;Landroid/util/Size;Z)V

    .line 445
    .line 446
    .line 447
    goto :goto_6

    .line 448
    :cond_14
    new-instance v2, Ljava/util/ArrayList;

    .line 449
    .line 450
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 451
    .line 452
    .line 453
    move-result-object v3

    .line 454
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 455
    .line 456
    .line 457
    new-instance v3, Li0/a;

    .line 458
    .line 459
    iget-object p0, p0, Lg11/b;->d:Ljava/io/Serializable;

    .line 460
    .line 461
    check-cast p0, Landroid/util/Rational;

    .line 462
    .line 463
    invoke-direct {v3, v1, p0}, Li0/a;-><init>(Landroid/util/Rational;Landroid/util/Rational;)V

    .line 464
    .line 465
    .line 466
    invoke-static {v2, v3}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 467
    .line 468
    .line 469
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 470
    .line 471
    .line 472
    move-result-object p0

    .line 473
    :cond_15
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 474
    .line 475
    .line 476
    move-result v1

    .line 477
    if-eqz v1, :cond_17

    .line 478
    .line 479
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v1

    .line 483
    check-cast v1, Landroid/util/Rational;

    .line 484
    .line 485
    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v1

    .line 489
    check-cast v1, Ljava/util/List;

    .line 490
    .line 491
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 492
    .line 493
    .line 494
    move-result-object v1

    .line 495
    :cond_16
    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 496
    .line 497
    .line 498
    move-result v2

    .line 499
    if-eqz v2, :cond_15

    .line 500
    .line 501
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v2

    .line 505
    check-cast v2, Landroid/util/Size;

    .line 506
    .line 507
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 508
    .line 509
    .line 510
    move-result v3

    .line 511
    if-nez v3, :cond_16

    .line 512
    .line 513
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 514
    .line 515
    .line 516
    goto :goto_7

    .line 517
    :cond_17
    return-object p1

    .line 518
    :cond_18
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 519
    .line 520
    new-instance p1, Ljava/lang/StringBuilder;

    .line 521
    .line 522
    const-string v0, "All supported output sizes are filtered out according to current resolution selection settings. \nminSize = "

    .line 523
    .line 524
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    invoke-virtual {p1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 528
    .line 529
    .line 530
    const-string v0, "\nmaxSize = "

    .line 531
    .line 532
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 533
    .line 534
    .line 535
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 536
    .line 537
    .line 538
    const-string v0, "\ninitial size list: "

    .line 539
    .line 540
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 541
    .line 542
    .line 543
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 544
    .line 545
    .line 546
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 547
    .line 548
    .line 549
    move-result-object p1

    .line 550
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    throw p0

    .line 554
    :cond_19
    move-object v2, p1

    .line 555
    check-cast v2, Lh0/a1;

    .line 556
    .line 557
    sget-object v5, Lh0/a1;->L0:Lh0/g;

    .line 558
    .line 559
    invoke-interface {v2, v5, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 560
    .line 561
    .line 562
    move-result-object v2

    .line 563
    check-cast v2, Landroid/util/Size;

    .line 564
    .line 565
    invoke-interface {v1}, Lh0/a1;->o()I

    .line 566
    .line 567
    .line 568
    sget-object v3, Lh0/o2;->Y0:Lh0/g;

    .line 569
    .line 570
    sget-object v5, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 571
    .line 572
    invoke-interface {p1, v3, v5}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v3

    .line 576
    check-cast v3, Ljava/lang/Boolean;

    .line 577
    .line 578
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 579
    .line 580
    .line 581
    move-result v3

    .line 582
    if-nez v3, :cond_1a

    .line 583
    .line 584
    invoke-interface {p1}, Lh0/z0;->l()I

    .line 585
    .line 586
    .line 587
    :cond_1a
    new-instance v3, Ljava/lang/StringBuilder;

    .line 588
    .line 589
    const-string v5, "useCaseConfig = "

    .line 590
    .line 591
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 595
    .line 596
    .line 597
    const-string p1, ", candidateSizes = "

    .line 598
    .line 599
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 600
    .line 601
    .line 602
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 603
    .line 604
    .line 605
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 606
    .line 607
    .line 608
    move-result-object p1

    .line 609
    invoke-static {v7, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 610
    .line 611
    .line 612
    sget-object p1, Lh0/a1;->N0:Lh0/g;

    .line 613
    .line 614
    invoke-interface {v1, p1}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 615
    .line 616
    .line 617
    move-result-object p1

    .line 618
    check-cast p1, Ls0/b;

    .line 619
    .line 620
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 621
    .line 622
    check-cast p0, Landroid/util/Rational;

    .line 623
    .line 624
    iget-object v1, p1, Ls0/b;->a:Ls0/a;

    .line 625
    .line 626
    invoke-static {v0}, Lil/g;->N(Ljava/util/ArrayList;)Ljava/util/HashMap;

    .line 627
    .line 628
    .line 629
    move-result-object v0

    .line 630
    if-eqz p0, :cond_1b

    .line 631
    .line 632
    invoke-virtual {p0}, Landroid/util/Rational;->getNumerator()I

    .line 633
    .line 634
    .line 635
    move-result v3

    .line 636
    invoke-virtual {p0}, Landroid/util/Rational;->getDenominator()I

    .line 637
    .line 638
    .line 639
    move-result v5

    .line 640
    if-lt v3, v5, :cond_1c

    .line 641
    .line 642
    :cond_1b
    move v3, v6

    .line 643
    goto :goto_8

    .line 644
    :cond_1c
    move v3, v4

    .line 645
    :goto_8
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 646
    .line 647
    .line 648
    invoke-static {v4, v3}, Lil/g;->K(IZ)Landroid/util/Rational;

    .line 649
    .line 650
    .line 651
    move-result-object v1

    .line 652
    new-instance v3, Ljava/util/ArrayList;

    .line 653
    .line 654
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 655
    .line 656
    .line 657
    move-result-object v5

    .line 658
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 659
    .line 660
    .line 661
    new-instance v5, Li0/a;

    .line 662
    .line 663
    invoke-direct {v5, v1, p0}, Li0/a;-><init>(Landroid/util/Rational;Landroid/util/Rational;)V

    .line 664
    .line 665
    .line 666
    invoke-static {v3, v5}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 667
    .line 668
    .line 669
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 670
    .line 671
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 672
    .line 673
    .line 674
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 675
    .line 676
    .line 677
    move-result-object v1

    .line 678
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 679
    .line 680
    .line 681
    move-result v3

    .line 682
    if-eqz v3, :cond_1d

    .line 683
    .line 684
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 685
    .line 686
    .line 687
    move-result-object v3

    .line 688
    check-cast v3, Landroid/util/Rational;

    .line 689
    .line 690
    invoke-virtual {v0, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 691
    .line 692
    .line 693
    move-result-object v5

    .line 694
    check-cast v5, Ljava/util/List;

    .line 695
    .line 696
    invoke-virtual {p0, v3, v5}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    goto :goto_9

    .line 700
    :cond_1d
    if-eqz v2, :cond_20

    .line 701
    .line 702
    sget-object v0, Lo0/a;->a:Landroid/util/Size;

    .line 703
    .line 704
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 705
    .line 706
    .line 707
    move-result v0

    .line 708
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 709
    .line 710
    .line 711
    move-result v1

    .line 712
    mul-int/2addr v1, v0

    .line 713
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    .line 714
    .line 715
    .line 716
    move-result-object v0

    .line 717
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 718
    .line 719
    .line 720
    move-result-object v0

    .line 721
    :goto_a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 722
    .line 723
    .line 724
    move-result v2

    .line 725
    if-eqz v2, :cond_20

    .line 726
    .line 727
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 728
    .line 729
    .line 730
    move-result-object v2

    .line 731
    check-cast v2, Landroid/util/Rational;

    .line 732
    .line 733
    invoke-virtual {p0, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 734
    .line 735
    .line 736
    move-result-object v2

    .line 737
    check-cast v2, Ljava/util/List;

    .line 738
    .line 739
    new-instance v3, Ljava/util/ArrayList;

    .line 740
    .line 741
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 742
    .line 743
    .line 744
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 745
    .line 746
    .line 747
    move-result-object v5

    .line 748
    :cond_1e
    :goto_b
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 749
    .line 750
    .line 751
    move-result v7

    .line 752
    if-eqz v7, :cond_1f

    .line 753
    .line 754
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 755
    .line 756
    .line 757
    move-result-object v7

    .line 758
    check-cast v7, Landroid/util/Size;

    .line 759
    .line 760
    invoke-static {v7}, Lo0/a;->a(Landroid/util/Size;)I

    .line 761
    .line 762
    .line 763
    move-result v8

    .line 764
    if-gt v8, v1, :cond_1e

    .line 765
    .line 766
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 767
    .line 768
    .line 769
    goto :goto_b

    .line 770
    :cond_1f
    invoke-interface {v2}, Ljava/util/List;->clear()V

    .line 771
    .line 772
    .line 773
    invoke-interface {v2, v3}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 774
    .line 775
    .line 776
    goto :goto_a

    .line 777
    :cond_20
    iget-object p1, p1, Ls0/b;->b:Ls0/c;

    .line 778
    .line 779
    if-nez p1, :cond_21

    .line 780
    .line 781
    goto :goto_d

    .line 782
    :cond_21
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    .line 783
    .line 784
    .line 785
    move-result-object v0

    .line 786
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 787
    .line 788
    .line 789
    move-result-object v0

    .line 790
    :cond_22
    :goto_c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 791
    .line 792
    .line 793
    move-result v1

    .line 794
    if-eqz v1, :cond_2a

    .line 795
    .line 796
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 797
    .line 798
    .line 799
    move-result-object v1

    .line 800
    check-cast v1, Landroid/util/Rational;

    .line 801
    .line 802
    invoke-virtual {p0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 803
    .line 804
    .line 805
    move-result-object v1

    .line 806
    check-cast v1, Ljava/util/List;

    .line 807
    .line 808
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 809
    .line 810
    .line 811
    move-result v2

    .line 812
    if-eqz v2, :cond_23

    .line 813
    .line 814
    goto :goto_c

    .line 815
    :cond_23
    iget v2, p1, Ls0/c;->b:I

    .line 816
    .line 817
    sget-object v3, Ls0/c;->c:Ls0/c;

    .line 818
    .line 819
    invoke-virtual {p1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 820
    .line 821
    .line 822
    move-result v3

    .line 823
    if-eqz v3, :cond_24

    .line 824
    .line 825
    goto :goto_c

    .line 826
    :cond_24
    iget-object v3, p1, Ls0/c;->a:Landroid/util/Size;

    .line 827
    .line 828
    if-eqz v2, :cond_29

    .line 829
    .line 830
    if-eq v2, v6, :cond_28

    .line 831
    .line 832
    const/4 v5, 0x2

    .line 833
    if-eq v2, v5, :cond_27

    .line 834
    .line 835
    const/4 v5, 0x3

    .line 836
    if-eq v2, v5, :cond_26

    .line 837
    .line 838
    const/4 v5, 0x4

    .line 839
    if-eq v2, v5, :cond_25

    .line 840
    .line 841
    goto :goto_c

    .line 842
    :cond_25
    invoke-static {v1, v3, v4}, Lil/g;->Y(Ljava/util/List;Landroid/util/Size;Z)V

    .line 843
    .line 844
    .line 845
    goto :goto_c

    .line 846
    :cond_26
    invoke-static {v1, v3, v6}, Lil/g;->Y(Ljava/util/List;Landroid/util/Size;Z)V

    .line 847
    .line 848
    .line 849
    goto :goto_c

    .line 850
    :cond_27
    invoke-static {v1, v3, v4}, Lil/g;->X(Ljava/util/List;Landroid/util/Size;Z)V

    .line 851
    .line 852
    .line 853
    goto :goto_c

    .line 854
    :cond_28
    invoke-static {v1, v3, v6}, Lil/g;->X(Ljava/util/List;Landroid/util/Size;Z)V

    .line 855
    .line 856
    .line 857
    goto :goto_c

    .line 858
    :cond_29
    invoke-interface {v1, v3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 859
    .line 860
    .line 861
    move-result v2

    .line 862
    invoke-interface {v1}, Ljava/util/List;->clear()V

    .line 863
    .line 864
    .line 865
    if-eqz v2, :cond_22

    .line 866
    .line 867
    invoke-interface {v1, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 868
    .line 869
    .line 870
    goto :goto_c

    .line 871
    :cond_2a
    :goto_d
    new-instance p1, Ljava/util/ArrayList;

    .line 872
    .line 873
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 874
    .line 875
    .line 876
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 877
    .line 878
    .line 879
    move-result-object p0

    .line 880
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 881
    .line 882
    .line 883
    move-result-object p0

    .line 884
    :cond_2b
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 885
    .line 886
    .line 887
    move-result v0

    .line 888
    if-eqz v0, :cond_2d

    .line 889
    .line 890
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 891
    .line 892
    .line 893
    move-result-object v0

    .line 894
    check-cast v0, Ljava/util/List;

    .line 895
    .line 896
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 897
    .line 898
    .line 899
    move-result-object v0

    .line 900
    :cond_2c
    :goto_e
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 901
    .line 902
    .line 903
    move-result v1

    .line 904
    if-eqz v1, :cond_2b

    .line 905
    .line 906
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 907
    .line 908
    .line 909
    move-result-object v1

    .line 910
    check-cast v1, Landroid/util/Size;

    .line 911
    .line 912
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 913
    .line 914
    .line 915
    move-result v2

    .line 916
    if-nez v2, :cond_2c

    .line 917
    .line 918
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 919
    .line 920
    .line 921
    goto :goto_e

    .line 922
    :cond_2d
    return-object p1
.end method

.method public L(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh6/e;

    .line 4
    .line 5
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public M()I
    .locals 0

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh6/e;

    .line 4
    .line 5
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public O(Landroid/view/View;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lh6/e;

    .line 11
    .line 12
    invoke-static {p1}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-eqz p1, :cond_2

    .line 17
    .line 18
    iget-object v0, p1, Lka/v0;->a:Landroid/view/View;

    .line 19
    .line 20
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 23
    .line 24
    iget v1, p1, Lka/v0;->q:I

    .line 25
    .line 26
    const/4 v2, -0x1

    .line 27
    if-eq v1, v2, :cond_0

    .line 28
    .line 29
    iput v1, p1, Lka/v0;->p:I

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/view/View;->getImportantForAccessibility()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    iput v1, p1, Lka/v0;->p:I

    .line 39
    .line 40
    :goto_0
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->M()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/4 v2, 0x4

    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    iput v2, p1, Lka/v0;->q:I

    .line 48
    .line 49
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->D1:Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    sget-object p0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 56
    .line 57
    invoke-virtual {v0, v2}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 58
    .line 59
    .line 60
    :cond_2
    return-void
.end method

.method public P()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll2/t2;

    .line 4
    .line 5
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 10
    .line 11
    if-ne v0, v1, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lil/g;

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0}, Lil/g;->P()Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 29
    return p0
.end method

.method public S(Leb/j0;Ljp/uf;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v4, v0

    .line 4
    check-cast v4, Landroidx/collection/a0;

    .line 5
    .line 6
    iget v0, v4, Landroidx/collection/a0;->b:I

    .line 7
    .line 8
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p0

    .line 11
    check-cast v2, Landroidx/collection/l0;

    .line 12
    .line 13
    new-instance v3, Landroidx/collection/l0;

    .line 14
    .line 15
    invoke-direct {v3}, Landroidx/collection/l0;-><init>()V

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    move v1, p0

    .line 20
    move v5, v1

    .line 21
    :goto_0
    if-ge v1, v0, :cond_1

    .line 22
    .line 23
    add-int/lit8 v6, v1, 0x1

    .line 24
    .line 25
    :try_start_0
    invoke-virtual {v4, v1}, Landroidx/collection/a0;->c(I)I

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    packed-switch v7, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    goto :goto_3

    .line 33
    :pswitch_0
    iget-object v1, p1, Leb/j0;->g:Ljava/lang/Object;

    .line 34
    .line 35
    instance-of v7, v1, Ll2/j;

    .line 36
    .line 37
    if-eqz v7, :cond_0

    .line 38
    .line 39
    move-object v7, v1

    .line 40
    check-cast v7, Ll2/j;

    .line 41
    .line 42
    iget-object v8, p2, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 43
    .line 44
    check-cast v8, Ln2/b;

    .line 45
    .line 46
    invoke-virtual {v8, v7}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    if-eqz v8, :cond_0

    .line 51
    .line 52
    invoke-interface {v7}, Ll2/j;->a()V

    .line 53
    .line 54
    .line 55
    goto :goto_2

    .line 56
    :goto_1
    move v5, v6

    .line 57
    move-object v6, p0

    .line 58
    goto/16 :goto_6

    .line 59
    .line 60
    :catchall_0
    move-exception v0

    .line 61
    move-object p0, v0

    .line 62
    goto/16 :goto_7

    .line 63
    .line 64
    :catch_0
    move-exception v0

    .line 65
    move-object p0, v0

    .line 66
    goto :goto_1

    .line 67
    :cond_0
    :goto_2
    invoke-virtual {v3, v1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    invoke-interface {p1}, Ll2/c;->m()V

    .line 71
    .line 72
    .line 73
    goto :goto_3

    .line 74
    :pswitch_1
    add-int/lit8 v1, v5, 0x1

    .line 75
    .line 76
    invoke-virtual {v2, v5}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    const-string v8, "null cannot be cast to non-null type @[ExtensionFunctionType] kotlin.Function2<kotlin.Any?, kotlin.Any?, kotlin.Unit>"

    .line 81
    .line 82
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const/4 v8, 0x2

    .line 86
    invoke-static {v8, v7}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    check-cast v7, Lay0/n;

    .line 90
    .line 91
    add-int/lit8 v5, v5, 0x2

    .line 92
    .line 93
    invoke-virtual {v2, v1}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-interface {p1, v1, v7}, Ll2/c;->d(Ljava/lang/Object;Lay0/n;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 98
    .line 99
    .line 100
    :goto_3
    move v1, v6

    .line 101
    goto :goto_0

    .line 102
    :pswitch_2
    add-int/lit8 v1, v1, 0x2

    .line 103
    .line 104
    :try_start_1
    invoke-virtual {v4, v6}, Landroidx/collection/a0;->c(I)I

    .line 105
    .line 106
    .line 107
    move-result v6

    .line 108
    add-int/lit8 v7, v5, 0x1

    .line 109
    .line 110
    invoke-virtual {v2, v5}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    invoke-interface {p1, v6, v5}, Ll2/c;->e(ILjava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :goto_4
    move v5, v7

    .line 118
    goto :goto_0

    .line 119
    :catch_1
    move-exception v0

    .line 120
    move-object p0, v0

    .line 121
    move-object v6, p0

    .line 122
    move v5, v1

    .line 123
    goto/16 :goto_6

    .line 124
    .line 125
    :pswitch_3
    add-int/lit8 v1, v1, 0x2

    .line 126
    .line 127
    invoke-virtual {v4, v6}, Landroidx/collection/a0;->c(I)I

    .line 128
    .line 129
    .line 130
    move-result v6

    .line 131
    add-int/lit8 v7, v5, 0x1

    .line 132
    .line 133
    invoke-virtual {v2, v5}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    invoke-interface {p1, v6, v5}, Ll2/c;->k(ILjava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 138
    .line 139
    .line 140
    goto :goto_4

    .line 141
    :pswitch_4
    :try_start_2
    invoke-virtual {p1}, Leb/j0;->r()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 142
    .line 143
    .line 144
    goto :goto_3

    .line 145
    :pswitch_5
    add-int/lit8 v7, v1, 0x2

    .line 146
    .line 147
    :try_start_3
    invoke-virtual {v4, v6}, Landroidx/collection/a0;->c(I)I

    .line 148
    .line 149
    .line 150
    move-result v6
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 151
    add-int/lit8 v8, v1, 0x3

    .line 152
    .line 153
    :try_start_4
    invoke-virtual {v4, v7}, Landroidx/collection/a0;->c(I)I

    .line 154
    .line 155
    .line 156
    move-result v7
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_2
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 157
    add-int/lit8 v1, v1, 0x4

    .line 158
    .line 159
    :try_start_5
    invoke-virtual {v4, v8}, Landroidx/collection/a0;->c(I)I

    .line 160
    .line 161
    .line 162
    move-result v8

    .line 163
    invoke-interface {p1, v6, v7, v8}, Ll2/c;->b(III)V
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 164
    .line 165
    .line 166
    goto/16 :goto_0

    .line 167
    .line 168
    :catch_2
    move-exception v0

    .line 169
    move-object p0, v0

    .line 170
    move-object v6, p0

    .line 171
    move v5, v8

    .line 172
    goto :goto_6

    .line 173
    :catch_3
    move-exception v0

    .line 174
    move-object p0, v0

    .line 175
    move-object v6, p0

    .line 176
    move v5, v7

    .line 177
    goto :goto_6

    .line 178
    :pswitch_6
    add-int/lit8 v7, v1, 0x2

    .line 179
    .line 180
    :try_start_6
    invoke-virtual {v4, v6}, Landroidx/collection/a0;->c(I)I

    .line 181
    .line 182
    .line 183
    move-result v6
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_3
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 184
    add-int/lit8 v1, v1, 0x3

    .line 185
    .line 186
    :try_start_7
    invoke-virtual {v4, v7}, Landroidx/collection/a0;->c(I)I

    .line 187
    .line 188
    .line 189
    move-result v7

    .line 190
    invoke-interface {p1, v6, v7}, Ll2/c;->c(II)V
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_1
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 191
    .line 192
    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :pswitch_7
    add-int/lit8 v1, v5, 0x1

    .line 196
    .line 197
    :try_start_8
    invoke-virtual {v2, v5}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v5

    .line 201
    invoke-virtual {p1, v5}, Leb/j0;->l(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    move v5, v1

    .line 205
    goto :goto_3

    .line 206
    :pswitch_8
    invoke-virtual {p1}, Leb/j0;->o()V
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 207
    .line 208
    .line 209
    goto :goto_3

    .line 210
    :cond_1
    :try_start_9
    iget p2, v2, Landroidx/collection/l0;->b:I

    .line 211
    .line 212
    if-ne v5, p2, :cond_2

    .line 213
    .line 214
    goto :goto_5

    .line 215
    :cond_2
    const-string p2, "Applier operation size mismatch"

    .line 216
    .line 217
    invoke-static {p2}, Ll2/v;->c(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    :goto_5
    invoke-virtual {v2}, Landroidx/collection/l0;->c()V

    .line 221
    .line 222
    .line 223
    iput p0, v4, Landroidx/collection/a0;->b:I
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_1
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 224
    .line 225
    invoke-interface {p1}, Ll2/c;->f()V

    .line 226
    .line 227
    .line 228
    return-void

    .line 229
    :goto_6
    :try_start_a
    new-instance v1, Ll2/l;

    .line 230
    .line 231
    invoke-direct/range {v1 .. v6}, Ll2/l;-><init>(Landroidx/collection/l0;Landroidx/collection/l0;Landroidx/collection/a0;ILjava/lang/Exception;)V

    .line 232
    .line 233
    .line 234
    throw v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 235
    :goto_7
    invoke-interface {p1}, Ll2/c;->f()V

    .line 236
    .line 237
    .line 238
    throw p0

    .line 239
    :pswitch_data_0
    .packed-switch 0x0
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

.method public U()V
    .locals 0

    .line 1
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/content/res/TypedArray;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public V(Ljava/lang/String;)Lin/y0;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto/16 :goto_1

    .line 5
    .line 6
    :cond_0
    const-string v1, "\""

    .line 7
    .line 8
    invoke-virtual {p1, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    invoke-virtual {p1, v1}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    sub-int/2addr v2, v3

    .line 26
    invoke-virtual {p1, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    const-string v2, "\\\""

    .line 31
    .line 32
    invoke-virtual {p1, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const-string v1, "\'"

    .line 38
    .line 39
    invoke-virtual {p1, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-eqz v2, :cond_2

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_2

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    sub-int/2addr v2, v3

    .line 56
    invoke-virtual {p1, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    const-string v2, "\\\'"

    .line 61
    .line 62
    invoke-virtual {p1, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    :cond_2
    :goto_0
    const-string v1, "\\\n"

    .line 67
    .line 68
    const-string v2, ""

    .line 69
    .line 70
    invoke-virtual {p1, v1, v2}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    const-string v1, "\\A"

    .line 75
    .line 76
    const-string v2, "\n"

    .line 77
    .line 78
    invoke-virtual {p1, v1, v2}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-le v1, v3, :cond_6

    .line 87
    .line 88
    const-string v1, "#"

    .line 89
    .line 90
    invoke-virtual {p1, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-eqz v1, :cond_6

    .line 95
    .line 96
    invoke-virtual {p1, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    iget-object v1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v1, Ljava/util/HashMap;

    .line 103
    .line 104
    if-eqz p1, :cond_6

    .line 105
    .line 106
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    if-nez v2, :cond_3

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_3
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Lin/t0;

    .line 116
    .line 117
    iget-object v0, v0, Lin/y0;->c:Ljava/lang/String;

    .line 118
    .line 119
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    if-eqz v0, :cond_4

    .line 124
    .line 125
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p0, Lin/t0;

    .line 128
    .line 129
    return-object p0

    .line 130
    :cond_4
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_5

    .line 135
    .line 136
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    check-cast p0, Lin/y0;

    .line 141
    .line 142
    return-object p0

    .line 143
    :cond_5
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p0, Lin/t0;

    .line 146
    .line 147
    invoke-static {p0, p1}, Lil/g;->D(Lin/w0;Ljava/lang/String;)Lin/y0;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-virtual {v1, p1, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_6
    :goto_1
    return-object v0
.end method

.method public W(Lk4/l;Lcq/r1;La2/c;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p4, Lk4/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lk4/i;

    .line 7
    .line 8
    iget v1, v0, Lk4/i;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lk4/i;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lk4/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lk4/i;-><init>(Lil/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lk4/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lk4/i;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lk4/i;->d:Lk4/h;

    .line 37
    .line 38
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p4, Lk4/h;

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    invoke-direct {p4, p1}, Lk4/h;-><init>(Lk4/l;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p1, Lnm0/b;

    .line 64
    .line 65
    monitor-enter p1

    .line 66
    :try_start_0
    iget-object p2, p0, Lil/g;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p2, Landroidx/collection/w;

    .line 69
    .line 70
    invoke-virtual {p2, p4}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    check-cast p2, Lk4/g;

    .line 75
    .line 76
    if-nez p2, :cond_3

    .line 77
    .line 78
    iget-object p2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p2, Landroidx/collection/q0;

    .line 81
    .line 82
    invoke-virtual {p2, p4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    check-cast p2, Lk4/g;

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :catchall_0
    move-exception p0

    .line 90
    goto :goto_5

    .line 91
    :cond_3
    :goto_1
    if-eqz p2, :cond_4

    .line 92
    .line 93
    iget-object p0, p2, Lk4/g;->a:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    .line 95
    monitor-exit p1

    .line 96
    return-object p0

    .line 97
    :cond_4
    monitor-exit p1

    .line 98
    iput-object p4, v0, Lk4/i;->d:Lk4/h;

    .line 99
    .line 100
    iput v3, v0, Lk4/i;->g:I

    .line 101
    .line 102
    invoke-virtual {p3, v0}, La2/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    if-ne p1, v1, :cond_5

    .line 107
    .line 108
    return-object v1

    .line 109
    :cond_5
    move-object v4, p4

    .line 110
    move-object p4, p1

    .line 111
    move-object p1, v4

    .line 112
    :goto_2
    iget-object p2, p0, Lil/g;->g:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast p2, Lnm0/b;

    .line 115
    .line 116
    monitor-enter p2

    .line 117
    if-nez p4, :cond_6

    .line 118
    .line 119
    :try_start_1
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p0, Landroidx/collection/q0;

    .line 122
    .line 123
    new-instance p3, Lk4/g;

    .line 124
    .line 125
    const/4 v0, 0x0

    .line 126
    invoke-direct {p3, v0}, Lk4/g;-><init>(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p0, p1, p3}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    goto :goto_3

    .line 133
    :catchall_1
    move-exception p0

    .line 134
    goto :goto_4

    .line 135
    :cond_6
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p0, Landroidx/collection/w;

    .line 138
    .line 139
    new-instance p3, Lk4/g;

    .line 140
    .line 141
    invoke-direct {p3, p4}, Lk4/g;-><init>(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {p0, p1, p3}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 145
    .line 146
    .line 147
    :goto_3
    monitor-exit p2

    .line 148
    return-object p4

    .line 149
    :goto_4
    monitor-exit p2

    .line 150
    throw p0

    .line 151
    :goto_5
    monitor-exit p1

    .line 152
    throw p0
.end method

.method public Z(Landroid/view/View;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lh6/e;

    .line 14
    .line 15
    invoke-static {p1}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 24
    .line 25
    iget v0, p1, Lka/v0;->p:I

    .line 26
    .line 27
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->M()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    iput v0, p1, Lka/v0;->q:I

    .line 34
    .line 35
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->D1:Ljava/util/ArrayList;

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    iget-object p0, p1, Lka/v0;->a:Landroid/view/View;

    .line 42
    .line 43
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 46
    .line 47
    .line 48
    :goto_0
    const/4 p0, 0x0

    .line 49
    iput p0, p1, Lka/v0;->p:I

    .line 50
    .line 51
    :cond_1
    return-void
.end method

.method public bridge synthetic a(Ljava/lang/Class;Lzs/d;)Lat/a;
    .locals 1

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    iget-object p2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p2, Ljava/util/HashMap;

    .line 11
    .line 12
    invoke-virtual {p2, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public a0(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 3

    .line 1
    new-instance v0, Lil/g;

    .line 2
    .line 3
    const/16 v1, 0x16

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lil/g;-><init>(IZ)V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lil/g;

    .line 12
    .line 13
    iput-object v0, v1, Lil/g;->g:Ljava/lang/Object;

    .line 14
    .line 15
    iput-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 16
    .line 17
    iput-object p1, v0, Lil/g;->f:Ljava/lang/Object;

    .line 18
    .line 19
    iput-object p2, v0, Lil/g;->e:Ljava/lang/Object;

    .line 20
    .line 21
    return-void
.end method

.method public b(III)V
    .locals 1

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v0, 0x3

    .line 6
    invoke-virtual {p0, v0}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1}, Landroidx/collection/a0;->a(I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, p2}, Landroidx/collection/a0;->a(I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p3}, Landroidx/collection/a0;->a(I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public c(II)V
    .locals 1

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v0, 0x2

    .line 6
    invoke-virtual {p0, v0}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1}, Landroidx/collection/a0;->a(I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, p2}, Landroidx/collection/a0;->a(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public d(Ljava/lang/Object;Lay0/n;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v1, 0x7

    .line 6
    invoke-virtual {v0, v1}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Landroidx/collection/l0;

    .line 12
    .line 13
    invoke-virtual {p0, p2}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public e(ILjava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v1, 0x6

    .line 6
    invoke-virtual {v0, v1}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, p1}, Landroidx/collection/a0;->a(I)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Landroidx/collection/l0;

    .line 15
    .line 16
    invoke-virtual {p0, p2}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public g()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lkx0/a;

    .line 4
    .line 5
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lpx0/g;

    .line 10
    .line 11
    iget-object v1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Lkx0/a;

    .line 14
    .line 15
    invoke-interface {v1}, Lkx0/a;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lhu/a1;

    .line 20
    .line 21
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lju/c;

    .line 24
    .line 25
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lm6/g;

    .line 30
    .line 31
    new-instance v2, Lku/m;

    .line 32
    .line 33
    invoke-direct {v2, v0, v1, p0}, Lku/m;-><init>(Lpx0/g;Lhu/a1;Lm6/g;)V

    .line 34
    .line 35
    .line 36
    return-object v2
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Laq/p;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, p0, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1, v1, v0}, Ly4/h;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lj0/b;

    .line 17
    .line 18
    iget-object v0, v0, Lj0/b;->d:Ljava/util/concurrent/atomic/AtomicReference;

    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    new-instance p1, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v0, "HandlerScheduledFuture-"

    .line 26
    .line 27
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Ljava/util/concurrent/Callable;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method public i(Landroid/view/View;IZ)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lh6/e;

    .line 4
    .line 5
    iget-object v0, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    .line 8
    .line 9
    if-gez p2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0, p2}, Lil/g;->G(I)I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    :goto_0
    iget-object v1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Lg1/i3;

    .line 23
    .line 24
    invoke-virtual {v1, p2, p3}, Lg1/i3;->v(IZ)V

    .line 25
    .line 26
    .line 27
    if-eqz p3, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lil/g;->O(Landroid/view/View;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    invoke-virtual {v0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {p1}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public j(Landroid/os/Bundle;)V
    .locals 6

    .line 1
    const-string v0, "Logging event _ae to Firebase Analytics with params "

    .line 2
    .line 3
    iget-object v1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    sget-object v2, Ljs/c;->a:Ljs/c;

    .line 7
    .line 8
    new-instance v3, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v2, v0}, Ljs/c;->e(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance v0, Ljava/util/concurrent/CountDownLatch;

    .line 24
    .line 25
    const/4 v3, 0x1

    .line 26
    invoke-direct {v0, v3}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 30
    .line 31
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Lhu/q;

    .line 34
    .line 35
    invoke-virtual {v0, p1}, Lhu/q;->j(Landroid/os/Bundle;)V

    .line 36
    .line 37
    .line 38
    const-string p1, "Awaiting app exception callback from Analytics..."

    .line 39
    .line 40
    invoke-virtual {v2, p1}, Ljs/c;->e(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    const/4 p1, 0x0

    .line 44
    :try_start_1
    iget-object v0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Ljava/util/concurrent/CountDownLatch;

    .line 47
    .line 48
    const/16 v3, 0x1f4

    .line 49
    .line 50
    int-to-long v3, v3

    .line 51
    sget-object v5, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 52
    .line 53
    invoke-virtual {v0, v3, v4, v5}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_0

    .line 58
    .line 59
    const-string v0, "App exception callback received from Analytics listener."

    .line 60
    .line 61
    invoke-virtual {v2, v0}, Ljs/c;->e(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :catchall_0
    move-exception p0

    .line 66
    goto :goto_1

    .line 67
    :cond_0
    const-string v0, "Timeout exceeded while awaiting app exception callback from Analytics listener."

    .line 68
    .line 69
    invoke-virtual {v2, v0, p1}, Ljs/c;->f(Ljava/lang/String;Ljava/lang/Exception;)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :catch_0
    :try_start_2
    const-string v0, "Interrupted while awaiting app exception callback from Analytics listener."

    .line 74
    .line 75
    const-string v2, "FirebaseCrashlytics"

    .line 76
    .line 77
    invoke-static {v2, v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 78
    .line 79
    .line 80
    :goto_0
    iput-object p1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 81
    .line 82
    monitor-exit v1

    .line 83
    return-void

    .line 84
    :goto_1
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 85
    throw p0
.end method

.method public k(ILjava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v1, 0x5

    .line 6
    invoke-virtual {v0, v1}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, p1}, Landroidx/collection/a0;->a(I)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Landroidx/collection/l0;

    .line 15
    .line 16
    invoke-virtual {p0, p2}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public l(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-virtual {v0, v1}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Landroidx/collection/l0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public m()V
    .locals 1

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/16 v0, 0x8

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroidx/collection/a0;->a(I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public n(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lh6/e;

    .line 4
    .line 5
    iget-object v0, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    .line 8
    .line 9
    if-gez p2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0, p2}, Lil/g;->G(I)I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    :goto_0
    iget-object v1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Lg1/i3;

    .line 23
    .line 24
    invoke-virtual {v1, p2, p4}, Lg1/i3;->v(IZ)V

    .line 25
    .line 26
    .line 27
    if-eqz p4, :cond_1

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lil/g;->O(Landroid/view/View;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    invoke-static {p1}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    if-eqz p0, :cond_4

    .line 37
    .line 38
    invoke-virtual {p0}, Lka/v0;->j()Z

    .line 39
    .line 40
    .line 41
    move-result p4

    .line 42
    if-nez p4, :cond_3

    .line 43
    .line 44
    invoke-virtual {p0}, Lka/v0;->o()Z

    .line 45
    .line 46
    .line 47
    move-result p4

    .line 48
    if-eqz p4, :cond_2

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    new-instance p2, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    const-string p3, "Called attach on a child which is not detached: "

    .line 56
    .line 57
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->z()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p1

    .line 78
    :cond_3
    :goto_1
    iget p4, p0, Lka/v0;->j:I

    .line 79
    .line 80
    and-int/lit16 p4, p4, -0x101

    .line 81
    .line 82
    iput p4, p0, Lka/v0;->j:I

    .line 83
    .line 84
    :cond_4
    invoke-static {v0, p1, p2, p3}, Landroidx/recyclerview/widget/RecyclerView;->a(Landroidx/recyclerview/widget/RecyclerView;Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    .line 85
    .line 86
    .line 87
    return-void
.end method

.method public o()V
    .locals 1

    .line 1
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/a0;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Landroidx/collection/a0;->a(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public onComplete(Laq/j;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lio/b;

    .line 4
    .line 5
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Ljava/lang/String;

    .line 8
    .line 9
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ljava/util/concurrent/ScheduledFuture;

    .line 12
    .line 13
    iget-object v1, p1, Lio/b;->a:Landroidx/collection/a1;

    .line 14
    .line 15
    monitor-enter v1

    .line 16
    :try_start_0
    iget-object p1, p1, Lio/b;->a:Landroidx/collection/a1;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Landroidx/collection/a1;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    const/4 p1, 0x0

    .line 23
    invoke-interface {p0, p1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    throw p0
.end method

.method public p(Lp0/k;Ljava/util/Map$Entry;)V
    .locals 9

    .line 1
    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v2, v0

    .line 6
    check-cast v2, Lp0/k;

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "     -> outputEdge = "

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "SurfaceProcessorNode"

    .line 23
    .line 24
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, p1, Lp0/k;->g:Lh0/k;

    .line 28
    .line 29
    iget-object v4, v0, Lh0/k;->a:Landroid/util/Size;

    .line 30
    .line 31
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lr0/b;

    .line 36
    .line 37
    iget-object v5, v0, Lr0/b;->d:Landroid/graphics/Rect;

    .line 38
    .line 39
    iget-boolean p1, p1, Lp0/k;->c:Z

    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    if-eqz p1, :cond_0

    .line 43
    .line 44
    iget-object p1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Lh0/b0;

    .line 47
    .line 48
    move-object v6, p1

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move-object v6, v0

    .line 51
    :goto_0
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    check-cast p1, Lr0/b;

    .line 56
    .line 57
    iget v7, p1, Lr0/b;->f:I

    .line 58
    .line 59
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    check-cast p1, Lr0/b;

    .line 64
    .line 65
    iget-boolean v8, p1, Lr0/b;->g:Z

    .line 66
    .line 67
    new-instance v3, Lb0/g;

    .line 68
    .line 69
    invoke-direct/range {v3 .. v8}, Lb0/g;-><init>(Landroid/util/Size;Landroid/graphics/Rect;Lh0/b0;IZ)V

    .line 70
    .line 71
    .line 72
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    check-cast p1, Lr0/b;

    .line 77
    .line 78
    iget v4, p1, Lr0/b;->c:I

    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    invoke-static {}, Llp/k1;->a()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2}, Lp0/k;->a()V

    .line 87
    .line 88
    .line 89
    iget-boolean p1, v2, Lp0/k;->j:Z

    .line 90
    .line 91
    const/4 p2, 0x1

    .line 92
    xor-int/2addr p1, p2

    .line 93
    const-string v1, "Consumer can only be linked once."

    .line 94
    .line 95
    invoke-static {v1, p1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 96
    .line 97
    .line 98
    iput-boolean p2, v2, Lp0/k;->j:Z

    .line 99
    .line 100
    move-object v5, v3

    .line 101
    iget-object v3, v2, Lp0/k;->l:Lp0/j;

    .line 102
    .line 103
    invoke-virtual {v3}, Lh0/t0;->c()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    new-instance v1, Lp0/h;

    .line 108
    .line 109
    move-object v6, v0

    .line 110
    invoke-direct/range {v1 .. v6}, Lp0/h;-><init>(Lp0/k;Lp0/j;ILb0/g;Lb0/g;)V

    .line 111
    .line 112
    .line 113
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    invoke-static {p1, v1, p2}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    new-instance p2, Lb81/d;

    .line 122
    .line 123
    const/16 v0, 0x12

    .line 124
    .line 125
    const/4 v1, 0x0

    .line 126
    invoke-direct {p2, p0, v2, v1, v0}, Lb81/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 127
    .line 128
    .line 129
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    new-instance v0, Lk0/g;

    .line 134
    .line 135
    invoke-direct {v0, v1, p1, p2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, p0, v0}, Lk0/d;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 139
    .line 140
    .line 141
    return-void
.end method

.method public q(Lmw/j;Lnw/g;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lkw/g;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    iget-object v2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v2, Lkw/i;

    .line 11
    .line 12
    if-eqz v2, :cond_2

    .line 13
    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Ld3/a;

    .line 20
    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p2, v0, v2, p1, p0}, Lnw/g;->a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    const-string p0, "insets"

    .line 28
    .line 29
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw v1

    .line 33
    :cond_2
    const-string p0, "horizontalDimensions"

    .line 34
    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v1

    .line 39
    :cond_3
    const-string p0, "context"

    .line 40
    .line 41
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw v1
.end method

.method public r(Lw71/c;Lw71/c;Lw71/c;Lw71/c;)Lv71/f;
    .locals 27

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v2, p0

    .line 6
    .line 7
    move-object/from16 v3, p4

    .line 8
    .line 9
    iget-object v2, v2, Lil/g;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lv71/e;

    .line 12
    .line 13
    invoke-static/range {p1 .. p2}, Lw71/d;->d(Lw71/c;Lw71/c;)Z

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move-object/from16 v4, p2

    .line 21
    .line 22
    invoke-static {v4, v0}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-static {v0, v4}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const-string v4, "dimensions"

    .line 34
    .line 35
    if-nez v3, :cond_2

    .line 36
    .line 37
    invoke-virtual {v0}, Lw71/a;->a()D

    .line 38
    .line 39
    .line 40
    move-result-wide v5

    .line 41
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v0, Lv71/f;

    .line 45
    .line 46
    invoke-direct {v0, v1, v5, v6, v2}, Lv71/f;-><init>(Lw71/c;DLv71/e;)V

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    :cond_2
    invoke-static/range {p3 .. p4}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    invoke-static {v3, v5}, Lmb/e;->o(Lw71/c;Lw71/c;)Lw71/a;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    if-nez v3, :cond_3

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    invoke-virtual {v3}, Lw71/a;->a()D

    .line 62
    .line 63
    .line 64
    move-result-wide v5

    .line 65
    const-wide v7, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    add-double/2addr v5, v7

    .line 71
    invoke-static {v1, v5, v6}, Lmb/e;->n(Lw71/c;D)Lw71/a;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    if-nez v3, :cond_4

    .line 76
    .line 77
    :goto_0
    const/4 v0, 0x0

    .line 78
    return-object v0

    .line 79
    :cond_4
    invoke-virtual {v0}, Lw71/a;->a()D

    .line 80
    .line 81
    .line 82
    move-result-wide v5

    .line 83
    const-wide/high16 v9, 0x3ff0000000000000L    # 1.0

    .line 84
    .line 85
    invoke-static {v5, v6, v9, v10}, Lw71/d;->c(DD)Lw71/c;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    iget-wide v5, v0, Lw71/c;->b:D

    .line 90
    .line 91
    iget-wide v11, v0, Lw71/c;->a:D

    .line 92
    .line 93
    invoke-virtual {v3}, Lw71/a;->a()D

    .line 94
    .line 95
    .line 96
    move-result-wide v13

    .line 97
    invoke-static {v13, v14, v9, v10}, Lw71/d;->c(DD)Lw71/c;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    iget-wide v9, v0, Lw71/c;->b:D

    .line 102
    .line 103
    iget-wide v13, v0, Lw71/c;->a:D

    .line 104
    .line 105
    invoke-static {v11, v12, v5, v6}, Ljava/lang/Math;->hypot(DD)D

    .line 106
    .line 107
    .line 108
    move-result-wide v15

    .line 109
    invoke-static {v13, v14, v9, v10}, Ljava/lang/Math;->hypot(DD)D

    .line 110
    .line 111
    .line 112
    move-result-wide v17

    .line 113
    mul-double v17, v17, v15

    .line 114
    .line 115
    mul-double v15, v11, v13

    .line 116
    .line 117
    mul-double v19, v5, v9

    .line 118
    .line 119
    add-double v21, v19, v15

    .line 120
    .line 121
    const-wide/high16 v23, -0x4010000000000000L    # -1.0

    .line 122
    .line 123
    const-wide/high16 v25, 0x3ff0000000000000L    # 1.0

    .line 124
    .line 125
    invoke-static/range {v21 .. v26}, Lkp/r9;->c(DDD)D

    .line 126
    .line 127
    .line 128
    move-result-wide v15

    .line 129
    invoke-static/range {v15 .. v16}, Ljava/lang/Math;->abs(D)D

    .line 130
    .line 131
    .line 132
    move-result-wide v19

    .line 133
    const-wide v21, 0x3fefff2e48e8a71eL    # 0.9999

    .line 134
    .line 135
    .line 136
    .line 137
    .line 138
    cmpg-double v0, v19, v21

    .line 139
    .line 140
    const-wide/16 v19, 0x0

    .line 141
    .line 142
    if-gez v0, :cond_5

    .line 143
    .line 144
    invoke-static/range {v15 .. v16}, Ljava/lang/Math;->acos(D)D

    .line 145
    .line 146
    .line 147
    move-result-wide v5

    .line 148
    goto :goto_1

    .line 149
    :cond_5
    mul-double/2addr v11, v9

    .line 150
    mul-double/2addr v5, v13

    .line 151
    sub-double/2addr v11, v5

    .line 152
    invoke-static {v11, v12}, Ljava/lang/Math;->abs(D)D

    .line 153
    .line 154
    .line 155
    move-result-wide v5

    .line 156
    cmpl-double v0, v15, v19

    .line 157
    .line 158
    div-double v5, v5, v17

    .line 159
    .line 160
    invoke-static {v5, v6}, Ljava/lang/Math;->asin(D)D

    .line 161
    .line 162
    .line 163
    move-result-wide v5

    .line 164
    if-ltz v0, :cond_6

    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_6
    const-wide v9, 0x400921fb54442d18L    # Math.PI

    .line 168
    .line 169
    .line 170
    .line 171
    .line 172
    sub-double v5, v9, v5

    .line 173
    .line 174
    :goto_1
    cmpl-double v0, v5, v7

    .line 175
    .line 176
    const/16 v5, 0xa

    .line 177
    .line 178
    if-lez v0, :cond_9

    .line 179
    .line 180
    iget-object v0, v3, Lw71/a;->a:Lw71/c;

    .line 181
    .line 182
    iget-wide v6, v0, Lw71/c;->a:D

    .line 183
    .line 184
    neg-double v6, v6

    .line 185
    iget-wide v8, v0, Lw71/c;->b:D

    .line 186
    .line 187
    neg-double v8, v8

    .line 188
    invoke-static {v8, v9, v6, v7}, Ljava/lang/Math;->atan2(DD)D

    .line 189
    .line 190
    .line 191
    move-result-wide v6

    .line 192
    cmpg-double v0, v19, v6

    .line 193
    .line 194
    const-wide v8, 0x401921fb54442d18L    # 6.283185307179586

    .line 195
    .line 196
    .line 197
    .line 198
    .line 199
    if-gtz v0, :cond_7

    .line 200
    .line 201
    cmpg-double v0, v6, v8

    .line 202
    .line 203
    if-gtz v0, :cond_7

    .line 204
    .line 205
    goto :goto_2

    .line 206
    :cond_7
    sub-double v6, v6, v19

    .line 207
    .line 208
    rem-double/2addr v6, v8

    .line 209
    add-double v6, v6, v19

    .line 210
    .line 211
    cmpg-double v0, v6, v19

    .line 212
    .line 213
    if-gez v0, :cond_8

    .line 214
    .line 215
    add-double/2addr v6, v8

    .line 216
    :cond_8
    :goto_2
    invoke-static {v5, v6, v7}, Llp/yc;->a(ID)D

    .line 217
    .line 218
    .line 219
    move-result-wide v5

    .line 220
    goto :goto_3

    .line 221
    :cond_9
    invoke-virtual {v3}, Lw71/a;->a()D

    .line 222
    .line 223
    .line 224
    move-result-wide v6

    .line 225
    invoke-static {v5, v6, v7}, Llp/yc;->a(ID)D

    .line 226
    .line 227
    .line 228
    move-result-wide v5

    .line 229
    :goto_3
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    new-instance v0, Lv71/f;

    .line 233
    .line 234
    invoke-direct {v0, v1, v5, v6, v2}, Lv71/f;-><init>(Lw71/c;DLv71/e;)V

    .line 235
    .line 236
    .line 237
    return-object v0
.end method

.method public s()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Ljava/util/ArrayDeque;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->removeLast()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public t(Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const-string p2, "_ae"

    .line 9
    .line 10
    invoke-virtual {p2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 17
    .line 18
    .line 19
    :cond_1
    :goto_0
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lil/g;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :sswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const/16 v1, 0x20

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const/16 v1, 0x7b

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lil/g;

    .line 33
    .line 34
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lil/g;

    .line 37
    .line 38
    const-string v1, ""

    .line 39
    .line 40
    :goto_0
    if-eqz p0, :cond_2

    .line 41
    .line 42
    iget-object v2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v1, Ljava/lang/String;

    .line 50
    .line 51
    if-eqz v1, :cond_0

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const/16 v1, 0x3d

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    :cond_0
    if-eqz v2, :cond_1

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v1}, Ljava/lang/Class;->isArray()Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_1

    .line 72
    .line 73
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-static {v1}, Ljava/util/Arrays;->deepToString([Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    add-int/lit8 v2, v2, -0x1

    .line 86
    .line 87
    const/4 v3, 0x1

    .line 88
    invoke-virtual {v0, v1, v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_1
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    :goto_1
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p0, Lil/g;

    .line 98
    .line 99
    const-string v1, ", "

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_2
    const/16 p0, 0x7d

    .line 103
    .line 104
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :sswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 113
    .line 114
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 115
    .line 116
    .line 117
    iget-object v1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v1, Lg1/i3;

    .line 120
    .line 121
    invoke-virtual {v1}, Lg1/i3;->toString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", hidden list:"

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast p0, Ljava/util/ArrayList;

    .line 136
    .line 137
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0

    .line 149
    :sswitch_data_0
    .sparse-switch
        0x5 -> :sswitch_1
        0x17 -> :sswitch_0
    .end sparse-switch
.end method

.method public u(I)V
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Lil/g;->G(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lg1/i3;

    .line 8
    .line 9
    invoke-virtual {v0, p1}, Lg1/i3;->x(I)Z

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lh6/e;

    .line 15
    .line 16
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    invoke-static {v0}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-eqz v0, :cond_2

    .line 31
    .line 32
    invoke-virtual {v0}, Lka/v0;->j()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    invoke-virtual {v0}, Lka/v0;->o()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 46
    .line 47
    new-instance v1, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v2, "called detach on an already detached child "

    .line 50
    .line 51
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->z()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p1

    .line 72
    :cond_1
    :goto_0
    const/16 v1, 0x100

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Lka/v0;->a(I)V

    .line 75
    .line 76
    .line 77
    :cond_2
    invoke-static {p0, p1}, Landroidx/recyclerview/widget/RecyclerView;->c(Landroidx/recyclerview/widget/RecyclerView;I)V

    .line 78
    .line 79
    .line 80
    return-void
.end method

.method public v(Lb0/a1;)V
    .locals 4

    .line 1
    invoke-interface {p1}, Lb0/a1;->i0()Lb0/v0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    instance-of v1, v0, Ll0/c;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    check-cast v0, Ll0/c;

    .line 11
    .line 12
    iget-object v0, v0, Ll0/c;->a:Lh0/s;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v2

    .line 16
    :goto_0
    if-nez v0, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    invoke-interface {v0}, Lh0/s;->i()Lh0/q;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    sget-object v3, Lh0/q;->i:Lh0/q;

    .line 24
    .line 25
    if-eq v1, v3, :cond_2

    .line 26
    .line 27
    invoke-interface {v0}, Lh0/s;->i()Lh0/q;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    sget-object v3, Lh0/q;->g:Lh0/q;

    .line 32
    .line 33
    if-eq v1, v3, :cond_2

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    invoke-interface {v0}, Lh0/s;->m()Lh0/p;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    sget-object v3, Lh0/p;->h:Lh0/p;

    .line 41
    .line 42
    if-eq v1, v3, :cond_3

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_3
    invoke-interface {v0}, Lh0/s;->k()Lh0/r;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sget-object v1, Lh0/r;->g:Lh0/r;

    .line 50
    .line 51
    if-eq v0, v1, :cond_4

    .line 52
    .line 53
    :goto_1
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lt0/c;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_4
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 65
    .line 66
    monitor-enter v0

    .line 67
    :try_start_0
    iget-object v1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v1, Ljava/util/ArrayDeque;

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->size()I

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    const/4 v3, 0x3

    .line 76
    if-lt v1, v3, :cond_5

    .line 77
    .line 78
    invoke-virtual {p0}, Lil/g;->s()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    goto :goto_2

    .line 83
    :catchall_0
    move-exception p0

    .line 84
    goto :goto_3

    .line 85
    :cond_5
    :goto_2
    iget-object v1, p0, Lil/g;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v1, Ljava/util/ArrayDeque;

    .line 88
    .line 89
    invoke-virtual {v1, p1}, Ljava/util/ArrayDeque;->addFirst(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 93
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Lt0/c;

    .line 96
    .line 97
    if-eqz p0, :cond_6

    .line 98
    .line 99
    if-eqz v2, :cond_6

    .line 100
    .line 101
    check-cast v2, Lb0/a1;

    .line 102
    .line 103
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 104
    .line 105
    .line 106
    :cond_6
    return-void

    .line 107
    :goto_3
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 108
    throw p0
.end method

.method public w(I)Landroid/view/View;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lil/g;->G(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lh6/e;

    .line 8
    .line 9
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public x()I
    .locals 1

    .line 1
    iget-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lh6/e;

    .line 4
    .line 5
    iget-object v0, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    sub-int/2addr v0, p0

    .line 22
    return v0
.end method

.method public y(I)Landroid/content/res/ColorStateList;
    .locals 2

    .line 1
    iget-object v0, p0, Lil/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/res/TypedArray;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-virtual {v0, p1, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/content/Context;

    .line 21
    .line 22
    invoke-static {p0, v1}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    invoke-virtual {v0, p1}, Landroid/content/res/TypedArray;->getColorStateList(I)Landroid/content/res/ColorStateList;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public z()Ln4/b;
    .locals 7

    .line 1
    invoke-static {}, Landroid/os/LocaleList;->getDefault()Landroid/os/LocaleList;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lil/g;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lnm0/b;

    .line 8
    .line 9
    monitor-enter v1

    .line 10
    :try_start_0
    iget-object v2, p0, Lil/g;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v2, Ln4/b;

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    iget-object v3, p0, Lil/g;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v3, Landroid/os/LocaleList;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    if-ne v0, v3, :cond_0

    .line 21
    .line 22
    monitor-exit v1

    .line 23
    return-object v2

    .line 24
    :cond_0
    :try_start_1
    invoke-virtual {v0}, Landroid/os/LocaleList;->size()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    new-instance v3, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 31
    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    :goto_0
    if-ge v4, v2, :cond_1

    .line 35
    .line 36
    new-instance v5, Ln4/a;

    .line 37
    .line 38
    invoke-virtual {v0, v4}, Landroid/os/LocaleList;->get(I)Ljava/util/Locale;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    invoke-direct {v5, v6}, Ln4/a;-><init>(Ljava/util/Locale;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    add-int/lit8 v4, v4, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance v2, Ln4/b;

    .line 54
    .line 55
    invoke-direct {v2, v3}, Ln4/b;-><init>(Ljava/util/List;)V

    .line 56
    .line 57
    .line 58
    iput-object v0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 59
    .line 60
    iput-object v2, p0, Lil/g;->f:Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    monitor-exit v1

    .line 63
    return-object v2

    .line 64
    :goto_1
    monitor-exit v1

    .line 65
    throw p0
.end method
