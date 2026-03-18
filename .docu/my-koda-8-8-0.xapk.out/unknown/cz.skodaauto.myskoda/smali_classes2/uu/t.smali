.class public final Luu/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILandroid/view/View;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Luu/t;->d:I

    iput-object p2, p0, Luu/t;->e:Ljava/lang/Object;

    iput-object p3, p0, Luu/t;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/h;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Luu/t;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Luu/t;->f:Ljava/lang/Object;

    return-void
.end method

.method private final a(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final b(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 1

    .line 1
    iget v0, p0, Luu/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    return-void

    .line 7
    :pswitch_1
    const-string v0, "mapView"

    .line 8
    .line 9
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iget-object v0, p0, Luu/t;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Landroidx/lifecycle/h;

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Luu/t;->e:Ljava/lang/Object;

    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 2

    .line 1
    iget v0, p0, Luu/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Luu/t;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Landroid/view/View;

    .line 9
    .line 10
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Luu/t;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ll2/y1;

    .line 16
    .line 17
    invoke-virtual {p0}, Ll2/y1;->v()V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_0
    iget-object p1, p0, Luu/t;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p1, Landroid/view/View;

    .line 24
    .line 25
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Luu/t;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lxy0/x;

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    check-cast p0, Lxy0/w;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lxy0/w;->o0(Ljava/lang/Throwable;)Z

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_1
    iget-object v0, p0, Luu/t;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Landroidx/lifecycle/h;

    .line 42
    .line 43
    const-string v1, "v"

    .line 44
    .line 45
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p1, p0, Luu/t;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p1, Landroidx/lifecycle/r;

    .line 51
    .line 52
    if-eqz p1, :cond_0

    .line 53
    .line 54
    invoke-virtual {p1, v0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 55
    .line 56
    .line 57
    :cond_0
    const/4 p1, 0x0

    .line 58
    iput-object p1, p0, Luu/t;->e:Ljava/lang/Object;

    .line 59
    .line 60
    iget-object p0, v0, Landroidx/lifecycle/h;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p0, Landroidx/lifecycle/q;

    .line 63
    .line 64
    sget-object p1, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-lez p0, :cond_1

    .line 71
    .line 72
    invoke-virtual {v0, p1}, Landroidx/lifecycle/h;->b(Landroidx/lifecycle/q;)V

    .line 73
    .line 74
    .line 75
    :cond_1
    return-void

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
