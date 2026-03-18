.class public final synthetic Landroidx/fragment/app/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroidx/fragment/app/b2;Landroid/view/View;Landroid/graphics/Rect;)V
    .locals 0

    .line 2
    const/4 p1, 0x0

    iput p1, p0, Landroidx/fragment/app/m;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Landroidx/fragment/app/m;->e:Ljava/lang/Object;

    iput-object p3, p0, Landroidx/fragment/app/m;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/fragment/app/p;Landroid/view/ViewGroup;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Landroidx/fragment/app/m;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/fragment/app/m;->e:Ljava/lang/Object;

    iput-object p2, p0, Landroidx/fragment/app/m;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Landroidx/fragment/app/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/m;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/p;

    .line 9
    .line 10
    iget-object p0, p0, Landroidx/fragment/app/m;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/view/ViewGroup;

    .line 13
    .line 14
    const-string v1, "$container"

    .line 15
    .line 16
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, v0, Landroidx/fragment/app/p;->c:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Landroidx/fragment/app/q;

    .line 36
    .line 37
    iget-object v1, v1, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 38
    .line 39
    iget-object v2, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 40
    .line 41
    invoke-virtual {v2}, Landroidx/fragment/app/j0;->getView()Landroid/view/View;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    if-eqz v2, :cond_0

    .line 46
    .line 47
    iget v1, v1, Landroidx/fragment/app/g2;->a:I

    .line 48
    .line 49
    invoke-static {v1, v2, p0}, La7/g0;->a(ILandroid/view/View;Landroid/view/ViewGroup;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    return-void

    .line 54
    :pswitch_0
    iget-object v0, p0, Landroidx/fragment/app/m;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Landroid/view/View;

    .line 57
    .line 58
    iget-object p0, p0, Landroidx/fragment/app/m;->f:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p0, Landroid/graphics/Rect;

    .line 61
    .line 62
    invoke-static {v0, p0}, Landroidx/fragment/app/b2;->j(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
