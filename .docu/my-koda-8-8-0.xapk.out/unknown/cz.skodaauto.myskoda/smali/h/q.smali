.class public final Lh/q;
.super Ljp/of;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh/q;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lh/q;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b()V
    .locals 2

    .line 1
    iget v0, p0, Lh/q;->a:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object p0, p0, Lh/q;->b:Ljava/lang/Object;

    .line 5
    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    check-cast p0, Lh/z;

    .line 11
    .line 12
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 18
    .line 19
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    instance-of v0, v0, Landroid/view/View;

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget-object p0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 28
    .line 29
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Landroid/view/View;

    .line 34
    .line 35
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 36
    .line 37
    invoke-static {p0}, Ld6/i0;->c(Landroid/view/View;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    return-void

    .line 41
    :pswitch_1
    check-cast p0, Lh/o;

    .line 42
    .line 43
    iget-object p0, p0, Lh/o;->e:Lh/z;

    .line 44
    .line 45
    iget-object p0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 46
    .line 47
    invoke-virtual {p0, v1}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final c()V
    .locals 3

    .line 1
    iget v0, p0, Lh/q;->a:I

    .line 2
    .line 3
    const/high16 v1, 0x3f800000    # 1.0f

    .line 4
    .line 5
    iget-object p0, p0, Lh/q;->b:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast p0, Lb81/b;

    .line 12
    .line 13
    iget-object p0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lh/z;

    .line 16
    .line 17
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 18
    .line 19
    const/16 v1, 0x8

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lh/z;->z:Landroid/widget/PopupWindow;

    .line 25
    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    instance-of v0, v0, Landroid/view/View;

    .line 39
    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 43
    .line 44
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Landroid/view/View;

    .line 49
    .line 50
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 51
    .line 52
    invoke-static {v0}, Ld6/i0;->c(Landroid/view/View;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    :goto_0
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 56
    .line 57
    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarContextView;->e()V

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Lh/z;->B:Ld6/w0;

    .line 61
    .line 62
    invoke-virtual {v0, v2}, Ld6/w0;->d(Ld6/x0;)V

    .line 63
    .line 64
    .line 65
    iput-object v2, p0, Lh/z;->B:Ld6/w0;

    .line 66
    .line 67
    iget-object p0, p0, Lh/z;->D:Landroid/view/ViewGroup;

    .line 68
    .line 69
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 70
    .line 71
    invoke-static {p0}, Ld6/i0;->c(Landroid/view/View;)V

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :pswitch_0
    check-cast p0, Lh/z;

    .line 76
    .line 77
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Landroid/view/View;->setAlpha(F)V

    .line 80
    .line 81
    .line 82
    iget-object v0, p0, Lh/z;->B:Ld6/w0;

    .line 83
    .line 84
    invoke-virtual {v0, v2}, Ld6/w0;->d(Ld6/x0;)V

    .line 85
    .line 86
    .line 87
    iput-object v2, p0, Lh/z;->B:Ld6/w0;

    .line 88
    .line 89
    return-void

    .line 90
    :pswitch_1
    check-cast p0, Lh/o;

    .line 91
    .line 92
    iget-object p0, p0, Lh/o;->e:Lh/z;

    .line 93
    .line 94
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Landroid/view/View;->setAlpha(F)V

    .line 97
    .line 98
    .line 99
    iget-object v0, p0, Lh/z;->B:Ld6/w0;

    .line 100
    .line 101
    invoke-virtual {v0, v2}, Ld6/w0;->d(Ld6/x0;)V

    .line 102
    .line 103
    .line 104
    iput-object v2, p0, Lh/z;->B:Ld6/w0;

    .line 105
    .line 106
    return-void

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
