.class public final synthetic Ly1/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly1/f;


# direct methods
.method public synthetic constructor <init>(Ly1/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly1/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly1/a;->e:Ly1/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ly1/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 7
    .line 8
    iget-object p0, p0, Ly1/a;->e:Ly1/f;

    .line 9
    .line 10
    iget-object p1, p0, Ly1/f;->e:Lv2/r;

    .line 11
    .line 12
    invoke-virtual {p1}, Lv2/r;->e()V

    .line 13
    .line 14
    .line 15
    new-instance p1, La2/j;

    .line 16
    .line 17
    const/16 v0, 0x15

    .line 18
    .line 19
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :pswitch_0
    iget-object p0, p0, Ly1/a;->e:Ly1/f;

    .line 24
    .line 25
    iget-object p0, p0, Ly1/f;->h:Landroid/view/ActionMode;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Landroid/view/ActionMode;->invalidateContentRect()V

    .line 30
    .line 31
    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_1
    iget-object p0, p0, Ly1/a;->e:Ly1/f;

    .line 36
    .line 37
    iget-object p0, p0, Ly1/f;->h:Landroid/view/ActionMode;

    .line 38
    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    invoke-virtual {p0}, Landroid/view/ActionMode;->invalidate()V

    .line 42
    .line 43
    .line 44
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_2
    check-cast p1, Lay0/a;

    .line 48
    .line 49
    iget-object p0, p0, Ly1/a;->e:Ly1/f;

    .line 50
    .line 51
    iget-object p0, p0, Ly1/f;->a:Landroid/view/View;

    .line 52
    .line 53
    invoke-virtual {p0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    goto :goto_0

    .line 64
    :cond_2
    const/4 v0, 0x0

    .line 65
    :goto_0
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    if-ne v0, v1, :cond_3

    .line 70
    .line 71
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    invoke-virtual {p0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-eqz p0, :cond_4

    .line 80
    .line 81
    new-instance v0, Lh91/c;

    .line 82
    .line 83
    const/16 v1, 0xa

    .line 84
    .line 85
    invoke-direct {v0, p1, v1}, Lh91/c;-><init>(Lay0/a;I)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 89
    .line 90
    .line 91
    :cond_4
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
