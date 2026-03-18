.class public final synthetic La8/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;
.implements Le6/m;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 1
    iput p3, p0, La8/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La8/s;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, La8/s;->e:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public B(Landroid/view/View;)Z
    .locals 4

    .line 1
    iget-object p1, p0, La8/s;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 4
    .line 5
    iget p0, p0, La8/s;->e:I

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_4

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    if-ne p0, v1, :cond_0

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    iget-object v1, p1, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 15
    .line 16
    if-eqz v1, :cond_3

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    iget-object v1, p1, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Landroid/view/View;

    .line 32
    .line 33
    new-instance v2, La8/j0;

    .line 34
    .line 35
    const/4 v3, 0x7

    .line 36
    invoke-direct {v2, p1, p0, v3}, La8/j0;-><init>(Ljava/lang/Object;II)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    if-eqz p0, :cond_2

    .line 44
    .line 45
    invoke-interface {p0}, Landroid/view/ViewParent;->isLayoutRequested()Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-eqz p0, :cond_2

    .line 50
    .line 51
    invoke-virtual {v1}, Landroid/view/View;->isAttachedToWindow()Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    invoke-virtual {v1, v2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 58
    .line 59
    .line 60
    return v0

    .line 61
    :cond_2
    invoke-virtual {v2}, La8/j0;->run()V

    .line 62
    .line 63
    .line 64
    return v0

    .line 65
    :cond_3
    :goto_0
    invoke-virtual {p1, p0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r(I)V

    .line 66
    .line 67
    .line 68
    return v0

    .line 69
    :cond_4
    :goto_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    new-instance v1, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v2, "STATE_"

    .line 74
    .line 75
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    if-ne p0, v0, :cond_5

    .line 79
    .line 80
    const-string p0, "DRAGGING"

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    const-string p0, "SETTLING"

    .line 84
    .line 85
    :goto_2
    const-string v0, " should not be set externally."

    .line 86
    .line 87
    invoke-static {v1, p0, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p1
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, La8/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La8/s;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lt7/x;

    .line 9
    .line 10
    iget p0, p0, La8/s;->e:I

    .line 11
    .line 12
    check-cast p1, Lt7/j0;

    .line 13
    .line 14
    invoke-interface {p1, v0, p0}, Lt7/j0;->f(Lt7/x;I)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, La8/s;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, La8/i1;

    .line 21
    .line 22
    check-cast p1, Lt7/j0;

    .line 23
    .line 24
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 25
    .line 26
    iget p0, p0, La8/s;->e:I

    .line 27
    .line 28
    invoke-interface {p1, p0}, Lt7/j0;->p(I)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
