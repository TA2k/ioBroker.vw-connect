.class public final synthetic Landroidx/fragment/app/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/fragment/app/y;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/fragment/app/y;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/fragment/app/y;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/fragment/app/y;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object p0, p0, Landroidx/fragment/app/j1;->n:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    throw p0

    .line 28
    :pswitch_0
    check-cast p0, Landroidx/fragment/app/p;

    .line 29
    .line 30
    const/4 v0, 0x2

    .line 31
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    const-string v0, "FragmentManager"

    .line 38
    .line 39
    const-string v1, "Transition for all operations has completed"

    .line 40
    .line 41
    invoke-static {v0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    :cond_1
    iget-object v0, p0, Landroidx/fragment/app/p;->c:Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    check-cast v1, Landroidx/fragment/app/q;

    .line 61
    .line 62
    iget-object v1, v1, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 63
    .line 64
    invoke-virtual {v1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    return-void

    .line 69
    :pswitch_1
    check-cast p0, Ljava/util/ArrayList;

    .line 70
    .line 71
    const/4 v0, 0x4

    .line 72
    invoke-static {p0, v0}, Landroidx/fragment/app/u1;->a(Ljava/util/ArrayList;I)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :pswitch_2
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 77
    .line 78
    const-string v0, "$seekCancelLambda"

    .line 79
    .line 80
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p0, Lay0/a;

    .line 86
    .line 87
    if-eqz p0, :cond_3

    .line 88
    .line 89
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    :cond_3
    return-void

    .line 93
    :pswitch_3
    check-cast p0, Landroidx/fragment/app/j0;

    .line 94
    .line 95
    iget-object v0, p0, Landroidx/fragment/app/j0;->mViewLifecycleOwner:Landroidx/fragment/app/c2;

    .line 96
    .line 97
    iget-object v1, p0, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 98
    .line 99
    iget-object v0, v0, Landroidx/fragment/app/c2;->i:Lra/e;

    .line 100
    .line 101
    invoke-virtual {v0, v1}, Lra/e;->b(Landroid/os/Bundle;)V

    .line 102
    .line 103
    .line 104
    const/4 v0, 0x0

    .line 105
    iput-object v0, p0, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 106
    .line 107
    return-void

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
