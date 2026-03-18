.class public final Lx4/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx4/t;


# direct methods
.method public synthetic constructor <init>(Lx4/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lx4/h;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lx4/h;->g:Lx4/t;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lx4/h;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lay0/a;

    .line 7
    .line 8
    iget-object p0, p0, Lx4/h;->g:Lx4/t;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x0

    .line 22
    :goto_0
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-ne v0, v1, :cond_1

    .line 27
    .line 28
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    new-instance v0, Lh91/c;

    .line 39
    .line 40
    const/16 v1, 0x9

    .line 41
    .line 42
    invoke-direct {v0, p1, v1}, Lh91/c;-><init>(Lay0/a;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 46
    .line 47
    .line 48
    :cond_2
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    check-cast p1, Lt4/l;

    .line 52
    .line 53
    iget-wide v0, p1, Lt4/l;->a:J

    .line 54
    .line 55
    new-instance p1, Lt4/l;

    .line 56
    .line 57
    invoke-direct {p1, v0, v1}, Lt4/l;-><init>(J)V

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Lx4/h;->g:Lx4/t;

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Lx4/t;->setPopupContentSize-fhxjrPA(Lt4/l;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Lx4/t;->n()V

    .line 66
    .line 67
    .line 68
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_1
    check-cast p1, Lt3/y;

    .line 72
    .line 73
    invoke-interface {p1}, Lt3/y;->O()Lt3/y;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lx4/h;->g:Lx4/t;

    .line 81
    .line 82
    invoke-virtual {p0, p1}, Lx4/t;->m(Lt3/y;)V

    .line 83
    .line 84
    .line 85
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
