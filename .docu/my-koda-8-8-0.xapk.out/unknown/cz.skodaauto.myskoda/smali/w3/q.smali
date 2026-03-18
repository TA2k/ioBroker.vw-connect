.class public final Lw3/q;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lw3/t;


# direct methods
.method public synthetic constructor <init>(Lw3/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw3/q;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lw3/q;->g:Lw3/t;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lw3/q;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lw3/q;->g:Lw3/t;

    .line 7
    .line 8
    invoke-static {p0}, Lw3/t;->d(Lw3/t;)Lw3/l;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lw3/q;->g:Lw3/t;

    .line 14
    .line 15
    iget-object v0, p0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {v0}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/4 v1, 0x7

    .line 24
    if-eq v0, v1, :cond_0

    .line 25
    .line 26
    const/16 v1, 0x9

    .line 27
    .line 28
    if-eq v0, v1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 32
    .line 33
    .line 34
    move-result-wide v0

    .line 35
    iput-wide v0, p0, Lw3/t;->F1:J

    .line 36
    .line 37
    iget-object v0, p0, Lw3/t;->K1:Lvp/g4;

    .line 38
    .line 39
    invoke-virtual {p0, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 40
    .line 41
    .line 42
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_1
    iget-object p0, p0, Lw3/q;->g:Lw3/t;

    .line 46
    .line 47
    invoke-static {p0}, Lw3/h0;->l(Lw3/t;)J

    .line 48
    .line 49
    .line 50
    move-result-wide v0

    .line 51
    new-instance p0, Lt4/l;

    .line 52
    .line 53
    invoke-direct {p0, v0, v1}, Lt4/l;-><init>(J)V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
