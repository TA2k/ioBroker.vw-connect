.class public final Lt3/n1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lt3/o1;


# direct methods
.method public synthetic constructor <init>(Lt3/o1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt3/n1;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lt3/n1;->g:Lt3/o1;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lt3/n1;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lv3/h0;

    .line 7
    .line 8
    check-cast p2, Lt3/o1;

    .line 9
    .line 10
    iget-object p0, p0, Lt3/n1;->g:Lt3/o1;

    .line 11
    .line 12
    iget-object p2, p0, Lt3/o1;->a:Lt3/q1;

    .line 13
    .line 14
    iget-object v0, p1, Lv3/h0;->J:Lt3/m0;

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    new-instance v0, Lt3/m0;

    .line 19
    .line 20
    invoke-direct {v0, p1, p2}, Lt3/m0;-><init>(Lv3/h0;Lt3/q1;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p1, Lv3/h0;->J:Lt3/m0;

    .line 24
    .line 25
    :cond_0
    iput-object v0, p0, Lt3/o1;->b:Lt3/m0;

    .line 26
    .line 27
    invoke-virtual {p0}, Lt3/o1;->a()Lt3/m0;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p1}, Lt3/m0;->d()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lt3/o1;->a()Lt3/m0;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    iget-object p1, p0, Lt3/m0;->f:Lt3/q1;

    .line 39
    .line 40
    if-eq p1, p2, :cond_1

    .line 41
    .line 42
    iput-object p2, p0, Lt3/m0;->f:Lt3/q1;

    .line 43
    .line 44
    const/4 p1, 0x0

    .line 45
    invoke-virtual {p0, p1}, Lt3/m0;->g(Z)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lt3/m0;->d:Lv3/h0;

    .line 49
    .line 50
    const/4 p2, 0x7

    .line 51
    invoke-static {p0, p1, p2}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 52
    .line 53
    .line 54
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_0
    check-cast p1, Lv3/h0;

    .line 58
    .line 59
    check-cast p2, Lay0/n;

    .line 60
    .line 61
    iget-object p0, p0, Lt3/n1;->g:Lt3/o1;

    .line 62
    .line 63
    invoke-virtual {p0}, Lt3/o1;->a()Lt3/m0;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    iget-object v0, p0, Lt3/m0;->s:Ljava/lang/String;

    .line 68
    .line 69
    new-instance v1, Lt3/j0;

    .line 70
    .line 71
    invoke-direct {v1, p0, p2, v0}, Lt3/j0;-><init>(Lt3/m0;Lay0/n;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, v1}, Lv3/h0;->h0(Lt3/q0;)V

    .line 75
    .line 76
    .line 77
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    return-object p0

    .line 80
    :pswitch_1
    check-cast p1, Lv3/h0;

    .line 81
    .line 82
    check-cast p2, Ll2/x;

    .line 83
    .line 84
    iget-object p0, p0, Lt3/n1;->g:Lt3/o1;

    .line 85
    .line 86
    invoke-virtual {p0}, Lt3/o1;->a()Lt3/m0;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    iput-object p2, p0, Lt3/m0;->e:Ll2/x;

    .line 91
    .line 92
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
