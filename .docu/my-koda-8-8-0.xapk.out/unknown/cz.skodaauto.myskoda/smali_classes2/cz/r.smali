.class public final Lcz/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcz/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcz/r;->e:Lay0/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lcz/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 7
    .line 8
    const/16 v1, 0x1d

    .line 9
    .line 10
    iget-object p0, p0, Lcz/r;->e:Lay0/a;

    .line 11
    .line 12
    invoke-direct {v0, v1, p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Lxf0/v2;->a:Lg1/e1;

    .line 16
    .line 17
    new-instance v1, Lg1/z1;

    .line 18
    .line 19
    invoke-direct {v1, p1}, Lg1/z1;-><init>(Lp3/x;)V

    .line 20
    .line 21
    .line 22
    new-instance v2, Lxf0/s2;

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    invoke-direct {v2, v1, p0, v0, v3}, Lxf0/s2;-><init>(Lg1/z1;Lay0/o;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    invoke-static {p1, v2, p2}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    if-ne p0, p1, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move-object p0, p2

    .line 40
    :goto_0
    if-ne p0, p1, :cond_1

    .line 41
    .line 42
    move-object p2, p0

    .line 43
    :cond_1
    return-object p2

    .line 44
    :pswitch_0
    iget-object p0, p0, Lcz/r;->e:Lay0/a;

    .line 45
    .line 46
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_1
    new-instance v0, Laj0/c;

    .line 53
    .line 54
    const/16 v1, 0x1b

    .line 55
    .line 56
    iget-object p0, p0, Lcz/r;->e:Lay0/a;

    .line 57
    .line 58
    invoke-direct {v0, p0, v1}, Laj0/c;-><init>(Lay0/a;I)V

    .line 59
    .line 60
    .line 61
    const/4 p0, 0x7

    .line 62
    const/4 v1, 0x0

    .line 63
    invoke-static {p1, v1, v0, p2, p0}, Lg1/g3;->e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    if-ne p0, p1, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    :goto_1
    return-object p0

    .line 75
    :pswitch_2
    iget-object p0, p0, Lcz/r;->e:Lay0/a;

    .line 76
    .line 77
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_3
    iget-object p0, p0, Lcz/r;->e:Lay0/a;

    .line 84
    .line 85
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
