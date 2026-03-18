.class public final synthetic Liz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lhz/d;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lhz/d;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Liz/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Liz/a;->e:Lhz/d;

    .line 4
    .line 5
    iput-object p2, p0, Liz/a;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Liz/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Liz/a;->e:Lhz/d;

    .line 7
    .line 8
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    new-instance v2, Lhz/c;

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x0

    .line 16
    invoke-direct {v2, v0, v4, v3}, Lhz/c;-><init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Liz/a;->f:Lay0/a;

    .line 24
    .line 25
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object v0, p0, Liz/a;->e:Lhz/d;

    .line 32
    .line 33
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v2, Lhz/c;

    .line 38
    .line 39
    const/4 v3, 0x0

    .line 40
    const/4 v4, 0x0

    .line 41
    invoke-direct {v2, v0, v4, v3}, Lhz/c;-><init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    const/4 v0, 0x3

    .line 45
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Liz/a;->f:Lay0/a;

    .line 49
    .line 50
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_1
    iget-object v0, p0, Liz/a;->e:Lhz/d;

    .line 55
    .line 56
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    new-instance v2, Lhz/c;

    .line 61
    .line 62
    const/4 v3, 0x1

    .line 63
    const/4 v4, 0x0

    .line 64
    invoke-direct {v2, v0, v4, v3}, Lhz/c;-><init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V

    .line 65
    .line 66
    .line 67
    const/4 v0, 0x3

    .line 68
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 69
    .line 70
    .line 71
    iget-object p0, p0, Liz/a;->f:Lay0/a;

    .line 72
    .line 73
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
