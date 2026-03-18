.class public final synthetic Lt1/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt1/k1;


# direct methods
.method public synthetic constructor <init>(Lt1/k1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt1/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt1/l;->e:Lt1/k1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lt1/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt1/l;->e:Lt1/k1;

    .line 7
    .line 8
    iget-object v0, p0, Lt1/k1;->b:Lg4/g;

    .line 9
    .line 10
    iget-object p0, p0, Lt1/k1;->a:Ll2/j1;

    .line 11
    .line 12
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lg4/l0;

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Lg4/l0;->a:Lg4/k0;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lg4/k0;->a:Lg4/g;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    :goto_0
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_0
    iget-object p0, p0, Lt1/l;->e:Lt1/k1;

    .line 38
    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    new-instance v0, Lt1/l;

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    invoke-direct {v0, p0, v1}, Lt1/l;-><init>(Lt1/k1;I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Lt1/l;->invoke()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_1
    iget-object p0, p0, Lt1/l;->e:Lt1/k1;

    .line 65
    .line 66
    if-eqz p0, :cond_2

    .line 67
    .line 68
    new-instance v0, Lt1/l;

    .line 69
    .line 70
    const/4 v1, 0x2

    .line 71
    invoke-direct {v0, p0, v1}, Lt1/l;-><init>(Lt1/k1;I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0}, Lt1/l;->invoke()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    check-cast p0, Ljava/lang/Boolean;

    .line 79
    .line 80
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    goto :goto_2

    .line 85
    :cond_2
    const/4 p0, 0x0

    .line 86
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
