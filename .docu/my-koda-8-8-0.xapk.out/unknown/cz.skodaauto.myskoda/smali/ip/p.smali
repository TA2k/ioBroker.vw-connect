.class public final synthetic Lip/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lip/p;->a:I

    iput-object p1, p0, Lip/p;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lvp/m1;Lvp/t;Ljava/lang/String;)V
    .locals 0

    const/4 p2, 0x6

    iput p2, p0, Lip/p;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lip/p;->b:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lip/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lvp/m1;

    .line 9
    .line 10
    iget-object v0, p0, Lvp/m1;->c:Lvp/z3;

    .line 11
    .line 12
    invoke-virtual {v0}, Lvp/z3;->B()V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lvp/m1;->c:Lvp/z3;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/z3;->k:Lvp/s0;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/z3;->T(Lvp/u3;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 23
    .line 24
    .line 25
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string v0, "Unexpected call on client side"

    .line 28
    .line 29
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :pswitch_0
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lvp/a1;

    .line 36
    .line 37
    new-instance v0, Lcom/google/android/gms/internal/measurement/k4;

    .line 38
    .line 39
    iget-object p0, p0, Lvp/a1;->o:Lro/f;

    .line 40
    .line 41
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/measurement/k4;-><init>(Lro/f;)V

    .line 42
    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_1
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Llp/lg;

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    sget-object v0, Lno/k;->c:Lno/k;

    .line 53
    .line 54
    iget-object p0, p0, Llp/lg;->g:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {v0, p0}, Lno/k;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_2
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Lkp/la;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    sget-object v0, Lno/k;->c:Lno/k;

    .line 69
    .line 70
    iget-object p0, p0, Lkp/la;->g:Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {v0, p0}, Lno/k;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :pswitch_3
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Ljp/vg;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    sget-object v0, Lno/k;->c:Lno/k;

    .line 85
    .line 86
    iget-object p0, p0, Ljp/vg;->g:Ljava/lang/String;

    .line 87
    .line 88
    invoke-virtual {v0, p0}, Lno/k;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :pswitch_4
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Ljava/lang/Runnable;

    .line 96
    .line 97
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 98
    .line 99
    .line 100
    const/4 p0, 0x0

    .line 101
    return-object p0

    .line 102
    :pswitch_5
    iget-object p0, p0, Lip/p;->b:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p0, Lip/r;

    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    sget-object v0, Lno/k;->c:Lno/k;

    .line 110
    .line 111
    iget-object p0, p0, Lip/r;->a:Ljava/lang/String;

    .line 112
    .line 113
    invoke-virtual {v0, p0}, Lno/k;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    return-object p0

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
