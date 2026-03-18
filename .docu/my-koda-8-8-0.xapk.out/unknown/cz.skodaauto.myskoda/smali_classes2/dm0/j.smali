.class public final Ldm0/j;
.super Landroid/net/ConnectivityManager$NetworkCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic c:I


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Li40/j0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ldm0/j;->a:I

    .line 2
    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    .line 3
    iput-object p1, p0, Ldm0/j;->b:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ldm0/j;->a:I

    iput-object p1, p0, Ldm0/j;->b:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public onAvailable(Landroid/net/Network;)V
    .locals 1

    .line 1
    iget v0, p0, Ldm0/j;->a:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Landroid/net/ConnectivityManager$NetworkCallback;->onAvailable(Landroid/net/Network;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :sswitch_0
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lrn/i;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-static {p0, p1, v0}, Lrn/i;->m(Lrn/i;Landroid/net/Network;Z)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :sswitch_1
    const-string v0, "network"

    .line 20
    .line 21
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-super {p0, p1}, Landroid/net/ConnectivityManager$NetworkCallback;->onAvailable(Landroid/net/Network;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Ldm0/k;

    .line 30
    .line 31
    iget-object p0, p0, Ldm0/k;->b:Lyl0/a;

    .line 32
    .line 33
    sget-object p1, Lcm0/d;->d:Lcm0/d;

    .line 34
    .line 35
    iget-object p0, p0, Lyl0/a;->a:Lyy0/c2;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_1
        0x3 -> :sswitch_0
    .end sparse-switch
.end method

.method public onCapabilitiesChanged(Landroid/net/Network;Landroid/net/NetworkCapabilities;)V
    .locals 3

    .line 1
    iget v0, p0, Ldm0/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Landroid/net/ConnectivityManager$NetworkCallback;->onCapabilitiesChanged(Landroid/net/Network;Landroid/net/NetworkCapabilities;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    const-string v0, "network"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p1, "capabilities"

    .line 16
    .line 17
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    sget-object v0, Lkb/g;->a:Ljava/lang/String;

    .line 25
    .line 26
    new-instance v1, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    const-string v2, "Network capabilities changed: "

    .line 29
    .line 30
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {p1, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lkb/f;

    .line 46
    .line 47
    const/16 p1, 0xc

    .line 48
    .line 49
    invoke-virtual {p2, p1}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    const/16 v0, 0x10

    .line 54
    .line 55
    invoke-virtual {p2, v0}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    const/16 v1, 0xb

    .line 60
    .line 61
    invoke-virtual {p2, v1}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    xor-int/lit8 v1, v1, 0x1

    .line 66
    .line 67
    const/16 v2, 0x12

    .line 68
    .line 69
    invoke-virtual {p2, v2}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    new-instance v2, Lib/e;

    .line 74
    .line 75
    invoke-direct {v2, p1, v0, v1, p2}, Lib/e;-><init>(ZZZZ)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, v2}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :pswitch_1
    const-string v0, "network"

    .line 83
    .line 84
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const-string p1, "networkCapabilities"

    .line 88
    .line 89
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    sget-object p2, Lib/j;->a:Ljava/lang/String;

    .line 97
    .line 98
    const-string v0, "NetworkRequestConstraintController onCapabilitiesChanged callback"

    .line 99
    .line 100
    invoke-virtual {p1, p2, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast p0, Li40/j0;

    .line 106
    .line 107
    sget-object p1, Lib/a;->a:Lib/a;

    .line 108
    .line 109
    invoke-virtual {p0, p1}, Li40/j0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    return-void

    .line 113
    :pswitch_2
    const-string p0, "network"

    .line 114
    .line 115
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    const-string p0, "networkCapabilities"

    .line 119
    .line 120
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    return-void

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final onLost(Landroid/net/Network;)V
    .locals 2

    .line 1
    iget v0, p0, Ldm0/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lrn/i;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-static {p0, p1, v0}, Lrn/i;->m(Lrn/i;Landroid/net/Network;Z)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    const-string v0, "network"

    .line 16
    .line 17
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    sget-object v0, Lkb/g;->a:Ljava/lang/String;

    .line 25
    .line 26
    const-string v1, "Network connection lost"

    .line 27
    .line 28
    invoke-virtual {p1, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lkb/f;

    .line 34
    .line 35
    iget-object p1, p0, Lkb/f;->f:Landroid/net/ConnectivityManager;

    .line 36
    .line 37
    invoke-static {p1}, Lkb/g;->a(Landroid/net/ConnectivityManager;)Lib/e;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :pswitch_1
    const-string v0, "network"

    .line 46
    .line 47
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    sget-object v0, Lib/j;->a:Ljava/lang/String;

    .line 55
    .line 56
    const-string v1, "NetworkRequestConstraintController onLost callback"

    .line 57
    .line 58
    invoke-virtual {p1, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Li40/j0;

    .line 64
    .line 65
    new-instance p1, Lib/b;

    .line 66
    .line 67
    const/4 v0, 0x7

    .line 68
    invoke-direct {p1, v0}, Lib/b;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0, p1}, Li40/j0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :pswitch_2
    const-string v0, "network"

    .line 76
    .line 77
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-super {p0, p1}, Landroid/net/ConnectivityManager$NetworkCallback;->onLost(Landroid/net/Network;)V

    .line 81
    .line 82
    .line 83
    iget-object p0, p0, Ldm0/j;->b:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p0, Ldm0/k;

    .line 86
    .line 87
    iget-object p0, p0, Ldm0/k;->b:Lyl0/a;

    .line 88
    .line 89
    sget-object p1, Lcm0/d;->e:Lcm0/d;

    .line 90
    .line 91
    iget-object p0, p0, Lyl0/a;->a:Lyy0/c2;

    .line 92
    .line 93
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    const/4 v0, 0x0

    .line 97
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
