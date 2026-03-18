.class public final synthetic Lw00/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lv00/i;


# direct methods
.method public synthetic constructor <init>(Lv00/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw00/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw00/f;->e:Lv00/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lw00/f;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lw00/f;->e:Lv00/i;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p1, Lql0/f;

    .line 11
    .line 12
    const-string v0, "it"

    .line 13
    .line 14
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lv00/i;->i:Ltr0/b;

    .line 18
    .line 19
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    return-object v1

    .line 23
    :pswitch_0
    check-cast p1, Lql0/f;

    .line 24
    .line 25
    const-string v0, "type"

    .line 26
    .line 27
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x2

    .line 31
    new-array v0, v0, [Lql0/f;

    .line 32
    .line 33
    sget-object v2, Lql0/c;->a:Lql0/c;

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    aput-object v2, v0, v3

    .line 37
    .line 38
    sget-object v2, Lql0/d;->a:Lql0/d;

    .line 39
    .line 40
    const/4 v3, 0x1

    .line 41
    aput-object v2, v0, v3

    .line 42
    .line 43
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_0

    .line 52
    .line 53
    iget-object p0, p0, Lv00/i;->i:Ltr0/b;

    .line 54
    .line 55
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    new-instance v0, Lv00/b;

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    invoke-direct {v0, p0, v2, v3}, Lv00/b;-><init>(Lv00/i;Lkotlin/coroutines/Continuation;I)V

    .line 67
    .line 68
    .line 69
    const/4 p0, 0x3

    .line 70
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 71
    .line 72
    .line 73
    :goto_0
    return-object v1

    .line 74
    :pswitch_1
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 75
    .line 76
    const-string v0, "$this$DisposableEffect"

    .line 77
    .line 78
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    new-instance p1, La2/j;

    .line 82
    .line 83
    const/16 v0, 0x10

    .line 84
    .line 85
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    return-object p1

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
