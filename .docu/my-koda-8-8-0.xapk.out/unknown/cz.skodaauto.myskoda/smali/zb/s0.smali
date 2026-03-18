.class public final synthetic Lzb/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzb/v0;


# direct methods
.method public synthetic constructor <init>(Lzb/v0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lzb/s0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzb/s0;->e:Lzb/v0;

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
    .locals 2

    .line 1
    iget v0, p0, Lzb/s0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 7
    .line 8
    const-string v0, "$this$DisposableEffect"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance p1, La2/j;

    .line 14
    .line 15
    const/16 v0, 0x16

    .line 16
    .line 17
    iget-object p0, p0, Lzb/s0;->e:Lzb/v0;

    .line 18
    .line 19
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 24
    .line 25
    const-string v0, "it"

    .line 26
    .line 27
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lod0/d;

    .line 31
    .line 32
    const/16 v1, 0x10

    .line 33
    .line 34
    invoke-direct {v0, p1, v1}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lzb/s0;->e:Lzb/v0;

    .line 38
    .line 39
    invoke-virtual {p0, v0}, Lzb/v0;->g(Lay0/k;)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_1
    check-cast p1, Ljava/lang/String;

    .line 46
    .line 47
    const-string v0, "url"

    .line 48
    .line 49
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Lod0/d;

    .line 53
    .line 54
    const/16 v1, 0xf

    .line 55
    .line 56
    invoke-direct {v0, p1, v1}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    iget-object p0, p0, Lzb/s0;->e:Lzb/v0;

    .line 60
    .line 61
    invoke-virtual {p0, v0}, Lzb/v0;->g(Lay0/k;)V

    .line 62
    .line 63
    .line 64
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0

    .line 67
    :pswitch_2
    check-cast p1, Lgi/c;

    .line 68
    .line 69
    const-string v0, "$this$log"

    .line 70
    .line 71
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, Lzb/s0;->e:Lzb/v0;

    .line 75
    .line 76
    iget-object p0, p0, Lzb/v0;->d:Ljava/lang/String;

    .line 77
    .line 78
    const-string p1, " received an event but references were disposed"

    .line 79
    .line 80
    invoke-static {p0, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
