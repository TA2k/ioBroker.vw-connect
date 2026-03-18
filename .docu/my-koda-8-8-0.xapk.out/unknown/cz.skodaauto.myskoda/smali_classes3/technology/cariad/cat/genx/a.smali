.class public final synthetic Ltechnology/cariad/cat/genx/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/TypedFrame;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/TypedFrame;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltechnology/cariad/cat/genx/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/a;->e:Ltechnology/cariad/cat/genx/TypedFrame;

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
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/a;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/a;->e:Ltechnology/cariad/cat/genx/TypedFrame;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->a(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->d(Ltechnology/cariad/cat/genx/TypedFrame;)Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->f(Ltechnology/cariad/cat/genx/TypedFrame;)[B

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_2
    invoke-static {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->b(Ltechnology/cariad/cat/genx/TypedFrame;)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->g(Ltechnology/cariad/cat/genx/TypedFrame;)[B

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->h(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :pswitch_5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->f(Ltechnology/cariad/cat/genx/TypedFrame;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
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
