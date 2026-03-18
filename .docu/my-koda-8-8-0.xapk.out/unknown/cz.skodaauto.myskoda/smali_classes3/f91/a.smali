.class public final synthetic Lf91/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lf91/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf91/a;->e:Ljava/lang/Object;

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
    iget v0, p0, Lf91/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lf91/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-static {p0}, Llx0/o;->b(Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "createCarKeyManager(): Returning "

    .line 13
    .line 14
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object p0, p0, Lf91/a;->e:Ljava/lang/Object;

    .line 20
    .line 21
    invoke-static {p0}, Llx0/o;->b(Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v0, "isCarKeyCreationSupported="

    .line 26
    .line 27
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    iget-object p0, p0, Lf91/a;->e:Ljava/lang/Object;

    .line 33
    .line 34
    const-string v0, "storeInternal(): Failed to serialize "

    .line 35
    .line 36
    invoke-static {p0, v0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_2
    iget-object p0, p0, Lf91/a;->e:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_3
    const-string v0, "throwableFrom(): Failed to extract throwable from "

    .line 45
    .line 46
    const-string v1, "."

    .line 47
    .line 48
    iget-object p0, p0, Lf91/a;->e:Ljava/lang/Object;

    .line 49
    .line 50
    invoke-static {p0, v0, v1}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
