.class public final Lil/i;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/z;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lil/j;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lil/i;->d:I

    iput-object p1, p0, Lil/i;->e:Ljava/lang/Object;

    .line 3
    sget-object p1, Lvy0/y;->d:Lvy0/y;

    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    return-void
.end method

.method public constructor <init>(Lt41/z;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lil/i;->d:I

    iput-object p1, p0, Lil/i;->e:Ljava/lang/Object;

    .line 1
    sget-object p1, Lvy0/y;->d:Lvy0/y;

    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    return-void
.end method

.method public constructor <init>(Lx41/u0;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lil/i;->d:I

    iput-object p1, p0, Lil/i;->e:Ljava/lang/Object;

    .line 2
    sget-object p1, Lvy0/y;->d:Lvy0/y;

    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    return-void
.end method


# virtual methods
.method public final handleException(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 7

    .line 1
    iget p1, p0, Lil/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lil/i;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lx41/u0;

    .line 9
    .line 10
    new-instance v0, Lt51/j;

    .line 11
    .line 12
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v5

    .line 16
    const-string p0, "getName(...)"

    .line 17
    .line 18
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    const-string v1, "Car2PhonePairing"

    .line 23
    .line 24
    sget-object v2, Lt51/e;->a:Lt51/e;

    .line 25
    .line 26
    sget-object v3, Lx41/l0;->d:Lx41/l0;

    .line 27
    .line 28
    move-object v4, p2

    .line 29
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    throw v4

    .line 36
    :pswitch_0
    move-object v4, p2

    .line 37
    iget-object p0, p0, Lil/i;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Lt41/z;

    .line 40
    .line 41
    sget-object p1, Lt41/r;->d:Lt41/r;

    .line 42
    .line 43
    const-string p2, "BeaconScanner"

    .line 44
    .line 45
    invoke-static {p0, p2, v4, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 46
    .line 47
    .line 48
    throw v4

    .line 49
    :pswitch_1
    iget-object p0, p0, Lil/i;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lil/j;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
