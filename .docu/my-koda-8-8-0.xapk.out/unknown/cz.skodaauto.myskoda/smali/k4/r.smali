.class public final Lk4/r;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/z;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(Lpx0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lk4/r;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private final T(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final U(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final V(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final handleException(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    iget p0, p0, Lk4/r;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    return-void

    .line 7
    :pswitch_1
    sget-object p0, Lu61/a;->d:Lu61/a;

    .line 8
    .line 9
    const-string p1, "RemoteParkAssistPlugin"

    .line 10
    .line 11
    invoke-static {p1, p2, p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 12
    .line 13
    .line 14
    throw p2

    .line 15
    :pswitch_2
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
