.class public final synthetic Lt61/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt61/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt61/c;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

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
    iget v0, p0, Lt61/c;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lt61/c;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->H(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->E(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->k(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
