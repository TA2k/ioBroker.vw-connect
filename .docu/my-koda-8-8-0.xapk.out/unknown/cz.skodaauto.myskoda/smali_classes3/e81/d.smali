.class public final synthetic Le81/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;I)V
    .locals 0

    .line 1
    iput p2, p0, Le81/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le81/d;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

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
    .locals 1

    .line 1
    iget v0, p0, Le81/d;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Le81/d;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p1, Lz71/j;

    .line 9
    .line 10
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/j;)Llx0/b0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p1, Lz71/i;

    .line 16
    .line 17
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/i;)Llx0/b0;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    check-cast p1, Lz71/d;

    .line 23
    .line 24
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/d;)Llx0/b0;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_2
    check-cast p1, Lz71/c;

    .line 30
    .line 31
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/c;)Llx0/b0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_3
    check-cast p1, Lz71/b;

    .line 37
    .line 38
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/b;)Llx0/b0;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
