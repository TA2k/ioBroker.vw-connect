.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg61/q;
.implements Lvy0/b0;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00a8\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u0002BY\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u0012\u001c\u0010\u000e\u001a\u0018\u0012\u0014\u0012\u0012\u0012\u0008\u0012\u00060\u000bj\u0002`\u000c\u0012\u0004\u0012\u00020\r0\n0\t\u0012\u0008\u0010\u0010\u001a\u0004\u0018\u00010\u000f\u0012\u0006\u0010\u0012\u001a\u00020\u0011\u0012\u0008\u0010\u0014\u001a\u0004\u0018\u00010\u0013\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J#\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u001a0\u00192\u000c\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\r0\u0017H\u0017\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ#\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u001e0\u00192\u000c\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\r0\u0017H\u0016\u00a2\u0006\u0004\u0008\u001f\u0010\u001cJ\u000f\u0010!\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008!\u0010\"J\u000f\u0010#\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008#\u0010\"J\u0019\u0010(\u001a\u00020\r2\u0008\u0010%\u001a\u0004\u0018\u00010$H\u0000\u00a2\u0006\u0004\u0008&\u0010\'J\u000f\u0010)\u001a\u00020\rH\u0002\u00a2\u0006\u0004\u0008)\u0010\"J+\u00100\u001a\u00020/2\u0008\u0010+\u001a\u0004\u0018\u00010*2\u0006\u0010-\u001a\u00020,2\u0008\u0010.\u001a\u0004\u0018\u00010$H\u0002\u00a2\u0006\u0004\u00080\u00101R\u0014\u0010\u0004\u001a\u00020\u00038\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0004\u00102R\u0014\u0010\u0006\u001a\u00020\u00058\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0006\u00103R\u0014\u0010\u0008\u001a\u00020\u00078\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0008\u00104R*\u0010\u000e\u001a\u0018\u0012\u0014\u0012\u0012\u0012\u0008\u0012\u00060\u000bj\u0002`\u000c\u0012\u0004\u0012\u00020\r0\n0\t8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000e\u00105R\u0014\u0010\u0012\u001a\u00020\u00118\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0012\u00106R\u0016\u0010\u0014\u001a\u0004\u0018\u00010\u00138\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0014\u00107R\u001a\u00109\u001a\u0002088\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00089\u0010:\u001a\u0004\u0008;\u0010<R\u0014\u0010>\u001a\u00020=8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008>\u0010?R \u0010A\u001a\u0008\u0012\u0004\u0012\u00020,0@8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008A\u0010B\u001a\u0004\u0008A\u0010CR\u001c\u0010.\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010$0D8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008.\u0010ER\u001a\u0010F\u001a\u0008\u0012\u0004\u0012\u00020/0D8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008F\u0010ER \u0010G\u001a\u0008\u0012\u0004\u0012\u00020/0@8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008G\u0010B\u001a\u0004\u0008H\u0010CR\u0014\u0010J\u001a\u00020I8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008J\u0010KR\u0018\u0010L\u001a\u0004\u0018\u00010\u000f8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008L\u0010MR\u0018\u0010P\u001a\u00060\u000bj\u0002`\u000c8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008N\u0010O\u00a8\u0006Q"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;",
        "Lg61/q;",
        "Lvy0/b0;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
        "vehicleAntenna",
        "Lg61/d;",
        "rpaConfiguration",
        "Lh61/a;",
        "rpaStarterConfiguration",
        "Ljava/lang/ref/WeakReference;",
        "Lkotlin/Function1;",
        "",
        "Ltechnology/cariad/cat/car2phone/pairing/VIN;",
        "Llx0/b0;",
        "onClose",
        "Lvy0/i1;",
        "supervisorJob",
        "Lvy0/x;",
        "ioDispatcher",
        "Ln71/a;",
        "rpaDispatcher",
        "<init>",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Lg61/d;Lh61/a;Ljava/lang/ref/WeakReference;Lvy0/i1;Lvy0/x;Ln71/a;)V",
        "Lkotlin/Function0;",
        "onRPAFinish",
        "Llx0/o;",
        "Landroidx/fragment/app/j0;",
        "start-IoAF18A",
        "(Lay0/a;)Ljava/lang/Object;",
        "start",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;",
        "startWithCompose-IoAF18A",
        "startWithCompose",
        "stop",
        "()V",
        "close",
        "Lg61/h;",
        "disabledReason",
        "updateDisabledStatus$remoteparkassistplugin_release",
        "(Lg61/h;)V",
        "updateDisabledStatus",
        "observeBleTransportStatusAndErrors",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "car2PhoneMode",
        "",
        "isConnectable",
        "disabledReasonStatus",
        "Lg61/p;",
        "createRPAStatus",
        "(Ltechnology/cariad/cat/genx/Car2PhoneMode;ZLg61/h;)Lg61/p;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
        "Lg61/d;",
        "Lh61/a;",
        "Ljava/lang/ref/WeakReference;",
        "Lvy0/x;",
        "Ln71/a;",
        "Lpx0/g;",
        "coroutineContext",
        "Lpx0/g;",
        "getCoroutineContext",
        "()Lpx0/g;",
        "Lq61/p;",
        "rpaViewModel",
        "Lq61/p;",
        "Lyy0/a2;",
        "isRunning",
        "Lyy0/a2;",
        "()Lyy0/a2;",
        "Lyy0/j1;",
        "Lyy0/j1;",
        "_status",
        "status",
        "getStatus",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;",
        "bleTransportFacade",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;",
        "rpaStarterJob",
        "Lvy0/i1;",
        "getVin",
        "()Ljava/lang/String;",
        "vin",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private final _status:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final bleTransportFacade:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

.field private final coroutineContext:Lpx0/g;

.field private final disabledReasonStatus:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final ioDispatcher:Lvy0/x;

.field private final isRunning:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final onClose:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "Lay0/k;",
            ">;"
        }
    .end annotation
.end field

.field private final rpaConfiguration:Lg61/d;

.field private final rpaDispatcher:Ln71/a;

.field private final rpaStarterConfiguration:Lh61/a;

.field private rpaStarterJob:Lvy0/i1;

.field private final rpaViewModel:Lq61/p;

.field private final status:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Lg61/d;Lh61/a;Ljava/lang/ref/WeakReference;Lvy0/i1;Lvy0/x;Ln71/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
            "Lg61/d;",
            "Lh61/a;",
            "Ljava/lang/ref/WeakReference<",
            "Lay0/k;",
            ">;",
            "Lvy0/i1;",
            "Lvy0/x;",
            "Ln71/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "vehicleAntenna"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "rpaConfiguration"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "rpaStarterConfiguration"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "onClose"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "ioDispatcher"

    .line 22
    .line 23
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 30
    .line 31
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaConfiguration:Lg61/d;

    .line 32
    .line 33
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaStarterConfiguration:Lh61/a;

    .line 34
    .line 35
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->onClose:Ljava/lang/ref/WeakReference;

    .line 36
    .line 37
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->ioDispatcher:Lvy0/x;

    .line 38
    .line 39
    iput-object p7, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaDispatcher:Ln71/a;

    .line 40
    .line 41
    const-string p1, "RPAStarter"

    .line 42
    .line 43
    invoke-static {p1, p6, p5}, Llp/h1;->a(Ljava/lang/String;Lvy0/x;Lvy0/i1;)Lpx0/g;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->coroutineContext:Lpx0/g;

    .line 48
    .line 49
    new-instance p1, Lq61/p;

    .line 50
    .line 51
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p2

    .line 55
    sget-object p3, Lvy0/p0;->a:Lcz0/e;

    .line 56
    .line 57
    sget-object p3, Laz0/m;->a:Lwy0/c;

    .line 58
    .line 59
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getCoroutineContext()Lpx0/g;

    .line 60
    .line 61
    .line 62
    move-result-object p4

    .line 63
    invoke-static {p4}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 64
    .line 65
    .line 66
    move-result-object p4

    .line 67
    invoke-direct {p1, p2, p3, p4}, Lq61/p;-><init>(Ljava/lang/String;Lwy0/c;Lvy0/i1;)V

    .line 68
    .line 69
    .line 70
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 71
    .line 72
    iget-object p1, p1, Lq61/p;->h:Lyy0/l1;

    .line 73
    .line 74
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->isRunning:Lyy0/a2;

    .line 75
    .line 76
    const/4 p1, 0x0

    .line 77
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->disabledReasonStatus:Lyy0/j1;

    .line 82
    .line 83
    sget-object p2, Lg61/o;->a:Lg61/o;

    .line 84
    .line 85
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->_status:Lyy0/j1;

    .line 90
    .line 91
    new-instance p3, Lyy0/l1;

    .line 92
    .line 93
    invoke-direct {p3, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 94
    .line 95
    .line 96
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->status:Lyy0/a2;

    .line 97
    .line 98
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getCoroutineContext()Lpx0/g;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    invoke-static {p2}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    new-instance p3, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 107
    .line 108
    invoke-direct {p3, p1, p2, p6}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Lvy0/i1;Lvy0/x;)V

    .line 109
    .line 110
    .line 111
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->bleTransportFacade:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 112
    .line 113
    new-instance p2, Li61/h;

    .line 114
    .line 115
    invoke-direct {p2, p0, p1}, Li61/h;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Lkotlin/coroutines/Continuation;)V

    .line 116
    .line 117
    .line 118
    const/4 p3, 0x3

    .line 119
    invoke-static {p0, p1, p1, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 120
    .line 121
    .line 122
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->observeBleTransportStatusAndErrors()V

    .line 123
    .line 124
    .line 125
    return-void
.end method

.method public static synthetic B()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic E(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->startWithCompose_IoAF18A$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic H()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->startWithCompose_IoAF18A$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic T(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->start_IoAF18A$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->stop$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final synthetic access$createRPAStatus(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Ltechnology/cariad/cat/genx/Car2PhoneMode;ZLg61/h;)Lg61/p;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->createRPAStatus(Ltechnology/cariad/cat/genx/Car2PhoneMode;ZLg61/h;)Lg61/p;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getBleTransportFacade$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->bleTransportFacade:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getDisabledReasonStatus$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->disabledReasonStatus:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_status$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->_status:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;Lay0/a;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->start_IoAF18A$lambda$3$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;Lay0/a;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method private final createRPAStatus(Ltechnology/cariad/cat/genx/Car2PhoneMode;ZLg61/h;)Lg61/p;
    .locals 8

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    new-instance v0, Lg61/i;

    .line 4
    .line 5
    invoke-direct {v0, p3}, Lg61/i;-><init>(Lg61/h;)V

    .line 6
    .line 7
    .line 8
    :goto_0
    move-object v6, v0

    .line 9
    goto/16 :goto_3

    .line 10
    .line 11
    :cond_0
    if-eqz p1, :cond_6

    .line 12
    .line 13
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;->getRawValue()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    sget-object v1, Lg61/b;->d:Lgv/a;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {v0}, Lkp/p7;->d(I)Ls71/b;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_5

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    if-eq v0, v1, :cond_4

    .line 34
    .line 35
    const/4 v1, 0x2

    .line 36
    if-eq v0, v1, :cond_3

    .line 37
    .line 38
    const/4 v1, 0x3

    .line 39
    if-eq v0, v1, :cond_2

    .line 40
    .line 41
    const/4 v1, 0x4

    .line 42
    if-ne v0, v1, :cond_1

    .line 43
    .line 44
    sget-object v0, Lg61/b;->i:Lg61/b;

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    new-instance p0, La8/r0;

    .line 48
    .line 49
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    sget-object v0, Lg61/b;->h:Lg61/b;

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    sget-object v0, Lg61/b;->g:Lg61/b;

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_4
    sget-object v0, Lg61/b;->f:Lg61/b;

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_5
    sget-object v0, Lg61/b;->e:Lg61/b;

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_6
    sget-object v0, Lg61/b;->i:Lg61/b;

    .line 66
    .line 67
    :goto_1
    sget-object v1, Lg61/b;->h:Lg61/b;

    .line 68
    .line 69
    if-ne v0, v1, :cond_7

    .line 70
    .line 71
    sget-object v0, Lg61/k;->a:Lg61/k;

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_7
    sget-object v1, Lg61/b;->e:Lg61/b;

    .line 75
    .line 76
    if-ne v0, v1, :cond_8

    .line 77
    .line 78
    sget-object v0, Lg61/l;->a:Lg61/l;

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_8
    sget-object v1, Lg61/o;->a:Lg61/o;

    .line 82
    .line 83
    if-eqz p2, :cond_b

    .line 84
    .line 85
    sget-object v2, Lg61/b;->i:Lg61/b;

    .line 86
    .line 87
    if-ne v0, v2, :cond_9

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_9
    sget-object v2, Lg61/b;->f:Lg61/b;

    .line 91
    .line 92
    if-ne v0, v2, :cond_a

    .line 93
    .line 94
    new-instance v0, Lg61/n;

    .line 95
    .line 96
    sget-object v1, Lg61/m;->d:Lg61/m;

    .line 97
    .line 98
    invoke-direct {v0, v1}, Lg61/n;-><init>(Lg61/m;)V

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_a
    sget-object v2, Lg61/b;->g:Lg61/b;

    .line 103
    .line 104
    if-ne v0, v2, :cond_b

    .line 105
    .line 106
    new-instance v0, Lg61/n;

    .line 107
    .line 108
    sget-object v1, Lg61/m;->e:Lg61/m;

    .line 109
    .line 110
    invoke-direct {v0, v1}, Lg61/n;-><init>(Lg61/m;)V

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_b
    :goto_2
    move-object v6, v1

    .line 115
    :goto_3
    new-instance v2, Li61/f;

    .line 116
    .line 117
    const/4 v7, 0x0

    .line 118
    move-object v3, p1

    .line 119
    move v5, p2

    .line 120
    move-object v4, p3

    .line 121
    invoke-direct/range {v2 .. v7}, Li61/f;-><init>(Ljava/lang/Object;Ljava/lang/Enum;ZLjava/lang/Object;I)V

    .line 122
    .line 123
    .line 124
    invoke-static {p0, v2}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 125
    .line 126
    .line 127
    return-object v6
.end method

.method private static final createRPAStatus$lambda$0$0(Ltechnology/cariad/cat/genx/Car2PhoneMode;Lg61/h;ZLg61/p;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "createStatus(): car2PhoneMode = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, ", disabledReasonStatus = "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p0, ", isConnectable = "

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string p0, " => status = "

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public static synthetic d(Lg61/p;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->start_IoAF18A$lambda$0(Lg61/p;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Lg61/h;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->updateDisabledStatus$lambda$0(Lg61/h;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->startWithCompose_IoAF18A$lambda$3$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic h(Lg61/p;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->startWithCompose_IoAF18A$lambda$0(Lg61/p;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->start_IoAF18A$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Lay0/a;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->startWithCompose_IoAF18A$lambda$3$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Lay0/a;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/genx/Car2PhoneMode;Lg61/h;ZLg61/p;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->createRPAStatus$lambda$0$0(Ltechnology/cariad/cat/genx/Car2PhoneMode;Lg61/h;ZLg61/p;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final observeBleTransportStatusAndErrors()V
    .locals 3

    .line 1
    new-instance v0, Li50/p;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v2, v1}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaStarterJob:Lvy0/i1;

    .line 13
    .line 14
    return-void
.end method

.method public static synthetic q()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->start_IoAF18A$lambda$3$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final startWithCompose_IoAF18A$lambda$0(Lg61/p;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-interface {p0}, Lg61/p;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "startWithCompose(): failed. canStartRPA = "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", status = "

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "!"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private static final startWithCompose_IoAF18A$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startWithCompose(): failed. A RPA instance is already running, could not start another RPA instance!"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startWithCompose_IoAF18A$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "startWithCompose(): vin = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final startWithCompose_IoAF18A$lambda$3$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Lay0/a;)Llx0/b0;
    .locals 2

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0
.end method

.method private static final startWithCompose_IoAF18A$lambda$3$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startWithCompose(): onRPAFinish"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final start_IoAF18A$lambda$0(Lg61/p;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-interface {p0}, Lg61/p;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "start(): failed. canStartRPA = "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", status = "

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "!"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method private static final start_IoAF18A$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "start(): failed. A RPA instance is already running, could not start another RPA instance!"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final start_IoAF18A$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "start() vin = "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final start_IoAF18A$lambda$3$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;Lay0/a;)Llx0/b0;
    .locals 2

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0
.end method

.method private static final start_IoAF18A$lambda$3$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "start(): onRPAFinish"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stop$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stop()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final updateDisabledStatus$lambda$0(Lg61/h;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "updateDisabledStatus(): disabledReasonStatus = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v0, v1}, Lq61/p;->stopRPAImmediately(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaStarterJob:Lvy0/i1;

    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const-string v1, "RPAStarterImpl is shutting down via close()"

    .line 25
    .line 26
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    const/4 v0, 0x0

    .line 30
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaStarterJob:Lvy0/i1;

    .line 31
    .line 32
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->bleTransportFacade:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 33
    .line 34
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->close()V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->_status:Lyy0/j1;

    .line 38
    .line 39
    check-cast v1, Lyy0/c2;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    sget-object v2, Lg61/j;->a:Lg61/j;

    .line 45
    .line 46
    invoke-virtual {v1, v0, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 50
    .line 51
    invoke-virtual {v0}, Lq61/p;->close()V

    .line 52
    .line 53
    .line 54
    const-string v0, "close()"

    .line 55
    .line 56
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->onClose:Ljava/lang/ref/WeakReference;

    .line 60
    .line 61
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    check-cast v0, Lay0/k;

    .line 66
    .line 67
    if-eqz v0, :cond_1

    .line 68
    .line 69
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    :cond_1
    return-void
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->coroutineContext:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStatus()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->status:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 2
    .line 3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public isRunning()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->isRunning:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public start-IoAF18A(Lay0/a;)Ljava/lang/Object;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    const-string v0, "onRPAFinish"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getStatus()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lg61/p;

    .line 15
    .line 16
    invoke-interface {v0}, Lg61/p;->a()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_0

    .line 21
    .line 22
    new-instance p1, Li61/g;

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    invoke-direct {p1, v0, v1}, Li61/g;-><init>(Lg61/p;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0, p1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lg61/s;

    .line 32
    .line 33
    invoke-direct {p0, v0}, Lg61/s;-><init>(Lg61/p;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 42
    .line 43
    iget-object v0, v0, Lq61/p;->g:Lyy0/l1;

    .line 44
    .line 45
    iget-object v0, v0, Lyy0/l1;->d:Lyy0/a2;

    .line 46
    .line 47
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    new-instance p1, Lhz/a;

    .line 60
    .line 61
    const/16 v0, 0x17

    .line 62
    .line 63
    invoke-direct {p1, v0}, Lhz/a;-><init>(I)V

    .line 64
    .line 65
    .line 66
    invoke-static {p0, p1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 67
    .line 68
    .line 69
    sget-object p0, Lg61/r;->d:Lg61/r;

    .line 70
    .line 71
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :cond_1
    new-instance v0, Li61/e;

    .line 77
    .line 78
    const/4 v1, 0x0

    .line 79
    invoke-direct {v0, p0, v1}, Li61/e;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;I)V

    .line 80
    .line 81
    .line 82
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 83
    .line 84
    .line 85
    new-instance v2, Lq61/e;

    .line 86
    .line 87
    invoke-direct {v2}, Lq61/e;-><init>()V

    .line 88
    .line 89
    .line 90
    new-instance v10, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 91
    .line 92
    invoke-direct {v10}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;-><init>()V

    .line 93
    .line 94
    .line 95
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaConfiguration:Lg61/d;

    .line 96
    .line 97
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaStarterConfiguration:Lh61/a;

    .line 98
    .line 99
    iget-object v5, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->bleTransportFacade:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 100
    .line 101
    iget-object v6, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 102
    .line 103
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getCoroutineContext()Lpx0/g;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-static {v0}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 108
    .line 109
    .line 110
    move-result-object v7

    .line 111
    iget-object v8, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->ioDispatcher:Lvy0/x;

    .line 112
    .line 113
    iget-object v9, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaDispatcher:Ln71/a;

    .line 114
    .line 115
    new-instance v11, Li2/t;

    .line 116
    .line 117
    const/16 p0, 0xa

    .line 118
    .line 119
    invoke-direct {v11, p0, v10, p1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual/range {v2 .. v11}, Lq61/e;->startRPA-tZkwj4A(Lg61/d;Lh61/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Lvy0/i1;Lvy0/x;Ln71/a;Lc81/e;Lay0/a;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    return-object v10
.end method

.method public startWithCompose-IoAF18A(Lay0/a;)Ljava/lang/Object;
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    const-string v0, "onRPAFinish"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getStatus()Lyy0/a2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lg61/p;

    .line 15
    .line 16
    invoke-interface {v0}, Lg61/p;->a()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_0

    .line 21
    .line 22
    new-instance p1, Li61/g;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {p1, v0, v1}, Li61/g;-><init>(Lg61/p;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0, p1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lg61/s;

    .line 32
    .line 33
    invoke-direct {p0, v0}, Lg61/s;-><init>(Lg61/p;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 42
    .line 43
    iget-object v0, v0, Lq61/p;->g:Lyy0/l1;

    .line 44
    .line 45
    iget-object v0, v0, Lyy0/l1;->d:Lyy0/a2;

    .line 46
    .line 47
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    new-instance p1, Lhz/a;

    .line 60
    .line 61
    const/16 v0, 0x15

    .line 62
    .line 63
    invoke-direct {p1, v0}, Lhz/a;-><init>(I)V

    .line 64
    .line 65
    .line 66
    invoke-static {p0, p1}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 67
    .line 68
    .line 69
    sget-object p0, Lg61/r;->d:Lg61/r;

    .line 70
    .line 71
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :cond_1
    new-instance v0, Li61/e;

    .line 77
    .line 78
    const/4 v1, 0x1

    .line 79
    invoke-direct {v0, p0, v1}, Li61/e;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;I)V

    .line 80
    .line 81
    .line 82
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 83
    .line 84
    .line 85
    new-instance v10, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 86
    .line 87
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 92
    .line 93
    invoke-direct {v10, v0, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->getRpaViewModel()Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaConfiguration:Lg61/d;

    .line 101
    .line 102
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaStarterConfiguration:Lh61/a;

    .line 103
    .line 104
    iget-object v5, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->bleTransportFacade:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 105
    .line 106
    iget-object v6, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 107
    .line 108
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getCoroutineContext()Lpx0/g;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    invoke-static {v0}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    iget-object v8, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->ioDispatcher:Lvy0/x;

    .line 117
    .line 118
    iget-object v9, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaDispatcher:Ln71/a;

    .line 119
    .line 120
    new-instance v11, Li2/t;

    .line 121
    .line 122
    const/16 p0, 0xb

    .line 123
    .line 124
    invoke-direct {v11, p0, v10, p1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-interface/range {v2 .. v11}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->startRPA-tZkwj4A(Lg61/d;Lh61/a;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Lvy0/i1;Lvy0/x;Ln71/a;Lc81/e;Lay0/a;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    return-object v10
.end method

.method public stop()V
    .locals 2

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/16 v1, 0x16

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->rpaViewModel:Lq61/p;

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getVin()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {v0, p0}, Lq61/p;->stopRPAImmediately(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final updateDisabledStatus$remoteparkassistplugin_release(Lg61/h;)V
    .locals 2

    .line 1
    new-instance v0, Lh50/q0;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, p1, v1}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->disabledReasonStatus:Lyy0/j1;

    .line 12
    .line 13
    check-cast p0, Lyy0/c2;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
