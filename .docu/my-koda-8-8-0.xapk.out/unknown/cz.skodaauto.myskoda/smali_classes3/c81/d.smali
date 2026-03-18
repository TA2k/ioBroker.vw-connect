.class public final Lc81/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;
.implements Lc81/h;
.implements Lc81/a;


# instance fields
.field public final a:Ll71/w;

.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

.field public final c:Lb81/b;

.field public d:Lt71/b;

.field public e:Lt71/a;

.field public f:Landroidx/lifecycle/c1;

.field public g:Lin/t1;

.field public h:Z

.field public i:Lc81/e;

.field public j:Lc81/f;

.field public final k:Lc81/c;


# direct methods
.method public constructor <init>(Ll71/w;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;Lb81/b;)V
    .locals 1

    .line 1
    const-string v0, "dependencies"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lc81/d;->a:Ll71/w;

    .line 10
    .line 11
    iput-object p2, p0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 12
    .line 13
    iput-object p3, p0, Lc81/d;->c:Lb81/b;

    .line 14
    .line 15
    new-instance p1, Lc81/c;

    .line 16
    .line 17
    invoke-direct {p1, p0}, Lc81/c;-><init>(Lc81/d;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lc81/d;->k:Lc81/c;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final carStatusChanged(Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;-><init>(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->reactToInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final connectionStatusChanged(Lk71/b;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;-><init>(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->reactToInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final lifecycleChanged(Ln71/c;)V
    .locals 3

    .line 1
    const-string v0, "lifecycle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc81/d;->a:Ll71/w;

    .line 7
    .line 8
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 9
    .line 10
    new-instance v1, Laa/k;

    .line 11
    .line 12
    const/16 v2, 0xe

    .line 13
    .line 14
    invoke-direct {v1, v2, p0, p1}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 p0, 0x0

    .line 18
    .line 19
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final safetyInstructionChanged(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SafetyInstructionInput;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SafetyInstructionInput;-><init>(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->reactToInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final touchPositionChanged(FFFFSZ)V
    .locals 9

    .line 1
    iget-object v0, p0, Lc81/d;->a:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 4
    .line 5
    new-instance v1, Lc81/b;

    .line 6
    .line 7
    move-object v2, p0

    .line 8
    move v7, p1

    .line 9
    move v8, p2

    .line 10
    move v5, p3

    .line 11
    move v6, p4

    .line 12
    move v3, p5

    .line 13
    move v4, p6

    .line 14
    invoke-direct/range {v1 .. v8}, Lc81/b;-><init>(Lc81/d;SZFFFF)V

    .line 15
    .line 16
    .line 17
    const-wide/16 p0, 0x0

    .line 18
    .line 19
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 20
    .line 21
    .line 22
    return-void
.end method
