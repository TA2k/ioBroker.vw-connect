.class public abstract Le81/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lz71/h;


# instance fields
.field private final classSimpleName:Ljava/lang/String;

.field private final dependencies:Ll71/w;

.field private onUserAction:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private final onUserActionBlocked:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ll71/w;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le81/x;->dependencies:Ll71/w;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    const-string p1, "ViewModelController"

    .line 23
    .line 24
    :cond_0
    iput-object p1, p0, Le81/x;->classSimpleName:Ljava/lang/String;

    .line 25
    .line 26
    new-instance p1, Le81/w;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, v0}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Le81/x;->onUserActionBlocked:Lay0/k;

    .line 33
    .line 34
    iput-object p1, p0, Le81/x;->onUserAction:Lay0/k;

    .line 35
    .line 36
    return-void
.end method

.method public static a(Le81/x;Ls71/q;)V
    .locals 2

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le81/x;->dependencies:Ll71/w;

    .line 7
    .line 8
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v1, "User action "

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string p1, " was blocked."

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public static b(Le81/x;Ls71/q;)V
    .locals 3

    .line 1
    iget-object v0, p0, Le81/x;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 4
    .line 5
    invoke-virtual {p0}, Le81/x;->getClassSimpleName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    new-instance v2, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ".triggerUserAction("

    .line 18
    .line 19
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ")"

    .line 26
    .line 27
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p1}, Le81/x;->didTriggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Le81/x;->onUserAction:Lay0/k;

    .line 41
    .line 42
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public closeScreen()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->f:Ls71/p;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public didTriggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V
    .locals 0

    .line 1
    const-string p0, "userAction"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final getAllSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ls71/q;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Le81/x;->getSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Ls71/p;->f:Ls71/p;

    .line 6
    .line 7
    invoke-static {p0, v0}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public getClassSimpleName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Le81/x;->classSimpleName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDependencies()Ll71/w;
    .locals 0

    .line 1
    iget-object p0, p0, Le81/x;->dependencies:Ll71/w;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract getSupportedScreenStates$remoteparkassistcoremeb_release()Ljava/util/Set;
.end method

.method public abstract getSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;
.end method

.method public onAppear()V
    .locals 2

    .line 1
    iget-object v0, p0, Le81/x;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 4
    .line 5
    invoke-virtual {p0}, Le81/x;->getClassSimpleName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, " appearing"

    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {v0, p0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public onDisappear()V
    .locals 2

    .line 1
    iget-object v0, p0, Le81/x;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 4
    .line 5
    invoke-virtual {p0}, Le81/x;->getClassSimpleName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, " disappearing"

    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {v0, p0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public onStateValuesChange$remoteparkassistcoremeb_release(Ll71/x;)V
    .locals 0

    .line 1
    const-string p0, "values"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setDelegate$remoteparkassistcoremeb_release(Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Le81/x;->onUserActionBlocked:Lay0/k;

    .line 4
    .line 5
    :cond_0
    iput-object p1, p0, Le81/x;->onUserAction:Lay0/k;

    .line 6
    .line 7
    return-void
.end method

.method public abstract toRPAViewModel$remoteparkassistcoremeb_release()Le81/t;
.end method

.method public final triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V
    .locals 3

    .line 1
    const-string v0, "userAction"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Le81/x;->getAllSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Le81/x;->getAllSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/lang/Iterable;

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 27
    .line 28
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-static {v0, v1}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    iget-object v0, p0, Le81/x;->dependencies:Ll71/w;

    .line 39
    .line 40
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {v2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    new-instance v1, Ljava/lang/StringBuilder;

    .line 55
    .line 56
    const-string v2, "Unsupported user action: "

    .line 57
    .line 58
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string p1, " during: "

    .line 65
    .line 66
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-static {v0, p0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_0
    iget-object v0, p0, Le81/x;->dependencies:Ll71/w;

    .line 81
    .line 82
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 83
    .line 84
    new-instance v1, Ld90/w;

    .line 85
    .line 86
    const/16 v2, 0xa

    .line 87
    .line 88
    invoke-direct {v1, v2, p0, p1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    const-wide/16 p0, 0x0

    .line 92
    .line 93
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 94
    .line 95
    .line 96
    return-void
.end method

.method public final update$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;)V
    .locals 2

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineNotRunningState;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Le81/x;->updateMEB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Le81/x;->updateMLB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;

    .line 32
    .line 33
    if-eqz v0, :cond_3

    .line 34
    .line 35
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Le81/x;->updatePPE$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;

    .line 42
    .line 43
    if-eqz v0, :cond_4

    .line 44
    .line 45
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Le81/x;->updateCommon$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_4
    iget-object p0, p0, Le81/x;->dependencies:Ll71/w;

    .line 52
    .line 53
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 54
    .line 55
    new-instance v0, Ljava/lang/StringBuilder;

    .line 56
    .line 57
    const-string v1, "update("

    .line 58
    .line 59
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string p1, ") cannot be processed. Unknown."

    .line 66
    .line 67
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public updateCommon$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;)V
    .locals 3

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le81/x;->dependencies:Ll71/w;

    .line 7
    .line 8
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 9
    .line 10
    invoke-virtual {p0}, Le81/x;->getClassSimpleName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance v1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v2, "updateCommon("

    .line 17
    .line 18
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p1, ") was called in in "

    .line 25
    .line 26
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p0, ". But not implemented!"

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {v0, p0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public abstract updateMEB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V
.end method

.method public abstract updateMLB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V
.end method

.method public abstract updatePPE$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;)V
.end method
