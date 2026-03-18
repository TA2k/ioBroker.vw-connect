.class public final Ltl/f;
.super Landroidx/lifecycle/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Ltl/f;

.field public static final c:Ltl/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltl/f;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/lifecycle/r;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltl/f;->b:Ltl/f;

    .line 7
    .line 8
    new-instance v0, Ltl/e;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Ltl/f;->c:Ltl/e;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(Landroidx/lifecycle/w;)V
    .locals 0

    .line 1
    instance-of p0, p1, Landroidx/lifecycle/f;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p1, Landroidx/lifecycle/f;

    .line 6
    .line 7
    sget-object p0, Ltl/f;->c:Ltl/e;

    .line 8
    .line 9
    invoke-interface {p1, p0}, Landroidx/lifecycle/f;->onCreate(Landroidx/lifecycle/x;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p1, p0}, Landroidx/lifecycle/f;->onStart(Landroidx/lifecycle/x;)V

    .line 13
    .line 14
    .line 15
    invoke-interface {p1, p0}, Landroidx/lifecycle/f;->onResume(Landroidx/lifecycle/x;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string p1, " must implement androidx.lifecycle.DefaultLifecycleObserver."

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p1
.end method

.method public final b()Landroidx/lifecycle/q;
    .locals 0

    .line 1
    sget-object p0, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(Landroidx/lifecycle/w;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "coil.request.GlobalLifecycle"

    .line 2
    .line 3
    return-object p0
.end method
