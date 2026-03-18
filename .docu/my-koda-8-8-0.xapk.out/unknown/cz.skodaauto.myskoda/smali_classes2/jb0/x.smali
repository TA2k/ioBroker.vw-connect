.class public final Ljb0/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxl0/f;

.field public final b:Lti0/a;


# direct methods
.method public constructor <init>(Lxl0/f;Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljb0/x;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Ljb0/x;->b:Lti0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/lang/String;Lmb0/i;Lqr0/q;Ljava/lang/Boolean;)Lyy0/m1;
    .locals 7

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "temperature"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lal/i;

    .line 12
    .line 13
    const/4 v6, 0x4

    .line 14
    move-object v3, p2

    .line 15
    move-object v4, p3

    .line 16
    move-object v2, p4

    .line 17
    move-object v5, p5

    .line 18
    invoke-direct/range {v1 .. v6}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 22
    .line 23
    .line 24
    move-result-object p4

    .line 25
    move-object p2, p0

    .line 26
    new-instance p0, La30/b;

    .line 27
    .line 28
    const/4 p5, 0x0

    .line 29
    move-object p3, p1

    .line 30
    const/16 p1, 0x17

    .line 31
    .line 32
    invoke-direct/range {p0 .. p5}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p2, Ljb0/x;->a:Lxl0/f;

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method
