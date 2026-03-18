.class public final Lif0/u;
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
    iput-object p1, p0, Lif0/u;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lif0/u;->b:Lti0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Llb0/y;
    .locals 4

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, La2/c;

    .line 7
    .line 8
    const/16 v1, 0x13

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v0, v1, p0, p1, v2}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Li70/q;

    .line 15
    .line 16
    const/16 v3, 0x16

    .line 17
    .line 18
    invoke-direct {v1, v3}, Li70/q;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iget-object v3, p0, Lif0/u;->a:Lxl0/f;

    .line 22
    .line 23
    invoke-virtual {v3, v0, v1, v2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    new-instance v1, Lif0/d;

    .line 28
    .line 29
    invoke-direct {v1, p0, p1}, Lif0/d;-><init>(Lif0/u;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    new-instance p0, Llb0/y;

    .line 33
    .line 34
    const/4 p1, 0x3

    .line 35
    invoke-direct {p0, p1, v0, v1}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-object p0
.end method
