.class public final Lkf0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lif0/w;

.field public final b:Lkf0/s;


# direct methods
.method public constructor <init>(Lif0/w;Lkf0/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/c;->a:Lif0/w;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/c;->b:Lkf0/s;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 5

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-input$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkf0/c;->a:Lif0/w;

    .line 7
    .line 8
    iget-object v1, v0, Lif0/w;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v2, Lif0/v;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-direct {v2, v0, p1, v4, v3}, Lif0/v;-><init>(Lif0/w;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Li70/q;

    .line 18
    .line 19
    const/16 v0, 0x19

    .line 20
    .line 21
    invoke-direct {p1, v0}, Li70/q;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, v2, p1, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance v0, Li50/p;

    .line 29
    .line 30
    const/16 v1, 0xf

    .line 31
    .line 32
    invoke-direct {v0, p0, v4, v1}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    new-instance p0, Lne0/n;

    .line 36
    .line 37
    const/4 v1, 0x5

    .line 38
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 39
    .line 40
    .line 41
    return-object p0
.end method

.method public final synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lss0/j0;

    .line 4
    .line 5
    iget-object v0, v0, Lss0/j0;->d:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lkf0/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
