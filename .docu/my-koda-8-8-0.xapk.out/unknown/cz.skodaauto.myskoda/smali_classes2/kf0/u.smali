.class public final Lkf0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/s;

.field public final b:Lkf0/c;


# direct methods
.method public constructor <init>(Lkf0/s;Lkf0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/u;->a:Lkf0/s;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/u;->b:Lkf0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 9

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-input$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v5, p0, Lkf0/u;->a:Lkf0/s;

    .line 7
    .line 8
    move-object v0, v5

    .line 9
    check-cast v0, Lif0/s;

    .line 10
    .line 11
    iget-object v8, v0, Lif0/s;->d:Lyy0/l1;

    .line 12
    .line 13
    iget-object v0, v0, Lif0/s;->b:Lez0/c;

    .line 14
    .line 15
    new-instance v1, La90/r;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    const/16 v3, 0x12

    .line 19
    .line 20
    const-class v4, Lkf0/s;

    .line 21
    .line 22
    const-string v6, "isDataValid"

    .line 23
    .line 24
    const-string v7, "isDataValid()Z"

    .line 25
    .line 26
    invoke-direct/range {v1 .. v7}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    new-instance v2, Lc1/b;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x5

    .line 33
    invoke-direct {v2, v4, p0, p1, v3}, Lc1/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v8, v0, v1, v2}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
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
    invoke-virtual {p0, v0}, Lkf0/u;->a(Ljava/lang/String;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
