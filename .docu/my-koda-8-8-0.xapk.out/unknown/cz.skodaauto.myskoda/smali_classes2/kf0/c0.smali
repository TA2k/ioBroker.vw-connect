.class public final Lkf0/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/t;

.field public final b:Lkf0/g;


# direct methods
.method public constructor <init>(Lkf0/t;Lkf0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/c0;->a:Lkf0/t;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/c0;->b:Lkf0/g;

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
    iget-object v5, p0, Lkf0/c0;->a:Lkf0/t;

    .line 7
    .line 8
    move-object v0, v5

    .line 9
    check-cast v0, Lif0/r;

    .line 10
    .line 11
    iget-object v1, v0, Lif0/r;->d:Lrz/k;

    .line 12
    .line 13
    const-string v2, "<this>"

    .line 14
    .line 15
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    new-instance v8, Lhg/q;

    .line 19
    .line 20
    const/16 v2, 0x10

    .line 21
    .line 22
    invoke-direct {v8, v1, v2}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 23
    .line 24
    .line 25
    iget-object v0, v0, Lif0/r;->b:Lez0/c;

    .line 26
    .line 27
    new-instance v1, La90/r;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/16 v3, 0x13

    .line 31
    .line 32
    const-class v4, Lkf0/t;

    .line 33
    .line 34
    const-string v6, "isMaintenanceStatusReportValid"

    .line 35
    .line 36
    const-string v7, "isMaintenanceStatusReportValid()Z"

    .line 37
    .line 38
    invoke-direct/range {v1 .. v7}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance v2, Lc1/b;

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    const/4 v4, 0x6

    .line 45
    invoke-direct {v2, v4, p0, p1, v3}, Lc1/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 46
    .line 47
    .line 48
    invoke-static {v8, v0, v1, v2}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
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
    invoke-virtual {p0, v0}, Lkf0/c0;->a(Ljava/lang/String;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
