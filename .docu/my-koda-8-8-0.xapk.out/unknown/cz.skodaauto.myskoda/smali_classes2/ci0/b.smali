.class public final Lci0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lai0/a;

.field public final b:Lif0/f0;

.field public final c:Lrs0/g;

.field public final d:Lgb0/l;

.field public final e:Lrs0/f;


# direct methods
.method public constructor <init>(Lai0/a;Lif0/f0;Lrs0/g;Lgb0/l;Lrs0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lci0/b;->a:Lai0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lci0/b;->b:Lif0/f0;

    .line 7
    .line 8
    iput-object p3, p0, Lci0/b;->c:Lrs0/g;

    .line 9
    .line 10
    iput-object p4, p0, Lci0/b;->d:Lgb0/l;

    .line 11
    .line 12
    iput-object p5, p0, Lci0/b;->e:Lrs0/f;

    .line 13
    .line 14
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
    iget-object v0, p0, Lci0/b;->a:Lai0/a;

    .line 7
    .line 8
    iget-object v1, v0, Lai0/a;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v2, La2/c;

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-direct {v2, v3, v0, p1, v4}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, La7/o;

    .line 22
    .line 23
    const/16 v2, 0x17

    .line 24
    .line 25
    invoke-direct {v1, v2, p0, p1, v4}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    new-instance p0, Lne0/n;

    .line 29
    .line 30
    const/4 p1, 0x5

    .line 31
    invoke-direct {p0, v0, v1, p1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 32
    .line 33
    .line 34
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
    invoke-virtual {p0, v0}, Lci0/b;->a(Ljava/lang/String;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
