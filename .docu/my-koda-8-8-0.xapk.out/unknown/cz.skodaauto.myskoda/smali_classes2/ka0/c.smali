.class public final Lka0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lka0/b;

.field public final b:Lka0/a;


# direct methods
.method public constructor <init>(Lka0/b;Lka0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lka0/c;->a:Lka0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lka0/c;->b:Lka0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 6

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-CommissionId$-input$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lka0/c;->a:Lka0/b;

    .line 7
    .line 8
    check-cast v0, Lia0/a;

    .line 9
    .line 10
    iget-object v1, v0, Lia0/a;->d:Lyy0/c2;

    .line 11
    .line 12
    iget-object v0, v0, Lia0/a;->b:Lez0/c;

    .line 13
    .line 14
    new-instance v2, Lh50/q0;

    .line 15
    .line 16
    const/16 v3, 0x13

    .line 17
    .line 18
    invoke-direct {v2, p0, v3}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    new-instance v3, Lc1/b;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    const/4 v5, 0x4

    .line 25
    invoke-direct {v3, v5, p0, p1, v4}, Lc1/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v1, v0, v2, v3}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public final synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lss0/g;

    .line 4
    .line 5
    iget-object v0, v0, Lss0/g;->d:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lka0/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
