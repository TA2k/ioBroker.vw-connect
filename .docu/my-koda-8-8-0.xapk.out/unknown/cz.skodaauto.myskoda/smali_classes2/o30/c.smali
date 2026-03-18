.class public final Lo30/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lm30/e;

.field public final b:Lo30/i;


# direct methods
.method public constructor <init>(Lm30/e;Lo30/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo30/c;->a:Lm30/e;

    .line 5
    .line 6
    iput-object p2, p0, Lo30/c;->b:Lo30/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 7

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lo30/c;->b:Lo30/i;

    .line 7
    .line 8
    check-cast v0, Lm30/a;

    .line 9
    .line 10
    iget-object v4, v0, Lm30/a;->a:Ljava/lang/String;

    .line 11
    .line 12
    new-instance v5, Lp30/d;

    .line 13
    .line 14
    invoke-direct {v5, p1}, Lp30/d;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v3, p0, Lo30/c;->a:Lm30/e;

    .line 18
    .line 19
    const-string p1, "conversationId"

    .line 20
    .line 21
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object p1, v3, Lm30/e;->a:Lxl0/f;

    .line 25
    .line 26
    new-instance v1, La30/b;

    .line 27
    .line 28
    const/16 v2, 0x19

    .line 29
    .line 30
    const/4 v6, 0x0

    .line 31
    invoke-direct/range {v1 .. v6}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    new-instance v0, Lkq0/a;

    .line 35
    .line 36
    const/16 v2, 0x1d

    .line 37
    .line 38
    invoke-direct {v0, v2}, Lkq0/a;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1, v1, v0, v6}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance v0, Lnz/g;

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    invoke-direct {v0, p0, v6, v1}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    invoke-static {v0, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lo30/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
