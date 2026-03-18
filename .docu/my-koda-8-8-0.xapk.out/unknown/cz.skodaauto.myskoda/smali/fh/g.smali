.class public final Lfh/g;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ldi/a;

.field public final e:Lkotlin/jvm/internal/k;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;

.field public final h:Llx0/q;

.field public i:Z


# direct methods
.method public constructor <init>(Ldi/a;Lay0/n;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfh/g;->d:Ldi/a;

    .line 5
    .line 6
    check-cast p2, Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    iput-object p2, p0, Lfh/g;->e:Lkotlin/jvm/internal/k;

    .line 9
    .line 10
    new-instance v0, Lfh/f;

    .line 11
    .line 12
    iget-boolean v1, p1, Ldi/a;->b:Z

    .line 13
    .line 14
    iget-boolean v2, p1, Ldi/a;->c:Z

    .line 15
    .line 16
    const/4 v5, 0x0

    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v3, 0x0

    .line 19
    const/4 v4, 0x0

    .line 20
    invoke-direct/range {v0 .. v6}, Lfh/f;-><init>(ZZZZZZ)V

    .line 21
    .line 22
    .line 23
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    iput-object p2, p0, Lfh/g;->f:Lyy0/c2;

    .line 28
    .line 29
    new-instance v0, Lyy0/l1;

    .line 30
    .line 31
    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lfh/g;->g:Lyy0/l1;

    .line 35
    .line 36
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    iput-object p2, p0, Lfh/g;->h:Llx0/q;

    .line 41
    .line 42
    iget-boolean p1, p1, Ldi/a;->b:Z

    .line 43
    .line 44
    iput-boolean p1, p0, Lfh/g;->i:Z

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final a(Lfh/e;)V
    .locals 4

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lfh/g;->h:Llx0/q;

    .line 7
    .line 8
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lzb/k0;

    .line 13
    .line 14
    new-instance v1, Le30/p;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    const/16 v3, 0xe

    .line 18
    .line 19
    invoke-direct {v1, v3, p1, p0, v2}, Le30/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v1}, Lzb/k0;->b(Lzb/k0;Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
