.class public final Llk0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Llk0/h;

.field public final b:Ljk0/c;

.field public final c:Lsf0/a;


# direct methods
.method public constructor <init>(Llk0/h;Ljk0/c;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llk0/k;->a:Llk0/h;

    .line 5
    .line 6
    iput-object p2, p0, Llk0/k;->b:Ljk0/c;

    .line 7
    .line 8
    iput-object p3, p0, Llk0/k;->c:Lsf0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Llk0/j;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const-string v0, "id"

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Llk0/k;->b:Ljk0/c;

    .line 15
    .line 16
    iget-object v2, v0, Ljk0/c;->a:Lxl0/f;

    .line 17
    .line 18
    new-instance v3, La2/c;

    .line 19
    .line 20
    const/16 v4, 0x15

    .line 21
    .line 22
    const/4 v5, 0x0

    .line 23
    invoke-direct {v3, v4, v0, v1, v5}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2, v3}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    new-instance v1, La10/a;

    .line 31
    .line 32
    const/16 v2, 0x19

    .line 33
    .line 34
    invoke-direct {v1, p0, v5, v2}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    invoke-static {v1, v0}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method
