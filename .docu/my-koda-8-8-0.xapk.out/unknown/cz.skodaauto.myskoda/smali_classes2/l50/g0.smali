.class public final Ll50/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ll50/a;

.field public final b:Lal0/w;

.field public final c:Lwj0/g;

.field public final d:Lml0/e;


# direct methods
.method public constructor <init>(Ll50/a;Lal0/w;Lwj0/g;Lml0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/g0;->a:Ll50/a;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/g0;->b:Lal0/w;

    .line 7
    .line 8
    iput-object p3, p0, Ll50/g0;->c:Lwj0/g;

    .line 9
    .line 10
    iput-object p4, p0, Ll50/g0;->d:Lml0/e;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll50/g0;->d:Lml0/e;

    .line 7
    .line 8
    invoke-virtual {v0}, Lml0/e;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lyy0/i;

    .line 13
    .line 14
    invoke-static {v0}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lac/l;

    .line 19
    .line 20
    const/16 v2, 0x1d

    .line 21
    .line 22
    invoke-direct {v1, v2, v0, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    new-instance v0, Lac/k;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const/16 v3, 0x15

    .line 29
    .line 30
    invoke-direct {v0, v3, p0, p1, v2}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
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
    invoke-virtual {p0, v0}, Ll50/g0;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
