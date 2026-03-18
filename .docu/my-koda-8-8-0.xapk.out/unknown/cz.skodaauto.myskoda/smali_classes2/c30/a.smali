.class public final Lc30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lc30/p;

.field public final c:Lc30/i;


# direct methods
.method public constructor <init>(Lkf0/o;Lc30/p;Lc30/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc30/a;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lc30/a;->b:Lc30/p;

    .line 7
    .line 8
    iput-object p3, p0, Lc30/a;->c:Lc30/i;

    .line 9
    .line 10
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
    iget-object v0, p0, Lc30/a;->a:Lkf0/o;

    .line 7
    .line 8
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    new-instance v1, Lac/k;

    .line 13
    .line 14
    const/4 v2, 0x6

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-direct {v1, v2, p0, p1, v3}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    new-instance v0, La50/c;

    .line 24
    .line 25
    const/16 v1, 0x19

    .line 26
    .line 27
    invoke-direct {v0, p0, v3, v1}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    new-instance p0, Lne0/n;

    .line 31
    .line 32
    const/4 v1, 0x5

    .line 33
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 34
    .line 35
    .line 36
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
    invoke-virtual {p0, v0}, Lc30/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
