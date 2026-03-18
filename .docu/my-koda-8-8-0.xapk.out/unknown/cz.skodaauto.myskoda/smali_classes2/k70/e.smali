.class public final Lk70/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li70/r;

.field public final b:Lk70/v;

.field public final c:Lkf0/o;


# direct methods
.method public constructor <init>(Li70/r;Lk70/v;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/e;->a:Li70/r;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/e;->b:Lk70/v;

    .line 7
    .line 8
    iput-object p3, p0, Lk70/e;->c:Lkf0/o;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ll70/h;)Lyy0/i;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk70/e;->c:Lkf0/o;

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
    const/16 v2, 0x10

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    invoke-direct {v1, v2, p0, p1, v3}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v1, Laa/s;

    .line 25
    .line 26
    const/16 v2, 0xf

    .line 27
    .line 28
    invoke-direct {v1, v2, p0, p1, v3}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lne0/n;

    .line 32
    .line 33
    const/4 p1, 0x5

    .line 34
    invoke-direct {p0, v0, v1, p1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ll70/h;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lk70/e;->a(Ll70/h;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
