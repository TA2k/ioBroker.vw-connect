.class public final Lk70/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li70/r;

.field public final b:Lk70/v;

.field public final c:Lk70/y;

.field public final d:Lk70/x;

.field public final e:Lkf0/o;


# direct methods
.method public constructor <init>(Li70/r;Lk70/v;Lk70/y;Lk70/x;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/b;->a:Li70/r;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/b;->b:Lk70/v;

    .line 7
    .line 8
    iput-object p3, p0, Lk70/b;->c:Lk70/y;

    .line 9
    .line 10
    iput-object p4, p0, Lk70/b;->d:Lk70/x;

    .line 11
    .line 12
    iput-object p5, p0, Lk70/b;->e:Lkf0/o;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ll70/d;

    .line 4
    .line 5
    iget-object v1, p0, Lk70/b;->e:Lkf0/o;

    .line 6
    .line 7
    invoke-static {v1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    new-instance v2, Lac/k;

    .line 12
    .line 13
    const/16 v3, 0xf

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    invoke-direct {v2, v3, v0, p0, v4}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    invoke-static {v1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    new-instance v2, Li50/p;

    .line 24
    .line 25
    const/16 v3, 0x8

    .line 26
    .line 27
    invoke-direct {v2, v3, p0, v0, v4}, Li50/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    invoke-static {v2, v1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
