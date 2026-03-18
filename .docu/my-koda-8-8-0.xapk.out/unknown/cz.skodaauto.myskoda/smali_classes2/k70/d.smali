.class public final Lk70/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li70/t;

.field public final b:Lk70/x;

.field public final c:Lkf0/z;

.field public final d:Lam0/c;

.field public final e:Lkc0/i;

.field public final f:Lkg0/a;


# direct methods
.method public constructor <init>(Li70/t;Lk70/x;Lkf0/z;Lam0/c;Lkc0/i;Lkg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/d;->a:Li70/t;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/d;->b:Lk70/x;

    .line 7
    .line 8
    iput-object p3, p0, Lk70/d;->c:Lkf0/z;

    .line 9
    .line 10
    iput-object p4, p0, Lk70/d;->d:Lam0/c;

    .line 11
    .line 12
    iput-object p5, p0, Lk70/d;->e:Lkc0/i;

    .line 13
    .line 14
    iput-object p6, p0, Lk70/d;->f:Lkg0/a;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lk70/d;->c:Lkf0/z;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    invoke-static {v0}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Lk70/c;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-direct {v1, v2, p0}, Lk70/c;-><init>(Lkotlin/coroutines/Continuation;Lk70/d;)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    new-instance v0, Lal0/m0;

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    const/16 v3, 0xf

    .line 27
    .line 28
    invoke-direct {v0, v1, v2, v3}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    new-instance v1, Lne0/n;

    .line 32
    .line 33
    invoke-direct {v1, v0, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 34
    .line 35
    .line 36
    return-object v1
.end method
