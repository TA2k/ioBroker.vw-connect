.class public final Lk70/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Li70/t;

.field public final c:Lk70/x;

.field public final d:Lk70/v;

.field public final e:Lk70/s;


# direct methods
.method public constructor <init>(Lkf0/o;Li70/t;Lk70/x;Lk70/v;Lk70/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/k;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/k;->b:Li70/t;

    .line 7
    .line 8
    iput-object p3, p0, Lk70/k;->c:Lk70/x;

    .line 9
    .line 10
    iput-object p4, p0, Lk70/k;->d:Lk70/v;

    .line 11
    .line 12
    iput-object p5, p0, Lk70/k;->e:Lk70/s;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Z)Lyy0/i;
    .locals 4

    .line 1
    iget-object v0, p0, Lk70/k;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lk70/h;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, p0, p1, v3, v2}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lbc/g;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v1, p1, p0, v3, v2}, Lbc/g;-><init>(ZLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {v1, v0}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance p1, Lk70/j;

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    invoke-direct {p1, p0, v0}, Lk70/j;-><init>(Lne0/n;I)V

    .line 32
    .line 33
    .line 34
    return-object p1
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0, v0}, Lk70/k;->a(Z)Lyy0/i;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
