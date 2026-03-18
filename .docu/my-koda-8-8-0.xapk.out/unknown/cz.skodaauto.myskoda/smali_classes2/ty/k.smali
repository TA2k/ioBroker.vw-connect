.class public final Lty/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lsf0/a;

.field public final c:Lkf0/j0;

.field public final d:Lko0/f;

.field public final e:Lry/k;


# direct methods
.method public constructor <init>(Lkf0/m;Lkf0/j0;Lko0/f;Lry/k;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lty/k;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p5, p0, Lty/k;->b:Lsf0/a;

    .line 7
    .line 8
    iput-object p2, p0, Lty/k;->c:Lkf0/j0;

    .line 9
    .line 10
    iput-object p3, p0, Lty/k;->d:Lko0/f;

    .line 11
    .line 12
    iput-object p4, p0, Lty/k;->e:Lry/k;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lty/k;->a:Lkf0/m;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lty/j;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-direct {v1, p0, v3, v2}, Lty/j;-><init>(Lty/k;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Llp/sf;->c(Lyy0/m1;Lay0/n;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lqa0/a;

    .line 19
    .line 20
    const/16 v2, 0xe

    .line 21
    .line 22
    invoke-direct {v1, v3, p0, v2}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iget-object v1, p0, Lty/k;->b:Lsf0/a;

    .line 30
    .line 31
    invoke-static {v0, v1, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    new-instance v1, Lty/j;

    .line 36
    .line 37
    const/4 v2, 0x1

    .line 38
    invoke-direct {v1, p0, v3, v2}, Lty/j;-><init>(Lty/k;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v1, v0}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method
