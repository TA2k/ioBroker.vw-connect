.class public final Lgn0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lgn0/h;

.field public final b:Len0/s;

.field public final c:Lgn0/a;


# direct methods
.method public constructor <init>(Lgn0/h;Len0/s;Lgn0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgn0/i;->a:Lgn0/h;

    .line 5
    .line 6
    iput-object p2, p0, Lgn0/i;->b:Len0/s;

    .line 7
    .line 8
    iput-object p3, p0, Lgn0/i;->c:Lgn0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lgn0/i;->a:Lgn0/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lgn0/h;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lrz/k;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Lgb0/z;

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-direct {v0, v3, p0, v2}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {v1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iget-object v1, p0, Lgn0/i;->b:Len0/s;

    .line 28
    .line 29
    iget-object v1, v1, Len0/s;->h:Lez0/c;

    .line 30
    .line 31
    new-instance v2, Ld2/g;

    .line 32
    .line 33
    const/16 v4, 0x15

    .line 34
    .line 35
    invoke-direct {v2, p0, v4}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    new-instance v4, Lbq0/i;

    .line 39
    .line 40
    const/16 v5, 0x10

    .line 41
    .line 42
    invoke-direct {v4, p0, v3, v5}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0, v1, v2, v4}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method
