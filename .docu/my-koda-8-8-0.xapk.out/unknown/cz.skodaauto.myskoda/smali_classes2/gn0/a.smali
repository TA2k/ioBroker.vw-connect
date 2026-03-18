.class public final Lgn0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lgn0/d;

.field public final b:Len0/k;

.field public final c:Len0/s;

.field public final d:Lgn0/m;


# direct methods
.method public constructor <init>(Lgn0/d;Len0/k;Len0/s;Lgn0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgn0/a;->a:Lgn0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lgn0/a;->b:Len0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lgn0/a;->c:Len0/s;

    .line 9
    .line 10
    iput-object p4, p0, Lgn0/a;->d:Lgn0/m;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lgn0/a;->a:Lgn0/d;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lgb0/z;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    const/4 v3, 0x0

    .line 11
    iget-object v4, p0, Lgn0/a;->b:Len0/k;

    .line 12
    .line 13
    invoke-direct {v1, v3, v4, v2}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v1, Lg60/w;

    .line 21
    .line 22
    const/4 v2, 0x5

    .line 23
    invoke-direct {v1, p0, v3, v2}, Lg60/w;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    new-instance p0, Lne0/n;

    .line 27
    .line 28
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method
